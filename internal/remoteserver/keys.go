package remoteserver

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/Praeviso/AgentSSH/internal/fileutil"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"golang.org/x/crypto/ssh"
)

// Data-directory layout. Every private key is age-encrypted to the server's
// X25519 recipient; only the X25519 identity itself is passphrase-encrypted.
const (
	fileMaster    = "master.age"
	fileRecipient = "recipient"
	fileCACert    = "ca.crt"
	fileCAKey     = "ca.key.age"
	fileTLSCert   = "tls.crt"
	fileTLSKey    = "tls.key.age"
	fileBundlePub = "bundle.pub"
	fileBundleKey = "bundle.key.age"
	// FileDatabase is the SQLite database name inside the data directory.
	FileDatabase = "server.db"
)

// ScryptWorkFactor is the age scrypt cost for the master passphrase. Tests
// lower it; production keeps age's default.
var ScryptWorkFactor = 18

// ErrWrongMaster reports a master passphrase that does not unlock the data dir.
var ErrWrongMaster = errors.New("wrong master password or corrupt master key")

// Keys is the unlocked key material a running control plane needs.
type Keys struct {
	identity  *age.X25519Identity
	CACert    *x509.Certificate
	caKey     crypto.Signer
	TLSCert   tls.Certificate
	BundleKey ed25519.PrivateKey
}

// Initialized reports whether dir already holds control plane keys.
func Initialized(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, fileMaster))
	return err == nil
}

// Init creates a new control plane data directory. sans lists the DNS names and
// IP addresses clients will use to reach the server.
func Init(dir string, master string, sans []string, now time.Time) error {
	if master == "" {
		return errors.New("master password must not be empty")
	}
	if Initialized(dir) {
		return fmt.Errorf("control plane already initialized in %s", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	recipient := identity.Recipient()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "AgentSSH control plane CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}

	tlsDER, tlsKey, err := issueServerCert(caCert, caKey, sans, now)
	if err != nil {
		return err
	}

	bundlePub, bundleKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	scrypt, err := age.NewScryptRecipient(master)
	if err != nil {
		return err
	}
	scrypt.SetWorkFactor(ScryptWorkFactor)
	masterBlob, err := encryptTo(scrypt, []byte(identity.String()))
	if err != nil {
		return err
	}
	caKeyBlob, err := encryptPrivateKey(recipient, caKey)
	if err != nil {
		return err
	}
	tlsKeyBlob, err := encryptPrivateKey(recipient, tlsKey)
	if err != nil {
		return err
	}
	bundleKeyBlob, err := encryptPrivateKey(recipient, bundleKey)
	if err != nil {
		return err
	}

	files := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{fileRecipient, []byte(recipient.String() + "\n"), 0o644},
		{fileCACert, pemBlock("CERTIFICATE", caDER), 0o644},
		{fileCAKey, caKeyBlob, 0o600},
		{fileTLSCert, pemBlock("CERTIFICATE", tlsDER), 0o644},
		{fileTLSKey, tlsKeyBlob, 0o600},
		{fileBundlePub, []byte(base64.StdEncoding.EncodeToString(bundlePub) + "\n"), 0o644},
		{fileBundleKey, bundleKeyBlob, 0o600},
	}
	for _, f := range files {
		if err := fileutil.WriteFileAtomic(filepath.Join(dir, f.name), f.data, f.perm, f.name+"-*"); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	store, err := OpenStore(filepath.Join(dir, FileDatabase))
	if err != nil {
		return err
	}
	if err := store.Close(); err != nil {
		return err
	}
	// The master file goes last: its presence is what marks the directory as
	// initialized, so a crash earlier leaves a directory Init can retry.
	return fileutil.WriteFileAtomic(filepath.Join(dir, fileMaster), masterBlob, 0o600, fileMaster+"-*")
}

// Unlock decrypts the data directory's key material with the master password.
func Unlock(dir string, master string) (*Keys, error) {
	keys, err := unlockCA(dir, master)
	if err != nil {
		return nil, err
	}

	tlsPEM, err := os.ReadFile(filepath.Join(dir, fileTLSCert))
	if err != nil {
		return nil, err
	}
	tlsCert, err := parseCertPEM(tlsPEM)
	if err != nil {
		return nil, fmt.Errorf("parse TLS certificate: %w", err)
	}
	tlsKey, err := keys.readPrivateKey(filepath.Join(dir, fileTLSKey))
	if err != nil {
		return nil, fmt.Errorf("unlock TLS key: %w", err)
	}
	// A renewal interrupted between its two writes leaves a key that does not
	// match the certificate; say so instead of failing every handshake.
	tlsSigner, ok := tlsKey.(crypto.Signer)
	if !ok || !publicKeyEqual(tlsSigner.Public(), tlsCert.PublicKey) {
		return nil, errors.New("TLS key does not match tls.crt; run agentssh-server tls renew")
	}
	// Serve the CA after the leaf so a client holding only the CA fingerprint
	// (first enrollment) can find and pin it in the presented chain.
	keys.TLSCert = tls.Certificate{
		Certificate: [][]byte{tlsCert.Raw, keys.CACert.Raw},
		PrivateKey:  tlsKey,
		Leaf:        tlsCert,
	}

	bundleKey, err := keys.readPrivateKey(filepath.Join(dir, fileBundleKey))
	if err != nil {
		return nil, fmt.Errorf("unlock bundle key: %w", err)
	}
	edKey, ok := bundleKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("bundle key is not ed25519")
	}
	keys.BundleKey = edKey
	return keys, nil
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// unlockCA decrypts the X25519 identity and the CA, which is all certificate
// issuance needs.
func unlockCA(dir string, master string) (*Keys, error) {
	blob, err := os.ReadFile(filepath.Join(dir, fileMaster))
	if err != nil {
		return nil, fmt.Errorf("read master key (run agentssh-server init first): %w", err)
	}
	scrypt, err := age.NewScryptIdentity(master)
	if err != nil {
		return nil, err
	}
	plain, err := decryptWith(scrypt, blob)
	if err != nil {
		return nil, ErrWrongMaster
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(plain)))
	if err != nil {
		return nil, ErrWrongMaster
	}
	keys := &Keys{identity: identity}

	caPEM, err := os.ReadFile(filepath.Join(dir, fileCACert))
	if err != nil {
		return nil, err
	}
	if keys.CACert, err = parseCertPEM(caPEM); err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	caKey, err := keys.readPrivateKey(filepath.Join(dir, fileCAKey))
	if err != nil {
		return nil, fmt.Errorf("unlock CA key: %w", err)
	}
	signer, ok := caKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA key is not a signer")
	}
	keys.caKey = signer
	return keys, nil
}

// serverCertValidity is the lifetime of a control plane TLS certificate.
// Renew it with RenewTLS; the CA (and so every client's pin) stays the same.
const serverCertValidity = 2 * 365 * 24 * time.Hour

// issueServerCert creates a TLS server key and certificate signed by the CA.
func issueServerCert(caCert *x509.Certificate, caKey crypto.Signer, sans []string, now time.Time) ([]byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "AgentSSH control plane"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(serverCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, san := range sans {
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}
		if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}
	if len(template.IPAddresses) == 0 && len(template.DNSNames) == 0 {
		return nil, nil, errors.New("TLS certificate needs at least one DNS name or IP address")
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create TLS certificate: %w", err)
	}
	return der, key, nil
}

// RenewTLS replaces the control plane's TLS key and certificate with new ones
// issued by the existing CA. Enrolled devices pin the CA, so they accept the
// new certificate without re-enrolling. With no sans, the current
// certificate's names are kept. A running server picks it up on restart.
func RenewTLS(dir string, master string, sans []string, now time.Time) (*x509.Certificate, error) {
	keys, err := unlockCA(dir, master)
	if err != nil {
		return nil, err
	}
	if len(sans) == 0 {
		data, err := os.ReadFile(filepath.Join(dir, fileTLSCert))
		if err != nil {
			return nil, fmt.Errorf("read current TLS certificate (pass --san to set names): %w", err)
		}
		current, err := parseCertPEM(data)
		if err != nil {
			return nil, fmt.Errorf("parse current TLS certificate (pass --san to set names): %w", err)
		}
		sans = CertNames(current)
	}
	der, key, err := issueServerCert(keys.CACert, keys.caKey, sans, now)
	if err != nil {
		return nil, err
	}
	keyBlob, err := encryptPrivateKey(keys.identity.Recipient(), key)
	if err != nil {
		return nil, err
	}
	if err := fileutil.WriteFileAtomic(filepath.Join(dir, fileTLSKey), keyBlob, 0o600, fileTLSKey+"-*"); err != nil {
		return nil, fmt.Errorf("write %s: %w", fileTLSKey, err)
	}
	if err := fileutil.WriteFileAtomic(filepath.Join(dir, fileTLSCert), pemBlock("CERTIFICATE", der), 0o644, fileTLSCert+"-*"); err != nil {
		return nil, fmt.Errorf("write %s: %w", fileTLSCert, err)
	}
	return x509.ParseCertificate(der)
}

// CertNames lists a certificate's DNS and IP subject alternative names.
func CertNames(cert *x509.Certificate) []string {
	names := append([]string(nil), cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	return names
}

// CAFingerprint returns the pin clients use for this control plane.
func (k *Keys) CAFingerprint() string {
	return remote.CertFingerprint(k.CACert.Raw)
}

// BundlePublicKey returns the base64 ed25519 key clients pin for bundles.
func (k *Keys) BundlePublicKey() string {
	return base64.StdEncoding.EncodeToString(k.BundleKey.Public().(ed25519.PublicKey))
}

// ParseCSR decodes and verifies a PEM certificate request.
func ParseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("csr_pem is not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("certificate request signature: %w", err)
	}
	return csr, nil
}

// IssueDeviceCert signs a client-auth certificate for deviceID. The CSR only
// contributes its public key; the subject is always the device id.
func (k *Keys) IssueDeviceCert(csr *x509.CertificateRequest, deviceID string, now time.Time) ([]byte, error) {
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, k.CACert, csr.PublicKey, k.caKey)
	if err != nil {
		return nil, fmt.Errorf("issue device certificate: %w", err)
	}
	return pemBlock("CERTIFICATE", der), nil
}

// DecryptIdentity returns the SSH signer for an identity's encrypted key.
func (k *Keys) DecryptIdentity(blob []byte) (ssh.Signer, error) {
	key, err := k.decryptPrivateKey(blob)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

// LoadRecipient reads the public age recipient. Creating identities needs only
// this, so it works without the master password.
func LoadRecipient(dir string) (age.Recipient, error) {
	data, err := os.ReadFile(filepath.Join(dir, fileRecipient))
	if err != nil {
		return nil, fmt.Errorf("read recipient (run agentssh-server init first): %w", err)
	}
	return age.ParseX25519Recipient(strings.TrimSpace(string(data)))
}

// LoadCAFingerprint reads the CA pin without unlocking anything.
func LoadCAFingerprint(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, fileCACert))
	if err != nil {
		return "", fmt.Errorf("read CA certificate (run agentssh-server init first): %w", err)
	}
	cert, err := parseCertPEM(data)
	if err != nil {
		return "", err
	}
	return remote.CertFingerprint(cert.Raw), nil
}

// NewIdentity generates an ed25519 SSH identity encrypted to recipient.
func NewIdentity(name string, recipient age.Recipient, now time.Time) (Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return Identity{}, err
	}
	blob, err := encryptPrivateKey(recipient, priv)
	if err != nil {
		return Identity{}, err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " agentssh:" + name
	return Identity{Name: name, PublicKey: line, PrivateKey: blob, Status: IdentityActive, CreatedAt: now}, nil
}

func (k *Keys) readPrivateKey(path string) (any, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return k.decryptPrivateKey(blob)
}

func (k *Keys) decryptPrivateKey(blob []byte) (any, error) {
	plain, err := decryptWith(k.identity, blob)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS8PrivateKey(plain)
}

func encryptPrivateKey(recipient age.Recipient, key any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return encryptTo(recipient, der)
}

func encryptTo(recipient age.Recipient, plain []byte) ([]byte, error) {
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func decryptWith(identity age.Identity, blob []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(blob), identity)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func pemBlock(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func randomSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return serial
}
