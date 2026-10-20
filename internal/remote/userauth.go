package remote

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	msgUserAuthRequest = 50
	maxSessionIDBytes  = 64
)

// UserAuth is the parsed RFC 4252 §7 publickey signature payload.
type UserAuth struct {
	SessionID []byte
	User      string
	Service   string
	Method    string
	Algorithm string
	PublicKey []byte
}

// ParseUserAuth strictly decodes the data an SSH client signs for publickey
// user authentication:
//
//	string session_id, byte 50, string user, string "ssh-connection",
//	string "publickey", bool TRUE, string algorithm, string public key
//
// The control plane signs nothing else, so a device cannot turn the signing
// endpoint into a general-purpose oracle for the identity key.
func ParseUserAuth(data []byte) (UserAuth, error) {
	r := reader{data: data}
	var out UserAuth
	out.SessionID = r.bytes()
	msgType := r.byte()
	out.User = string(r.bytes())
	out.Service = string(r.bytes())
	out.Method = string(r.bytes())
	hasSignature := r.byte()
	out.Algorithm = string(r.bytes())
	out.PublicKey = r.bytes()
	if r.err != nil {
		return UserAuth{}, r.err
	}
	if len(r.data) != 0 {
		return UserAuth{}, errors.New("userauth data has trailing bytes")
	}
	if len(out.SessionID) == 0 || len(out.SessionID) > maxSessionIDBytes {
		return UserAuth{}, fmt.Errorf("userauth session id has invalid length %d", len(out.SessionID))
	}
	if msgType != msgUserAuthRequest {
		return UserAuth{}, fmt.Errorf("userauth message type %d is not USERAUTH_REQUEST", msgType)
	}
	if out.Service != "ssh-connection" {
		return UserAuth{}, fmt.Errorf("userauth service %q is not ssh-connection", out.Service)
	}
	if out.Method != "publickey" {
		return UserAuth{}, fmt.Errorf("userauth method %q is not publickey", out.Method)
	}
	if hasSignature != 1 {
		return UserAuth{}, errors.New("userauth data is not a signature request")
	}
	if out.User == "" || out.Algorithm == "" || len(out.PublicKey) == 0 {
		return UserAuth{}, errors.New("userauth data is missing user, algorithm, or public key")
	}
	return out, nil
}

type reader struct {
	data []byte
	err  error
}

func (r *reader) byte() byte {
	if r.err != nil {
		return 0
	}
	if len(r.data) < 1 {
		r.err = errors.New("userauth data is truncated")
		return 0
	}
	b := r.data[0]
	r.data = r.data[1:]
	return b
}

func (r *reader) bytes() []byte {
	if r.err != nil {
		return nil
	}
	if len(r.data) < 4 {
		r.err = errors.New("userauth data is truncated")
		return nil
	}
	n := binary.BigEndian.Uint32(r.data)
	if uint64(n) > uint64(len(r.data)-4) {
		r.err = errors.New("userauth data is truncated")
		return nil
	}
	out := r.data[4 : 4+n]
	r.data = r.data[4+n:]
	return out
}
