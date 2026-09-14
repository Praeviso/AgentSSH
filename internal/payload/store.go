package payload

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	MaxItemBytes      int64 = 32 << 20
	DefaultTotalBytes int64 = 256 << 20
	PreviewBytes            = 64 << 10
	DiffBytes               = 128 << 10
)

var (
	ErrInvalidRef     = errors.New("invalid payload ref")
	ErrNotFound       = errors.New("payload not found")
	ErrTooLarge       = errors.New("payload item exceeds 32 MiB")
	ErrTotalTooLarge  = errors.New("payload store total size limit exceeded")
	ErrCorrupt        = errors.New("payload content hash mismatch")
	ErrActiveRef      = errors.New("payload has active references")
	ErrUnretained     = errors.New("payload content is not retained")
	ErrUnsupportedTTL = errors.New("payload ttl must be positive")
)

type Store struct {
	Dir           string
	Now           func() time.Time
	MaxTotalBytes int64
}

type Ref struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

func (r Ref) Valid() bool {
	if len(r.SHA256) != 64 || r.Bytes < 0 || r.Bytes > MaxItemBytes {
		return false
	}
	for _, c := range r.SHA256 {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (r Ref) String() string {
	if r.SHA256 == "" {
		return ""
	}
	return fmt.Sprintf("sha256:%s:%d", r.SHA256, r.Bytes)
}

type PutOptions struct {
	Name      string
	ExpireAt  time.Time
	RetainFor time.Duration
	PinOwner  string
}

type Meta struct {
	Version  int    `json:"version"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
	Name     string `json:"name,omitempty"`
	StoredAt string `json:"stored_at"`
	ExpireAt string `json:"expire_at,omitempty"`
}

type Pin struct {
	Version int    `json:"version"`
	Owner   string `json:"owner"`
	SHA256  string `json:"sha256"`
	TS      string `json:"ts"`
}

type Item struct {
	Ref      Ref       `json:"ref"`
	Name     string    `json:"name,omitempty"`
	StoredAt time.Time `json:"stored_at"`
	ExpireAt time.Time `json:"expire_at,omitempty"`
	Retained bool      `json:"retained"`
	Pins     []string  `json:"pins,omitempty"`
}

type ShowOptions struct {
	PreviewBytes int
}

type ShowResult struct {
	Ref       Ref      `json:"ref"`
	Retained  bool     `json:"retained"`
	Text      string   `json:"text,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
	Binary    bool     `json:"binary,omitempty"`
	Archives  []Member `json:"archives,omitempty"`
}

type Member struct {
	Archive string `json:"archive"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode,omitempty"`
}

type DiffResult struct {
	From      Ref    `json:"from"`
	To        Ref    `json:"to"`
	Changed   bool   `json:"changed"`
	Text      string `json:"text,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Binary    bool   `json:"binary,omitempty"`
}

func (s Store) Put(data []byte, opts PutOptions) (Ref, error) {
	unlock, err := s.lock()
	if err != nil {
		return Ref{}, err
	}
	defer unlock()
	return s.putLocked(data, opts)
}

func (s Store) putLocked(data []byte, opts PutOptions) (Ref, error) {
	if int64(len(data)) > MaxItemBytes {
		return Ref{}, ErrTooLarge
	}
	if err := s.ensure(); err != nil {
		return Ref{}, err
	}
	sum := sha256.Sum256(data)
	ref := Ref{SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(data))}
	if err := s.checkTotal(ref.SHA256, ref.Bytes); err != nil {
		return Ref{}, err
	}
	dataPath := s.dataPath(ref.SHA256)
	if existing, err := s.getLocked(ref); err == nil {
		if !bytes.Equal(existing, data) {
			return Ref{}, ErrCorrupt
		}
	} else if errors.Is(err, ErrUnretained) || errors.Is(err, ErrCorrupt) {
		if err := writeDataAtomic(dataPath, data); err != nil {
			return Ref{}, err
		}
	} else if err != nil {
		return Ref{}, err
	}
	now := s.now().UTC()
	expireAt := opts.ExpireAt
	if opts.RetainFor > 0 {
		expireAt = now.Add(opts.RetainFor)
	}
	meta := Meta{Version: 1, SHA256: ref.SHA256, Bytes: ref.Bytes, Name: opts.Name, StoredAt: now.Format(time.RFC3339)}
	if !expireAt.IsZero() {
		meta.ExpireAt = expireAt.UTC().Format(time.RFC3339)
	}
	if err := s.writeJSON(s.metaPath(ref.SHA256), meta); err != nil {
		return Ref{}, err
	}
	if opts.PinOwner != "" {
		if err := s.pinLocked(ref, opts.PinOwner); err != nil {
			return Ref{}, err
		}
	}
	return ref, nil
}

func (s Store) Get(ref Ref) ([]byte, error) {
	return s.getLocked(ref)
}

func (s Store) getLocked(ref Ref) ([]byte, error) {
	if !ref.Valid() {
		return nil, ErrInvalidRef
	}
	file, err := os.Open(s.dataPath(ref.SHA256))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnretained
	}
	if err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, ref.Bytes+1))
	if err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	if int64(len(data)) != ref.Bytes || shaHex(data) != ref.SHA256 {
		return nil, ErrCorrupt
	}
	return data, nil
}

func (s Store) Pin(ref Ref, owner string) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if !ref.Valid() {
		return ErrInvalidRef
	}
	if owner == "" || strings.ContainsAny(owner, `/\`) {
		return fmt.Errorf("invalid payload pin owner")
	}
	return s.pinLocked(ref, owner)
}

func (s Store) pinLocked(ref Ref, owner string) error {
	if _, err := s.getLocked(ref); err != nil {
		return err
	}
	if err := os.MkdirAll(s.pinsDir(ref.SHA256), 0o700); err != nil {
		return fmt.Errorf("create payload pins: %w", err)
	}
	return s.writeJSON(s.pinPath(ref.SHA256, owner), Pin{Version: 1, Owner: owner, SHA256: ref.SHA256, TS: s.now().UTC().Format(time.RFC3339)})
}

func (s Store) Unpin(ref Ref, owner string) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if !ref.Valid() {
		return ErrInvalidRef
	}
	if owner == "" || strings.ContainsAny(owner, `/\`) {
		return fmt.Errorf("invalid payload pin owner")
	}
	err = os.Remove(s.pinPath(ref.SHA256, owner))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s Store) Remove(ref Ref, force bool) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return s.removeLocked(ref, force)
}

func (s Store) removeLocked(ref Ref, force bool) error {
	if !ref.Valid() {
		return ErrInvalidRef
	}
	pins, err := s.pins(ref.SHA256)
	if err != nil {
		return err
	}
	if len(pins) > 0 && !force {
		return ErrActiveRef
	}
	for _, path := range []string{s.dataPath(ref.SHA256), s.metaPath(ref.SHA256)} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if force {
		_ = os.RemoveAll(s.pinsDir(ref.SHA256))
	}
	return nil
}

func (s Store) GC() ([]Ref, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	items, err := s.List()
	if err != nil {
		return nil, err
	}
	now := s.now()
	var removed []Ref
	for _, item := range items {
		if item.ExpireAt.IsZero() || item.ExpireAt.After(now) || len(item.Pins) > 0 {
			continue
		}
		if err := s.removeLocked(item.Ref, false); err != nil {
			return removed, err
		}
		removed = append(removed, item.Ref)
	}
	return removed, nil
}

func (s Store) lock() (func(), error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("create payload store: %w", err)
	}
	file, err := os.OpenFile(filepath.Join(s.Dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open payload store lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock payload store: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func (s Store) List() ([]Item, error) {
	entries, err := os.ReadDir(s.metaDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list payloads: %w", err)
	}
	var out []Item
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		meta, err := s.readMeta(id)
		if err != nil {
			continue
		}
		pins, _ := s.pins(id)
		_, statErr := os.Stat(s.dataPath(id))
		item := Item{Ref: Ref{SHA256: meta.SHA256, Bytes: meta.Bytes}, Name: meta.Name, Retained: statErr == nil, Pins: pins}
		if ts, err := time.Parse(time.RFC3339, meta.StoredAt); err == nil {
			item.StoredAt = ts
		}
		if meta.ExpireAt != "" {
			if ts, err := time.Parse(time.RFC3339, meta.ExpireAt); err == nil {
				item.ExpireAt = ts
			}
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref.SHA256 < out[j].Ref.SHA256 })
	return out, nil
}

func (s Store) Show(ref Ref, opts ShowOptions) (ShowResult, error) {
	data, err := s.Get(ref)
	if err != nil {
		return ShowResult{}, err
	}
	limit := opts.PreviewBytes
	if limit <= 0 || limit > PreviewBytes {
		limit = PreviewBytes
	}
	result := ShowResult{Ref: ref, Retained: true, Archives: archiveInventory(data)}
	preview := data
	if len(preview) > limit {
		preview = preview[:limit]
		result.Truncated = true
	}
	if isText(preview) {
		result.Text = sanitizeText(string(preview))
	} else {
		result.Binary = true
	}
	return result, nil
}

func (s Store) Diff(from, to Ref) (DiffResult, error) {
	a, err := s.Get(from)
	if err != nil {
		return DiffResult{}, err
	}
	b, err := s.Get(to)
	if err != nil {
		return DiffResult{}, err
	}
	result := DiffResult{From: from, To: to, Changed: !bytes.Equal(a, b)}
	if !isText(a) || !isText(b) {
		result.Binary = true
		return result, nil
	}
	if len(a) > DiffBytes || len(b) > DiffBytes {
		result.Truncated = true
		if len(a) > DiffBytes {
			a = a[:DiffBytes]
		}
		if len(b) > DiffBytes {
			b = b[:DiffBytes]
		}
	}
	result.Text = sanitizeText(simpleDiff(string(a), string(b)))
	return result, nil
}

func ParseRef(value string, size ...int64) (Ref, error) {
	value = strings.TrimPrefix(value, "sha256:")
	var bytes int64 = -1
	parts := strings.Split(value, ":")
	if len(size) > 0 {
		bytes = size[0]
	}
	if len(parts) == 2 {
		value = parts[0]
		parsed, err := parseInt64(parts[1])
		if err != nil {
			return Ref{}, ErrInvalidRef
		}
		bytes = parsed
	}
	ref := Ref{SHA256: value, Bytes: bytes}
	if !ref.Valid() {
		return Ref{}, ErrInvalidRef
	}
	return ref, nil
}

func (s Store) PutAndPin(data []byte, opts PutOptions, owner string) (Ref, error) {
	opts.PinOwner = owner
	return s.Put(data, opts)
}

func (s Store) ensure() error {
	for _, dir := range []string{s.Dir, s.dataDir(), s.metaDir(), filepath.Join(s.Dir, "pins")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create payload store: %w", err)
		}
	}
	return nil
}

func (s Store) checkTotal(newSHA string, newBytes int64) error {
	limit := s.MaxTotalBytes
	if limit <= 0 {
		limit = DefaultTotalBytes
	}
	var total int64
	entries, err := os.ReadDir(s.dataDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		total += info.Size()
	}
	if _, err := os.Stat(s.dataPath(newSHA)); errors.Is(err, os.ErrNotExist) {
		total += newBytes
	}
	if total > limit {
		return ErrTotalTooLarge
	}
	return nil
}

func (s Store) readMeta(sha string) (Meta, error) {
	var meta Meta
	data, err := os.ReadFile(s.metaPath(sha))
	if err != nil {
		return meta, err
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return meta, err
	}
	if meta.SHA256 != sha || len(meta.SHA256) != 64 || meta.Bytes < 0 {
		return meta, ErrInvalidRef
	}
	return meta, nil
}

func (s Store) pins(sha string) ([]string, error) {
	entries, err := os.ReadDir(s.pinsDir(sha))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			out = append(out, strings.TrimSuffix(entry.Name(), ".json"))
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s Store) writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func (s Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s Store) dataDir() string            { return filepath.Join(s.Dir, "objects") }
func (s Store) metaDir() string            { return filepath.Join(s.Dir, "meta") }
func (s Store) dataPath(sha string) string { return filepath.Join(s.dataDir(), sha) }
func (s Store) metaPath(sha string) string { return filepath.Join(s.metaDir(), sha+".json") }
func (s Store) pinsDir(sha string) string  { return filepath.Join(s.Dir, "pins", sha) }
func (s Store) pinPath(sha, owner string) string {
	return filepath.Join(s.pinsDir(sha), owner+".json")
}

func writeDataAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create payload directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary payload: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temporary payload: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary payload: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary payload: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary payload: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace payload: %w", err)
	}
	cleanup = false
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open payload directory: %w", err)
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync payload directory: %w", err)
	}
	return nil
}

func shaHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func parseInt64(value string) (int64, error) {
	var out int64
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, ErrInvalidRef
		}
		out = out*10 + int64(r-'0')
		if out > MaxItemBytes {
			return 0, ErrInvalidRef
		}
	}
	return out, nil
}

func isText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	if !utf8.Valid(data) {
		return false
	}
	for _, b := range data {
		if b == 0 {
			return false
		}
	}
	return true
}

func sanitizeText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' || r == '\r' || r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func archiveInventory(data []byte) []Member {
	var out []Member
	if zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
		for _, f := range zr.File {
			out = append(out, Member{Archive: "zip", Name: sanitizeText(f.Name), Size: int64(f.UncompressedSize64), Mode: f.Mode().String()})
			if len(out) >= 256 {
				return out
			}
		}
	}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break
		}
		out = append(out, Member{Archive: "tar", Name: sanitizeText(header.Name), Size: header.Size, Mode: header.FileInfo().Mode().String()})
		if len(out) >= 256 {
			break
		}
	}
	return out
}

func simpleDiff(a, b string) string {
	alines := strings.Split(a, "\n")
	blines := strings.Split(b, "\n")
	var out strings.Builder
	max := len(alines)
	if len(blines) > max {
		max = len(blines)
	}
	for i := 0; i < max; i++ {
		var av, bv string
		if i < len(alines) {
			av = alines[i]
		}
		if i < len(blines) {
			bv = blines[i]
		}
		if av == bv {
			continue
		}
		if i < len(alines) {
			out.WriteString("- ")
			out.WriteString(av)
			out.WriteByte('\n')
		}
		if i < len(blines) {
			out.WriteString("+ ")
			out.WriteString(bv)
			out.WriteByte('\n')
		}
		if out.Len() > DiffBytes {
			return out.String()[:DiffBytes]
		}
	}
	return out.String()
}
