// Package steamtable reads steam2guid lookup tables: precomputed BattlEye
// GUID -> SteamID64 maps, so a GUID's SteamID is a disk read instead of a
// brute-force search over every account.
//
// This file has no dependencies outside the standard library. To use it in
// ReCON, copy it into ReCON's module as its own package (for example
// steamtable/steamtable.go); build.go is only needed to make tables.
//
// # Background
//
// A BattlEye GUID is md5("BE" + SteamID64 as 8 little-endian bytes). A
// SteamID64 is Base + an account ID (0 .. 2^32-1). The table lists every
// account ID below MaxAccount, sorted by GUID.
//
// # File layout (every part)
//
//	offset  size  field
//	0       8     magic "STM2GUID"
//	8       2     version (1)
//	10      1     entry bytes: 2, 4 or 8
//	11      1     index bits (b): groups are keyed by the GUID's top b bits
//	12      2     this part's number (0-based)
//	14      2     number of parts
//	16      8     Base (76561197960265728)
//	24      8     MaxAccount: account IDs 0 .. MaxAccount-1 are in the table
//	32      4     first group in this part
//	36      4     number of groups in this part
//	40      8     entries in this part
//	48      8     entries in all parts
//	56      4     reserved (0)
//	60      4     CRC-32 (IEEE) of bytes 0..59
//	64      4*G   index: for each group, the entry where it starts (relative
//	              to this part); a group ends where the next one starts, or
//	              at the part's entry count
//	...     E*n   entries, sorted by GUID
//
// All header and index integers are little-endian.
//
// # Entries
//
// "key" below is the 32 GUID bits right after the index bits.
//
//	8 bytes  [key, big-endian][account ID, little-endian]
//	         binary search on key, one MD5 to confirm
//	4 bytes  [account ID, little-endian]
//	         interpolation search, an MD5 per probe (about 3-4 per lookup)
//	2 bytes  [low 16 bits of the account ID, little-endian]
//	         the high 16 bits are not stored, so a lookup tries every value
//	         for them against every entry in the group: tens of millions of
//	         MD5s in the worst case, spread over Table.Workers cores
//
// Parts split the table at group boundaries, so each part holds a
// contiguous range of GUIDs.
package steamtable

import (
	"bytes"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	Base       = uint64(76561197960265728) // SteamID64 of account ID 0
	FullRange  = uint64(1) << 32           // every possible account ID
	Magic      = "STM2GUID"
	Version    = 1
	HeaderSize = 64
	FilePrefix = "steam2guid-"
	FileSuffix = ".bin"
)

// Header is one part's header.
type Header struct {
	EntryBytes   int
	IndexBits    int
	Part, Parts  int
	MaxAccount   uint64
	FirstGroup   uint32
	Groups       uint32
	Entries      uint64
	TotalEntries uint64
}

// Marshal encodes the header into its 64 bytes.
func (h Header) Marshal() []byte {
	b := make([]byte, HeaderSize)
	copy(b, Magic)
	le := binary.LittleEndian
	le.PutUint16(b[8:], Version)
	b[10], b[11] = byte(h.EntryBytes), byte(h.IndexBits)
	le.PutUint16(b[12:], uint16(h.Part))
	le.PutUint16(b[14:], uint16(h.Parts))
	le.PutUint64(b[16:], Base)
	le.PutUint64(b[24:], h.MaxAccount)
	le.PutUint32(b[32:], h.FirstGroup)
	le.PutUint32(b[36:], h.Groups)
	le.PutUint64(b[40:], h.Entries)
	le.PutUint64(b[48:], h.TotalEntries)
	le.PutUint32(b[60:], crc32.ChecksumIEEE(b[:60]))
	return b
}

// ParseHeader decodes and checks a header.
func ParseHeader(b []byte) (Header, error) {
	var h Header
	if len(b) < HeaderSize || string(b[:8]) != Magic {
		return h, errors.New("not a steam2guid table (bad magic)")
	}
	le := binary.LittleEndian
	if crc32.ChecksumIEEE(b[:60]) != le.Uint32(b[60:]) {
		return h, errors.New("header checksum mismatch")
	}
	if v := le.Uint16(b[8:]); v != Version {
		return h, fmt.Errorf("unsupported table version %d", v)
	}
	if le.Uint64(b[16:]) != Base {
		return h, errors.New("unexpected SteamID64 base")
	}
	h = Header{
		EntryBytes: int(b[10]), IndexBits: int(b[11]),
		Part: int(le.Uint16(b[12:])), Parts: int(le.Uint16(b[14:])),
		MaxAccount: le.Uint64(b[24:]), FirstGroup: le.Uint32(b[32:]),
		Groups: le.Uint32(b[36:]), Entries: le.Uint64(b[40:]), TotalEntries: le.Uint64(b[48:]),
	}
	switch {
	case h.EntryBytes != 2 && h.EntryBytes != 4 && h.EntryBytes != 8:
		return h, fmt.Errorf("bad entry size %d", h.EntryBytes)
	case h.IndexBits < MinIndexBits || h.IndexBits > MaxIndexBits:
		return h, fmt.Errorf("bad index bits %d", h.IndexBits)
	case h.MaxAccount == 0 || h.MaxAccount > FullRange:
		return h, fmt.Errorf("bad account range %d", h.MaxAccount)
	case h.Parts == 0 || h.Part >= h.Parts:
		return h, fmt.Errorf("bad part %d of %d", h.Part, h.Parts)
	}
	return h, nil
}

const (
	MinIndexBits = 4
	MaxIndexBits = 30
)

// EntriesOffset is where this part's entries start.
func (h Header) EntriesOffset() int64 { return HeaderSize + 4*int64(h.Groups) }

// FileSize is the size this part's file must have.
func (h Header) FileSize() int64 {
	return h.EntriesOffset() + int64(h.Entries)*int64(h.EntryBytes)
}

// MaxExp is the largest account exponent: 2^32 is every account ID.
const MaxExp = 32

// AccountsForExp is the number of account IDs a table covering IDs below
// 2^exp holds (exp = 1 to MaxExp).
func AccountsForExp(exp int) (uint64, error) {
	if exp < 1 || exp > MaxExp {
		return 0, fmt.Errorf("account exponent must be 1 to %d (2^%d is every account ID), not %d", MaxExp, MaxExp, exp)
	}
	return uint64(1) << exp, nil
}

// ExpOf returns n when maxAccount is exactly 2^n, so a table built with an
// exponent can say so; ok is false for any other size.
func ExpOf(maxAccount uint64) (n int, ok bool) {
	if maxAccount == 0 || maxAccount&(maxAccount-1) != 0 {
		return 0, false
	}
	return bits.TrailingZeros64(maxAccount), true
}

// Exp is the table's account exponent, if MaxAccount is a power of two.
func (t *Table) Exp() (int, bool) { return ExpOf(t.MaxAccount) }

// PartName is the file name of part i.
func PartName(i int) string { return fmt.Sprintf("%s%03d%s", FilePrefix, i, FileSuffix) }

// GUIDOf is the BattlEye GUID of an account ID (raw bytes).
func GUIDOf(account uint32) [16]byte {
	var in [10]byte
	in[0], in[1] = 'B', 'E'
	binary.LittleEndian.PutUint64(in[2:], Base+uint64(account))
	return md5.Sum(in[:])
}

// Split returns a GUID's group (its top indexBits bits) and key (the next
// 32 bits).
func Split(g *[16]byte, indexBits int) (group, key uint32) {
	u := binary.BigEndian.Uint64(g[:8])
	return uint32(u >> (64 - indexBits)), uint32((u << indexBits) >> 32)
}

// ParseGUID reads a 32-character hex GUID.
func ParseGUID(s string) ([16]byte, error) {
	var g [16]byte
	s = strings.TrimSpace(s)
	if len(s) != 32 {
		return g, fmt.Errorf("GUID %q: want 32 hex characters", s)
	}
	if _, err := hex.Decode(g[:], []byte(s)); err != nil {
		return g, fmt.Errorf("GUID %q: %v", s, err)
	}
	return g, nil
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

type part struct {
	f *os.File
	h Header
}

// Table is an open table. Lookups are safe from many goroutines at once.
type Table struct {
	parts      []part
	EntryBytes int
	IndexBits  int
	MaxAccount uint64 // accounts 0 .. MaxAccount-1 are covered
	Entries    uint64
	// Workers is how many goroutines a 2-byte lookup uses (default: all
	// CPUs). 4- and 8-byte lookups always use one.
	Workers int
}

// Open opens every part in dir and checks that they form one table.
func Open(dir string) (*Table, error) {
	names, err := filepath.Glob(filepath.Join(dir, FilePrefix+"*"+FileSuffix))
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no %s*%s files in %s", FilePrefix, FileSuffix, dir)
	}
	t := &Table{Workers: runtime.NumCPU()}
	for _, name := range names {
		f, err := os.Open(name)
		if err != nil {
			t.Close()
			return nil, err
		}
		t.parts = append(t.parts, part{f: f})
		p := &t.parts[len(t.parts)-1]
		buf := make([]byte, HeaderSize)
		if _, err := f.ReadAt(buf, 0); err != nil {
			t.Close()
			return nil, fmt.Errorf("%s: %v", name, err)
		}
		if p.h, err = ParseHeader(buf); err != nil {
			t.Close()
			return nil, fmt.Errorf("%s: %v", name, err)
		}
		if st, err := f.Stat(); err != nil || st.Size() != p.h.FileSize() {
			t.Close()
			return nil, fmt.Errorf("%s: wrong size (incomplete or damaged file)", name)
		}
	}
	sort.Slice(t.parts, func(i, j int) bool { return t.parts[i].h.Part < t.parts[j].h.Part })
	h0 := t.parts[0].h
	t.EntryBytes, t.IndexBits, t.MaxAccount, t.Entries = h0.EntryBytes, h0.IndexBits, h0.MaxAccount, h0.TotalEntries
	var next uint32
	var sum uint64
	for i, p := range t.parts {
		h := p.h
		if h.Part != i || h.Parts != len(t.parts) {
			t.Close()
			return nil, fmt.Errorf("%s: part %d of %d, but found %d part file(s)", p.f.Name(), h.Part, h.Parts, len(t.parts))
		}
		if h.EntryBytes != h0.EntryBytes || h.IndexBits != h0.IndexBits || h.MaxAccount != h0.MaxAccount || h.TotalEntries != h0.TotalEntries {
			t.Close()
			return nil, fmt.Errorf("%s: belongs to a different table", p.f.Name())
		}
		if h.FirstGroup != next {
			t.Close()
			return nil, fmt.Errorf("%s: starts at group %d, expected %d", p.f.Name(), h.FirstGroup, next)
		}
		next += h.Groups
		sum += h.Entries
	}
	if uint64(next) != uint64(1)<<h0.IndexBits || sum != h0.TotalEntries || sum != h0.MaxAccount {
		t.Close()
		return nil, errors.New("parts don't cover the whole table")
	}
	return t, nil
}

// Close closes every part.
func (t *Table) Close() error {
	var first error
	for _, p := range t.parts {
		if p.f != nil {
			if err := p.f.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// Headers returns each part's header.
func (t *Table) Headers() []Header {
	hs := make([]Header, len(t.parts))
	for i, p := range t.parts {
		hs[i] = p.h
	}
	return hs
}

// Lookup finds the SteamID64 of a hex GUID. found is false when no account
// below MaxAccount has that GUID: either it is newer than the table, or the
// GUID is not a Steam account's.
func (t *Table) Lookup(guid string) (steamID64 uint64, found bool, err error) {
	g, err := ParseGUID(guid)
	if err != nil {
		return 0, false, err
	}
	return t.LookupRaw(g)
}

// partIndex is the index in t.parts of the part holding a group.
func (t *Table) partIndex(group uint32) (int, error) {
	i := sort.Search(len(t.parts), func(i int) bool {
		h := t.parts[i].h
		return uint64(h.FirstGroup)+uint64(h.Groups) > uint64(group)
	})
	if i == len(t.parts) {
		return 0, errors.New("group outside the table")
	}
	return i, nil
}

// PartFile is the file name of the part that holds a hex GUID: where its
// entry is if the table has it, and the one file a lookup reads either way.
// It needs no disk read: parts split the table by the GUID's leading bits.
func (t *Table) PartFile(guid string) (string, error) {
	g, err := ParseGUID(guid)
	if err != nil {
		return "", err
	}
	group, _ := Split(&g, t.IndexBits)
	i, err := t.partIndex(group)
	if err != nil {
		return "", err
	}
	return filepath.Base(t.parts[i].f.Name()), nil
}

// LookupRaw is Lookup for a GUID's raw 16 bytes.
func (t *Table) LookupRaw(g [16]byte) (uint64, bool, error) {
	group, key := Split(&g, t.IndexBits)
	i, err := t.partIndex(group)
	if err != nil {
		return 0, false, err
	}
	p := t.parts[i]
	local := group - p.h.FirstGroup

	// where the group starts and ends
	var ib [8]byte
	n := 8
	if local+1 == p.h.Groups {
		n = 4
	}
	if _, err := p.f.ReadAt(ib[:n], HeaderSize+4*int64(local)); err != nil {
		return 0, false, fmt.Errorf("%s: index: %v", p.f.Name(), err)
	}
	start := uint64(binary.LittleEndian.Uint32(ib[:]))
	end := p.h.Entries
	if n == 8 {
		end = uint64(binary.LittleEndian.Uint32(ib[4:]))
	}
	if end < start || end > p.h.Entries {
		return 0, false, fmt.Errorf("%s: damaged index at group %d", p.f.Name(), group)
	}
	if end == start {
		return 0, false, nil
	}

	eb := int64(t.EntryBytes)
	buf := make([]byte, int64(end-start)*eb)
	if _, err := p.f.ReadAt(buf, p.h.EntriesOffset()+int64(start)*eb); err != nil {
		return 0, false, fmt.Errorf("%s: entries: %v", p.f.Name(), err)
	}

	var acc uint32
	var ok bool
	switch t.EntryBytes {
	case 8:
		acc, ok = lookup8(buf, key, &g)
	case 4:
		acc, ok = lookup4(buf, key, &g, t.IndexBits)
	case 2:
		acc, ok = lookup2(buf, &g, t.MaxAccount, t.Workers)
	}
	if !ok {
		return 0, false, nil
	}
	return Base + uint64(acc), true, nil
}

// lookup8: entries are [key BE][account LE], sorted by GUID, so by key.
func lookup8(buf []byte, key uint32, g *[16]byte) (uint32, bool) {
	n := len(buf) / 8
	i := sort.Search(n, func(i int) bool { return binary.BigEndian.Uint32(buf[i*8:]) >= key })
	for ; i < n && binary.BigEndian.Uint32(buf[i*8:]) == key; i++ {
		acc := binary.LittleEndian.Uint32(buf[i*8+4:])
		if GUIDOf(acc) == *g {
			return acc, true
		}
	}
	return 0, false
}

// lookup4: entries are account IDs sorted by GUID. The GUIDs are uniform,
// so the key predicts where in the group the entry sits (interpolation
// search); after a few probes it falls back to plain bisection.
func lookup4(buf []byte, key uint32, g *[16]byte, indexBits int) (uint32, bool) {
	lo, hi := 0, len(buf)/4
	loKey, hiKey := uint64(0), uint64(1)<<32 // keys bounding [lo, hi)
	for step := 0; lo < hi; step++ {
		mid := (lo + hi) / 2
		if step < 4 && hiKey > loKey && uint64(key) >= loKey {
			mid = lo + int((uint64(key)-loKey)*uint64(hi-lo)/(hiKey-loKey))
			mid = min(max(mid, lo), hi-1)
		}
		acc := binary.LittleEndian.Uint32(buf[mid*4:])
		h := GUIDOf(acc)
		c := bytes.Compare(h[:], g[:])
		if c == 0 {
			return acc, true
		}
		_, k := Split(&h, indexBits)
		if c < 0 {
			lo, loKey = mid+1, uint64(k)
		} else {
			hi, hiKey = mid, uint64(k)+1
		}
	}
	return 0, false
}

// lookup2: entries hold only the low 16 bits of each account ID, so every
// possible high half is tried against every entry. A match on the full
// MD5 is exact.
func lookup2(buf []byte, g *[16]byte, maxAccount uint64, workers int) (uint32, bool) {
	lows := make([]uint32, len(buf)/2)
	for i := range lows {
		lows[i] = uint32(binary.LittleEndian.Uint16(buf[i*2:]))
	}
	highs := uint32((maxAccount-1)>>16) + 1
	workers = max(1, min(workers, int(highs)))
	var (
		next   atomic.Uint32
		done   atomic.Bool
		result atomic.Uint32
		wg     sync.WaitGroup
	)
	want0 := binary.LittleEndian.Uint64(g[:8])
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var in [10]byte
			in[0], in[1] = 'B', 'E'
			for !done.Load() {
				hi := next.Add(1) - 1
				if hi >= highs {
					return
				}
				for _, lo := range lows {
					acc := uint64(hi)<<16 | uint64(lo)
					if acc >= maxAccount {
						continue
					}
					binary.LittleEndian.PutUint64(in[2:], Base+acc)
					s := md5.Sum(in[:])
					if binary.LittleEndian.Uint64(s[:8]) == want0 && s == *g {
						result.Store(uint32(acc))
						done.Store(true)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	if !done.Load() {
		return 0, false
	}
	return result.Load(), true
}

// ---------------------------------------------------------------------------
// Signed manifests
// ---------------------------------------------------------------------------
//
// A table can carry a signed manifest, steam2guid-manifest.sig, next to its
// part files, so someone who downloads the table can check who built it and
// that no byte has changed since. It is plain text:
//
//	steam2guid-manifest 1
//	entry-bytes 4
//	index-bits 24
//	max-account 2147483648
//	file steam2guid-000.bin 2147483712 <SHA-256 of the whole file, hex>
//	...                                (one line per part, in part order)
//	key <Ed25519 public key, base64>
//	signature <Ed25519 signature of every line above, base64>
//
// Check accepts only manifests signed by a key in TrustedKeys, which is
// compiled in: building this package from source pins the publisher's key,
// so a download can't swap in a key of its own. Check can also be given
// keys at run time.

// ManifestName is the signed manifest's file name. It starts with FilePrefix
// but not FileSuffix, so --force removes it with the table, but Open never
// mistakes it for a part.
const ManifestName = FilePrefix + "manifest.sig"

const manifestMagic = "steam2guid-manifest 1"

// TrustedKeys are the public keys (base64, as "steam2guid keygen" prints
// them) whose signed tables Check accepts without being told about them.
var TrustedKeys = []string{
	// "paste the publisher's public key here",
	"GPSxosNJdKdyy1d1v47wVwL8KYEalGUj5jDWxa8bswg=",
}

// ManifestFile is one part file as the manifest records it.
type ManifestFile struct {
	Name   string
	Size   int64
	SHA256 [32]byte
}

// Manifest is a parsed or freshly made signed manifest.
type Manifest struct {
	EntryBytes int
	IndexBits  int
	MaxAccount uint64
	Files      []ManifestFile
	Key        ed25519.PublicKey
	Signature  []byte
}

// signedPart is the exact bytes the signature covers.
func (m *Manifest) signedPart() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\nentry-bytes %d\nindex-bits %d\nmax-account %d\n", manifestMagic, m.EntryBytes, m.IndexBits, m.MaxAccount)
	for _, f := range m.Files {
		fmt.Fprintf(&b, "file %s %d %x\n", f.Name, f.Size, f.SHA256)
	}
	fmt.Fprintf(&b, "key %s\n", EncodePublicKey(m.Key))
	return []byte(b.String())
}

// Marshal is the manifest file's contents.
func (m *Manifest) Marshal() []byte {
	return append(m.signedPart(), "signature "+base64.StdEncoding.EncodeToString(m.Signature)+"\n"...)
}

// ParseManifest reads a manifest. It doesn't check the signature (Check
// does); it only insists the file is exactly as Marshal writes it, so there
// is one way to read every signed byte.
func ParseManifest(b []byte) (*Manifest, error) {
	bad := func(why string) (*Manifest, error) { return nil, errors.New("manifest: " + why) }
	i := bytes.LastIndex(b, []byte("\nsignature "))
	if i < 0 {
		return bad("no signature line")
	}
	signed := b[:i+1]
	lines := strings.Split(strings.TrimSuffix(string(signed), "\n"), "\n")
	if len(lines) < 6 || lines[0] != manifestMagic {
		return bad("not a steam2guid manifest (version 1)")
	}
	m := &Manifest{}
	num := func(line, field string) (uint64, bool) {
		v, ok := strings.CutPrefix(line, field+" ")
		if !ok {
			return 0, false
		}
		n, err := strconv.ParseUint(v, 10, 64)
		return n, err == nil
	}
	eb, ok1 := num(lines[1], "entry-bytes")
	ib, ok2 := num(lines[2], "index-bits")
	ma, ok3 := num(lines[3], "max-account")
	if !ok1 || !ok2 || !ok3 || eb > 8 || ib > MaxIndexBits {
		return bad("bad table settings")
	}
	m.EntryBytes, m.IndexBits, m.MaxAccount = int(eb), int(ib), ma
	for _, line := range lines[4 : len(lines)-1] {
		f := strings.Fields(line)
		if len(f) != 4 || f[0] != "file" {
			return bad(fmt.Sprintf("bad line %q", line))
		}
		name := f[1]
		if filepath.Base(name) != name || !strings.HasPrefix(name, FilePrefix) || !strings.HasSuffix(name, FileSuffix) {
			return bad(fmt.Sprintf("bad file name %q", name))
		}
		size, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil || size < HeaderSize {
			return bad(fmt.Sprintf("bad size for %s", name))
		}
		var sum [32]byte
		if h, err := hex.DecodeString(f[3]); err != nil || len(h) != 32 {
			return bad(fmt.Sprintf("bad SHA-256 for %s", name))
		} else {
			copy(sum[:], h)
		}
		m.Files = append(m.Files, ManifestFile{Name: name, Size: size, SHA256: sum})
	}
	keyText, ok := strings.CutPrefix(lines[len(lines)-1], "key ")
	if !ok {
		return bad("no key line")
	}
	key, err := ParsePublicKey(keyText)
	if err != nil {
		return bad(err.Error())
	}
	m.Key = key
	sigText := strings.TrimSuffix(string(b[i+len("\nsignature "):]), "\n")
	sig, err := base64.StdEncoding.DecodeString(sigText)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return bad("bad signature encoding")
	}
	m.Signature = sig
	if !bytes.Equal(m.signedPart(), signed) {
		return bad("not in canonical form (edited by hand?)")
	}
	return m, nil
}

// EncodePublicKey writes a public key as base64.
func EncodePublicKey(k ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(k) }

// ParsePublicKey reads a base64 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%q isn't an Ed25519 public key (44 base64 characters)", s)
	}
	return ed25519.PublicKey(b), nil
}

// CompiledKeys parses TrustedKeys.
func CompiledKeys() ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, s := range TrustedKeys {
		k, err := ParsePublicKey(s)
		if err != nil {
			return nil, fmt.Errorf("TrustedKeys: %v", err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// HashProgress, if set, is called every couple of seconds while files are
// hashed and once at the end, with bytes read so far.
type HashProgress func(done, total uint64, elapsed time.Duration)

// hashFiles reads every named file in dir (several at once, up to cores)
// and returns each one's size and SHA-256, in the order given.
func hashFiles(dir string, names []string, cores int, progress HashProgress) ([]ManifestFile, error) {
	out := make([]ManifestFile, len(names))
	var total uint64
	for i, n := range names {
		st, err := os.Stat(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out[i] = ManifestFile{Name: n, Size: st.Size()}
		total += uint64(st.Size())
	}
	var (
		done  atomic.Uint64
		next  atomic.Int64
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)
	start := time.Now()
	stop := make(chan struct{})
	if progress != nil {
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					progress(done.Load(), total, time.Since(start))
				}
			}
		}()
	}
	for w := 0; w < max(1, min(cores, len(names))); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 4<<20)
			for {
				i := int(next.Add(1) - 1)
				if i >= len(names) {
					return
				}
				err := func() error {
					f, err := os.Open(filepath.Join(dir, names[i]))
					if err != nil {
						return err
					}
					defer f.Close()
					h := sha256.New()
					var n int64
					for {
						k, err := f.Read(buf)
						h.Write(buf[:k])
						n += int64(k)
						done.Add(uint64(k))
						if err == io.EOF {
							break
						}
						if err != nil {
							return fmt.Errorf("%s: %v", names[i], err)
						}
					}
					if n != out[i].Size {
						return fmt.Errorf("%s changed size while being read", names[i])
					}
					copy(out[i].SHA256[:], h.Sum(nil))
					return nil
				}()
				if err != nil {
					mu.Lock()
					if first == nil {
						first = err
					}
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	if first != nil {
		return nil, first
	}
	if progress != nil {
		progress(total, total, time.Since(start))
	}
	return out, nil
}

// CheckOptions says what Check trusts and how hard it works.
type CheckOptions struct {
	Keys     []ed25519.PublicKey // trusted in addition to TrustedKeys
	Cores    int                 // files hashed at once; 0: all CPUs
	Progress HashProgress
}

// Check verifies the table in dir against its signed manifest: the manifest
// must be signed by a trusted key, list exactly the part files in dir, and
// match every one of them byte for byte (a full SHA-256 of each file). On
// success it returns the manifest, whose Key says who signed it.
func Check(dir string, opt CheckOptions) (*Manifest, error) {
	compiled, err := CompiledKeys()
	if err != nil {
		return nil, err
	}
	trusted := append(compiled, opt.Keys...)
	if len(trusted) == 0 {
		return nil, errors.New("no trusted keys: add the publisher's key to TrustedKeys in steamtable.go, or pass one")
	}
	b, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s has no %s: the table isn't signed", dir, ManifestName)
	} else if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("manifest: too large")
	}
	m, err := ParseManifest(b)
	if err != nil {
		return nil, err
	}
	known := false
	for _, k := range trusted {
		if k.Equal(m.Key) {
			known = true
			break
		}
	}
	if !known {
		return nil, fmt.Errorf("signed by %s, which isn't a trusted key", EncodePublicKey(m.Key))
	}
	if !ed25519.Verify(m.Key, m.signedPart(), m.Signature) {
		return nil, errors.New("bad signature: the manifest isn't what the key signed")
	}

	// The part files: exactly the ones listed, forming one sound table that
	// matches the manifest's settings.
	t, err := Open(dir)
	if err != nil {
		return nil, err
	}
	t.Close()
	if t.EntryBytes != m.EntryBytes || t.IndexBits != m.IndexBits || t.MaxAccount != m.MaxAccount {
		return nil, errors.New("the table's settings don't match the manifest")
	}
	names, _ := filepath.Glob(filepath.Join(dir, FilePrefix+"*"+FileSuffix))
	if len(names) != len(m.Files) {
		return nil, fmt.Errorf("the manifest lists %d part file(s) but %s has %d", len(m.Files), dir, len(names))
	}
	onDisk := map[string]bool{}
	for _, n := range names {
		onDisk[filepath.Base(n)] = true
	}
	listed := make([]string, len(m.Files))
	for i, f := range m.Files {
		if !onDisk[f.Name] {
			return nil, fmt.Errorf("%s is listed in the manifest but missing (or listed twice)", f.Name)
		}
		delete(onDisk, f.Name)
		listed[i] = f.Name
	}

	if opt.Cores <= 0 {
		opt.Cores = runtime.NumCPU()
	}
	got, err := hashFiles(dir, listed, opt.Cores, opt.Progress)
	if err != nil {
		return nil, err
	}
	for i, f := range m.Files {
		if got[i].Size != f.Size || got[i].SHA256 != f.SHA256 {
			return nil, fmt.Errorf("%s doesn't match the signed manifest (changed or damaged)", f.Name)
		}
	}
	return m, nil
}
