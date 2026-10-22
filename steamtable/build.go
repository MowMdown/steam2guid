package steamtable

// Building a table. Not needed to read one, so ReCON only needs
// steamtable.go.
//
// The table is bigger than memory, so it is built in passes over every
// account ID:
//
//  1. count:  hash every account, count how many land in each group. This
//     fixes every group's position, so the part files can be laid out and
//     their indexes written straight away.
//  2. fill:   hash every account again, keeping only those whose group falls
//     in the current batch of groups (as many as fit in Memory, 8 bytes
//     each). Sort each group by GUID and write the batch into place.
//     Repeat until every group has been written.
//
// So the build hashes everything 1 + batches times. MD5 is the cost; more
// cores or more memory (fewer batches) make it faster.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BuildOptions says what to build.
type BuildOptions struct {
	Dir        string
	EntryBytes int    // 2, 4 or 8
	IndexBits  int    // 0: picked from EntryBytes and MaxAccount (AutoIndexBits)
	MaxAccount uint64 // 0: FullRange (every account ID)
	Exp        int    // if set (1 to MaxExp), cover account IDs below 2^Exp; leave MaxAccount 0
	PartSize   int64  // largest part file in bytes; 0: no limit
	Parts      int    // if > 0, split into this many parts instead of by PartSize
	Cores      int    // 0: all
	Memory     int64  // bytes for the fill buffer; 0: 4 GiB
	Force      bool   // replace an existing table in Dir

	// SignKey, if set, signs the finished table (see Sign).
	SignKey ed25519.PrivateKey

	// Progress, if set, is called every couple of seconds during a pass and
	// once when it ends. Log, if set, gets one line per step.
	Progress func(stage string, done, total uint64, elapsed time.Duration)
	Log      func(format string, args ...any)
}

// AutoIndexBits picks the index size: groups average about 256 entries
// (64 for 2-byte entries, whose lookups cost grows with group size).
func AutoIndexBits(entryBytes int, maxAccount uint64) int {
	target := 256.0
	if entryBytes == 2 {
		target = 64
	}
	b := int(math.Round(math.Log2(float64(maxAccount) / target)))
	return min(max(b, MinIndexBits), 26)
}

type partLayout struct {
	firstGroup, groups uint32
	entryStart         uint64 // global index of its first entry
	entries            uint64
}

// Plan is the layout chosen after counting.
type Plan struct {
	Parts      []Header
	Batches    int
	TotalBytes int64
}

// Build makes a table in opt.Dir.
func Build(opt BuildOptions) (*Plan, error) {
	if opt.EntryBytes != 2 && opt.EntryBytes != 4 && opt.EntryBytes != 8 {
		return nil, fmt.Errorf("entry size must be 2, 4 or 8 bytes, not %d", opt.EntryBytes)
	}
	if opt.Exp != 0 {
		if opt.MaxAccount != 0 {
			return nil, errors.New("set Exp or MaxAccount, not both")
		}
		n, err := AccountsForExp(opt.Exp)
		if err != nil {
			return nil, err
		}
		opt.MaxAccount = n
	}
	if opt.MaxAccount == 0 {
		opt.MaxAccount = FullRange
	}
	if opt.MaxAccount > FullRange {
		return nil, fmt.Errorf("max account %d is past the last account ID (%d)", opt.MaxAccount, FullRange)
	}
	if opt.IndexBits == 0 {
		opt.IndexBits = AutoIndexBits(opt.EntryBytes, opt.MaxAccount)
	}
	if opt.IndexBits < MinIndexBits || opt.IndexBits > MaxIndexBits {
		return nil, fmt.Errorf("index bits must be %d to %d", MinIndexBits, MaxIndexBits)
	}
	if opt.Cores <= 0 {
		opt.Cores = runtime.NumCPU()
	}
	if opt.Memory <= 0 {
		opt.Memory = 4 << 30
	}
	if opt.Memory < 8 {
		return nil, errors.New("memory too small")
	}
	logf := opt.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ib := opt.IndexBits
	groups := uint64(1) << ib
	eb := uint64(opt.EntryBytes)

	if err := prepareDir(opt.Dir, opt.Force); err != nil {
		return nil, err
	}

	// ---- pass 1: count ------------------------------------------------
	counts := make([]uint32, groups)
	maxBatch := uint64(opt.Memory / 8)
	estBatches := (opt.MaxAccount + maxBatch - 1) / maxBatch
	stage := fmt.Sprintf("pass 1/%d (count)", 1+estBatches)
	hashPass(opt.MaxAccount, opt.Cores, ib, stage, opt.Progress, func(acc, group, key uint32) {
		atomic.AddUint32(&counts[group], 1)
	})

	// ---- layout -------------------------------------------------------
	parts, err := layout(counts, eb, opt.PartSize, opt.Parts)
	if err != nil {
		return nil, err
	}
	if len(parts) > math.MaxUint16 {
		return nil, fmt.Errorf("%d parts is too many (at most %d); use a bigger part size", len(parts), math.MaxUint16)
	}
	plan := &Plan{}
	headers := make([]Header, len(parts))
	for i, p := range parts {
		headers[i] = Header{EntryBytes: opt.EntryBytes, IndexBits: ib, Part: i, Parts: len(parts),
			MaxAccount: opt.MaxAccount, FirstGroup: p.firstGroup, Groups: p.groups,
			Entries: p.entries, TotalEntries: opt.MaxAccount}
		plan.TotalBytes += headers[i].FileSize()
	}
	plan.Parts = headers

	// batches of whole groups, each at most maxBatch entries
	type batch struct {
		g0, g1     uint64
		entryStart uint64
		entries    uint64
	}
	var batches []batch
	{
		var b batch
		var pos uint64
		for g := uint64(0); g < groups; g++ {
			c := uint64(counts[g])
			if b.g1 > b.g0 && b.entries+c > maxBatch {
				batches = append(batches, b)
				b = batch{g0: g, g1: g, entryStart: pos}
			}
			b.g1, b.entries = g+1, b.entries+c
			pos += c
		}
		batches = append(batches, b)
	}
	plan.Batches = len(batches)
	logf("layout: %d part(s), %s total, %d fill pass(es)", len(parts), HumanBytes(plan.TotalBytes), len(batches))

	// ---- create files, write headers and indexes ------------------------
	files := make([]*os.File, len(parts))
	defer func() {
		for _, f := range files {
			if f != nil {
				f.Close()
			}
		}
	}()
	for i, h := range headers {
		f, err := os.OpenFile(partialName(opt.Dir, i), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return nil, err
		}
		files[i] = f
		if err := f.Truncate(h.FileSize()); err != nil {
			return nil, fmt.Errorf("%s: %v", f.Name(), err)
		}
		w := bufio.NewWriterSize(io.NewOffsetWriter(f, 0), 1<<20)
		w.Write(h.Marshal())
		var start uint64
		var b [4]byte
		for g := uint64(h.FirstGroup); g < uint64(h.FirstGroup)+uint64(h.Groups); g++ {
			if start > math.MaxUint32 {
				return nil, fmt.Errorf("part %d holds more than 2^32 entries; use a smaller part size or more parts", i)
			}
			binary.LittleEndian.PutUint32(b[:], uint32(start))
			w.Write(b[:])
			start += uint64(counts[g])
		}
		if err := w.Flush(); err != nil {
			return nil, fmt.Errorf("%s: %v", f.Name(), err)
		}
	}

	// ---- fill passes ----------------------------------------------------
	bufLen := uint64(0)
	for _, b := range batches {
		bufLen = max(bufLen, b.entries)
	}
	buf := make([]uint64, bufLen)
	for bi, b := range batches {
		next := make([]uint64, b.g1-b.g0) // next free slot of each group, batch-local
		var pos uint64
		for j := range next {
			next[j] = pos
			pos += uint64(counts[b.g0+uint64(j)])
		}
		g0, g1 := uint32(b.g0), uint64(b.g1)
		stage := fmt.Sprintf("pass %d/%d (fill groups %d-%d)", bi+2, len(batches)+1, b.g0, b.g1-1)
		hashPass(opt.MaxAccount, opt.Cores, ib, stage, opt.Progress, func(acc, group, key uint32) {
			if group < g0 || uint64(group) >= g1 {
				return
			}
			i := atomic.AddUint64(&next[group-g0], 1) - 1
			buf[i] = uint64(key)<<32 | uint64(acc)
		})
		sortGroups(buf[:b.entries], next, opt.Cores)
		if err := writeEntries(buf[:b.entries], b.entryStart, parts, headers, files, opt.EntryBytes); err != nil {
			return nil, err
		}
	}

	// ---- finish -------------------------------------------------------
	for i, f := range files {
		if err := f.Sync(); err != nil {
			return nil, fmt.Errorf("%s: %v", f.Name(), err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("%s: %v", f.Name(), err)
		}
		files[i] = nil
		if err := os.Rename(partialName(opt.Dir, i), filepath.Join(opt.Dir, PartName(i))); err != nil {
			return nil, err
		}
	}

	if opt.SignKey != nil {
		logf("signing: hashing %s", HumanBytes(plan.TotalBytes))
		var progress HashProgress
		if opt.Progress != nil {
			progress = func(done, total uint64, el time.Duration) { opt.Progress("hashing files", done, total, el) }
		}
		if _, err := Sign(opt.Dir, opt.SignKey, opt.Cores, progress); err != nil {
			return nil, fmt.Errorf("the table was built but signing failed: %v", err)
		}
	}
	return plan, nil
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

const privateKeyPrefix = "steam2guid-private-key "

// GenerateKey makes a new signing key, writes its private half to path
// (readable only by you; an existing file is never overwritten) and returns
// the public half to publish.
func GenerateKey(path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%s already exists; not overwriting a key", path)
		}
		return nil, err
	}
	_, err = fmt.Fprintf(f, "%s%s\n", privateKeyPrefix, base64.StdEncoding.EncodeToString(priv.Seed()))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	return pub, nil
}

// LoadKey reads a private key written by GenerateKey.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, ok := strings.CutPrefix(strings.TrimSpace(string(b)), privateKeyPrefix)
	if !ok {
		return nil, fmt.Errorf("%s isn't a steam2guid private key", path)
	}
	seed, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: damaged private key", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Sign hashes every part of the table in dir and writes a signed manifest
// (ManifestName) beside them, replacing any old one.
func Sign(dir string, key ed25519.PrivateKey, cores int, progress HashProgress) (*Manifest, error) {
	t, err := Open(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(t.parts))
	for i, p := range t.parts {
		names[i] = filepath.Base(p.f.Name())
	}
	m := &Manifest{EntryBytes: t.EntryBytes, IndexBits: t.IndexBits, MaxAccount: t.MaxAccount,
		Key: key.Public().(ed25519.PublicKey)}
	t.Close()
	if cores <= 0 {
		cores = runtime.NumCPU()
	}
	if m.Files, err = hashFiles(dir, names, cores, progress); err != nil {
		return nil, err
	}
	m.Signature = ed25519.Sign(key, m.signedPart())

	tmp := filepath.Join(dir, ManifestName+".partial")
	if err := os.WriteFile(tmp, m.Marshal(), 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, filepath.Join(dir, ManifestName)); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	return m, nil
}

func partialName(dir string, i int) string { return filepath.Join(dir, PartName(i)+".partial") }

// prepareDir makes dir, refusing to overwrite a table unless force.
func prepareDir(dir string, force bool) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	old, _ := filepath.Glob(filepath.Join(dir, FilePrefix+"*"))
	if len(old) == 0 {
		return nil
	}
	if !force {
		return fmt.Errorf("%s already has a table (%d file(s)); use --force to replace it", dir, len(old))
	}
	for _, f := range old {
		if err := os.Remove(f); err != nil {
			return err
		}
	}
	return nil
}

// layout splits the groups into parts: nParts equal ranges of groups, or
// as few parts as keep each file within partSize (0: one part).
func layout(counts []uint32, eb uint64, partSize int64, nParts int) ([]partLayout, error) {
	groups := uint64(len(counts))
	var parts []partLayout
	if nParts > 0 {
		if uint64(nParts) > groups {
			return nil, fmt.Errorf("%d parts but only %d groups; use fewer parts or more index bits", nParts, groups)
		}
		var pos uint64
		for i := 0; i < nParts; i++ {
			a, b := groups*uint64(i)/uint64(nParts), groups*uint64(i+1)/uint64(nParts)
			p := partLayout{firstGroup: uint32(a), groups: uint32(b - a), entryStart: pos}
			for g := a; g < b; g++ {
				p.entries += uint64(counts[g])
			}
			pos += p.entries
			parts = append(parts, p)
		}
		return parts, nil
	}
	limit := uint64(math.MaxInt64)
	if partSize > 0 {
		limit = uint64(partSize)
	}
	cur := partLayout{}
	size := uint64(HeaderSize)
	var pos uint64
	for g := uint64(0); g < groups; g++ {
		add := 4 + uint64(counts[g])*eb
		if HeaderSize+add > limit {
			return nil, fmt.Errorf("part size %s is too small to hold one group", HumanBytes(int64(limit)))
		}
		if cur.groups > 0 && size+add > limit {
			parts = append(parts, cur)
			cur = partLayout{firstGroup: uint32(g), entryStart: pos}
			size = HeaderSize
		}
		cur.groups++
		cur.entries += uint64(counts[g])
		size += add
		pos += uint64(counts[g])
	}
	return append(parts, cur), nil
}

// hashPass hashes account IDs 0 .. n-1 on cores goroutines and calls fn
// with each one's group and key. fn is called concurrently.
func hashPass(n uint64, cores, ib int, stage string, progress func(string, uint64, uint64, time.Duration), fn func(acc, group, key uint32)) {
	const chunk = 1 << 16
	var next, done atomic.Uint64
	var wg sync.WaitGroup
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
					progress(stage, done.Load(), n, time.Since(start))
				}
			}
		}()
	}
	shift := uint(64 - ib)
	for w := 0; w < cores; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var in [10]byte
			in[0], in[1] = 'B', 'E'
			for {
				lo := next.Add(chunk) - chunk
				if lo >= n {
					return
				}
				hi := min(lo+chunk, n)
				for acc := lo; acc < hi; acc++ {
					binary.LittleEndian.PutUint64(in[2:], Base+acc)
					s := md5.Sum(in[:])
					u := binary.BigEndian.Uint64(s[:8])
					fn(uint32(acc), uint32(u>>shift), uint32((u<<ib)>>32))
				}
				done.Add(hi - lo)
			}
		}()
	}
	wg.Wait()
	close(stop)
	if progress != nil {
		progress(stage, n, n, time.Since(start))
	}
}

// sortGroups sorts each group (ends[j] is where group j ends) by GUID:
// by key, then, for the rare entries sharing a key, by the whole GUID.
func sortGroups(buf []uint64, ends []uint64, cores int) {
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < cores; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				j := int(next.Add(1) - 1)
				if j >= len(ends) {
					return
				}
				var start uint64
				if j > 0 {
					start = ends[j-1]
				}
				s := buf[start:ends[j]]
				slices.Sort(s)
				for i := 0; i < len(s); {
					k := i + 1
					for k < len(s) && s[k]>>32 == s[i]>>32 {
						k++
					}
					if k-i > 1 {
						slices.SortFunc(s[i:k], func(a, b uint64) int {
							ga, gb := GUIDOf(uint32(a)), GUIDOf(uint32(b))
							return bytes.Compare(ga[:], gb[:])
						})
					}
					i = k
				}
			}
		}()
	}
	wg.Wait()
}

// writeEntries encodes a batch (global entries entryStart onward) and
// writes it into the parts it belongs to.
func writeEntries(buf []uint64, entryStart uint64, parts []partLayout, headers []Header, files []*os.File, eb int) error {
	out := make([]byte, 0, 4<<20)
	pi := 0
	for i := uint64(0); i < uint64(len(buf)); {
		pos := entryStart + i
		for pos >= parts[pi].entryStart+parts[pi].entries {
			pi++
		}
		p := parts[pi]
		m := min(uint64(len(buf))-i, p.entryStart+p.entries-pos, uint64(cap(out)/eb))
		out = out[:0]
		for _, v := range buf[i : i+m] {
			switch eb {
			case 8:
				out = binary.BigEndian.AppendUint32(out, uint32(v>>32))
				out = binary.LittleEndian.AppendUint32(out, uint32(v))
			case 4:
				out = binary.LittleEndian.AppendUint32(out, uint32(v))
			case 2:
				out = binary.LittleEndian.AppendUint16(out, uint16(v))
			}
		}
		off := headers[pi].EntriesOffset() + int64(pos-p.entryStart)*int64(eb)
		if _, err := files[pi].WriteAt(out, off); err != nil {
			return fmt.Errorf("%s: %v", files[pi].Name(), err)
		}
		i += m
	}
	return nil
}

// HumanBytes formats a size with binary units (1 GiB = 1024^3 bytes).
func HumanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	e := (63 - bits.LeadingZeros64(uint64(n))) / 10
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(uint64(1)<<(10*e)), "KMGTPE"[e-1])
}
