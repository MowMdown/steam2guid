// steam2guid builds a table of every Steam account's BattlEye GUID, so
// ReCON can find a GUID's SteamID64 with a disk read instead of hashing
// billions of accounts.
//
//	steam2guid [build] --out D [flags]  build a table (the default command)
//	steam2guid lookup --dir D GUID…     find SteamIDs in a table
//	steam2guid info   --dir D           show a table's parts
//	steam2guid keygen --key F           make a signing key
//	steam2guid sign   --dir D --key F   sign a table
//	steam2guid check  --dir D           check a downloaded table's signature
package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"steam2guid/steamtable"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	cmd := "build"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "build":
		err = cmdBuild(args)
	case "lookup":
		err = cmdLookup(args)
	case "info":
		err = cmdInfo(args)
	case "keygen":
		err = cmdKeygen(args)
	case "sign":
		err = cmdSign(args)
	case "check":
		err = cmdCheck(args)
	case "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "steam2guid: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "steam2guid:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `steam2guid: precompute BattlEye GUID -> SteamID64 tables

  steam2guid [build] --out D [flags]   build a table (build is the default)
  steam2guid lookup --dir D GUID...    look GUIDs up
  steam2guid info   --dir D            show the table's parts
  steam2guid keygen --key F            make a signing key (private half to F)
  steam2guid sign   --dir D --key F    sign a table so others can check it
  steam2guid check  --dir D [--pubkey K]  check a table's signature and every byte

Examples:
  steam2guid --out /data/table                        4-byte table, 2G parts
  steam2guid --out /data/table --bytes 8 --parts 10   8-byte table split into 10 files
  steam2guid --out /data/table --bytes 2 --part-size 512M
  steam2guid --out /data/table --exp 31               table of 2,147,483,648 accounts
  steam2guid lookup --dir /data/table 0123456789abcdef0123456789abcdef
  steam2guid --out /data/table --sign-key ~/steam2guid.key   build and sign
  steam2guid check --dir /data/table                 check a downloaded table

Run "steam2guid build -h" for every build flag.
`)
}

func cmdBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	entryBytes := fs.Int("bytes", 4, "bytes per account: 4 (default), 8 (faster lookups, 2x the disk) or 2 (half the disk, lookups take seconds of CPU)")
	partSize := fs.String("part-size", "2G", "largest file size (K, M, G, T = 1024-based); 0 = one file")
	parts := fs.Int("parts", 0, "split into exactly this many files instead of by --part-size")
	dir := fs.String("out", "", "directory to write the table to (required)")
	indexBits := fs.Int("index-bits", 0, "GUID bits used to group entries (0 = auto: 24 for 4/8-byte, 26 for 2-byte on a full table)")
	maxAccount := fs.String("max-account", "4294967296", "cover account IDs below this (default: all 2^32)")
	exp := fs.Int("exp", 0, "build a table of 2^n accounts, n = 1 to 32 (e.g. --exp 31 for every account in use today)")
	cores := fs.Int("cores", runtime.NumCPU(), "CPU cores to hash with")
	memory := fs.String("mem", "4G", "memory for sorting; less memory means more passes")
	force := fs.Bool("force", false, "replace an existing table in --out")
	signKey := fs.String("sign-key", "", "private key file (from keygen) to sign the table with when it's built")
	fs.Parse(args)
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if err := requirePath("out", *dir); err != nil {
		return err
	}
	var key ed25519.PrivateKey
	if *signKey != "" {
		// Load now, so a bad key fails before hours of building, not after.
		k, err := steamtable.LoadKey(*signKey)
		if err != nil {
			return fmt.Errorf("--sign-key: %v", err)
		}
		key = k
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if set["parts"] && set["part-size"] {
		return errors.New("use --parts or --part-size, not both")
	}
	ps, err := parseSize(*partSize)
	if err != nil {
		return fmt.Errorf("--part-size: %v", err)
	}
	if *parts > 0 {
		ps = 0
	} else if *parts < 0 {
		return errors.New("--parts must be positive")
	}
	if ps != 0 && ps < 1<<20 {
		return errors.New("--part-size must be at least 1M")
	}
	mem, err := parseSize(*memory)
	if err != nil || mem < 64<<20 {
		return errors.New("--mem must be a size of at least 64M")
	}
	if set["exp"] && set["max-account"] {
		return errors.New("use --exp or --max-account, not both")
	}
	var ma uint64
	if set["exp"] {
		// steamtable.Build does the real check; this only sizes the plan line.
		if ma, err = steamtable.AccountsForExp(*exp); err != nil {
			return fmt.Errorf("--exp: %v", err)
		}
	} else {
		ma, err = strconv.ParseUint(strings.ReplaceAll(*maxAccount, "_", ""), 10, 64)
		if err != nil || ma == 0 || ma > steamtable.FullRange {
			return fmt.Errorf("--max-account must be 1 to %d", steamtable.FullRange)
		}
	}
	if *cores < 1 {
		return errors.New("--cores must be at least 1")
	}
	ib := *indexBits
	if ib == 0 {
		ib = steamtable.AutoIndexBits(*entryBytes, ma)
	}

	est := int64(ma) * int64(*entryBytes)
	passes := 1 + (ma*8+uint64(mem)-1)/uint64(mem)
	split := "one file"
	if *parts > 0 {
		split = fmt.Sprintf("%d files", *parts)
	} else if ps > 0 {
		split = fmt.Sprintf("files of at most %s", steamtable.HumanBytes(ps))
	}
	fmt.Fprintf(os.Stderr, "building a %d-byte table of %d accounts (about %s + %s index) in %s, %s\n",
		*entryBytes, ma, steamtable.HumanBytes(est), steamtable.HumanBytes(4<<ib), *dir, split)
	fmt.Fprintf(os.Stderr, "%d hash passes on %d core(s), %s for sorting\n", passes, *cores, steamtable.HumanBytes(mem))

	opt := steamtable.BuildOptions{
		Dir: *dir, EntryBytes: *entryBytes, IndexBits: ib, MaxAccount: ma,
		PartSize: ps, Parts: *parts, Cores: *cores, Memory: mem, Force: *force,
		Progress: progressLine,
		Log:      func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) },
	}
	if set["exp"] {
		opt.Exp, opt.MaxAccount = *exp, 0
	}
	opt.SignKey = key
	start := time.Now()
	plan, err := steamtable.Build(opt)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "done in %s: %d file(s), %s\n", time.Since(start).Round(time.Second), len(plan.Parts), steamtable.HumanBytes(plan.TotalBytes))
	printParts(plan.Parts)
	if key != nil {
		fmt.Printf("signed: %s\n", steamtable.ManifestName)
	}
	return nil
}

func progressLine(stage string, done, total uint64, elapsed time.Duration) {
	pct := float64(done) * 100 / float64(total)
	rate := float64(done) / elapsed.Seconds()
	eta := "-"
	if done > 0 && done < total {
		eta = time.Duration(float64(total-done) / rate * float64(time.Second)).Round(time.Second).String()
	}
	end := "\r"
	if done == total {
		end = "\n"
	}
	unit := "M hashes/s"
	if stage == "hashing files" {
		unit = " MB/s" // signing and checking count bytes read, not MD5s
	}
	fmt.Fprintf(os.Stderr, "\r  %s: %5.1f%%  %.1f%s  eta %s   %s", stage, pct, rate/1e6, unit, eta, end)
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	path := fs.String("key", "", "where to write the private key (required; never overwritten)")
	fs.Parse(args)
	if strings.TrimSpace(*path) == "" {
		return errors.New("--key is required: where to save the private key, e.g. --key ~/steam2guid.key")
	}
	pub, err := steamtable.GenerateKey(*path)
	if err != nil {
		return err
	}
	fmt.Printf("private key: %s (keep it secret: anyone with it can sign tables as you)\n", *path)
	fmt.Printf("public key:  %s\n\n", steamtable.EncodePublicKey(pub))
	fmt.Println("Publish the public key, and add it to TrustedKeys in steamtable/steamtable.go so")
	fmt.Println("anyone who builds steam2guid from source trusts tables signed with this key.")
	return nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	dir := fs.String("dir", "", "table directory (required)")
	path := fs.String("key", "", "private key file from keygen (required)")
	cores := fs.Int("cores", runtime.NumCPU(), "files to hash at once")
	fs.Parse(args)
	if err := requirePath("dir", *dir); err != nil {
		return err
	}
	if strings.TrimSpace(*path) == "" {
		return errors.New("--key is required: the private key file from keygen")
	}
	key, err := steamtable.LoadKey(*path)
	if err != nil {
		return err
	}
	m, err := steamtable.Sign(*dir, key, *cores, func(d, t uint64, el time.Duration) { progressLine("hashing files", d, t, el) })
	if err != nil {
		return err
	}
	fmt.Printf("signed %d file(s) with %s\nwrote %s\n", len(m.Files), steamtable.EncodePublicKey(m.Key), steamtable.ManifestName)
	return nil
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	dir := fs.String("dir", "", "table directory (required)")
	pubkeys := fs.String("pubkey", "", "also trust these public keys (comma-separated), besides the ones built in")
	cores := fs.Int("cores", runtime.NumCPU(), "files to hash at once")
	fs.Parse(args)
	if err := requirePath("dir", *dir); err != nil {
		return err
	}
	var extra []ed25519.PublicKey
	for _, s := range strings.Split(*pubkeys, ",") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		k, err := steamtable.ParsePublicKey(s)
		if err != nil {
			return fmt.Errorf("--pubkey: %v", err)
		}
		extra = append(extra, k)
	}
	m, err := steamtable.Check(*dir, steamtable.CheckOptions{Keys: extra, Cores: *cores,
		Progress: func(d, t uint64, el time.Duration) { progressLine("hashing files", d, t, el) }})
	if err != nil {
		return fmt.Errorf("CHECK FAILED: %v", err)
	}
	fmt.Printf("ok: %d file(s) match the manifest signed by %s\n", len(m.Files), steamtable.EncodePublicKey(m.Key))
	return nil
}

func printParts(hs []steamtable.Header) {
	for _, h := range hs {
		first := uint64(h.FirstGroup) << (32 - h.IndexBits)
		last := (uint64(h.FirstGroup+h.Groups) << (32 - h.IndexBits)) - 1
		fmt.Printf("%s  GUIDs %08x.. to %08x..  %12d accounts  %s\n",
			steamtable.PartName(h.Part), first, last, h.Entries, steamtable.HumanBytes(h.FileSize()))
	}
}

func cmdLookup(args []string) error {
	fs := flag.NewFlagSet("lookup", flag.ExitOnError)
	dir := fs.String("dir", "", "table directory (required)")
	fs.Parse(args)
	if err := requirePath("dir", *dir); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("give one or more GUIDs")
	}
	t, err := steamtable.Open(*dir)
	if err != nil {
		return err
	}
	defer t.Close()
	missing := 0
	for _, g := range fs.Args() {
		start := time.Now()
		id, found, err := t.Lookup(g)
		took := time.Since(start).Round(time.Microsecond)
		switch {
		case err != nil:
			return err
		case found:
			// A full URL: most terminals make it clickable (Ctrl/Cmd-click).
			fmt.Printf("%s  https://steamcommunity.com/profiles/%d  (%s)\n", strings.ToLower(g), id, took)
		default:
			missing++
			fmt.Printf("%s  not found (no account below %d has this GUID)  (%s)\n", strings.ToLower(g), t.MaxAccount, took)
		}
	}
	if missing > 0 {
		os.Exit(3)
	}
	return nil
}

func cmdInfo(args []string) error {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	dir := fs.String("dir", "", "table directory (required)")
	fs.Parse(args)
	if err := requirePath("dir", *dir); err != nil {
		return err
	}
	t, err := steamtable.Open(*dir)
	if err != nil {
		return err
	}
	defer t.Close()
	cover := fmt.Sprintf("accounts 0 to %d", t.MaxAccount-1)
	if n, ok := t.Exp(); ok {
		cover = fmt.Sprintf("accounts below 2^%d (0 to %d)", n, t.MaxAccount-1)
	}
	fmt.Printf("%d-byte entries, %d index bits, %s (SteamID64 %d to %d)\n",
		t.EntryBytes, t.IndexBits, cover, steamtable.Base, steamtable.Base+t.MaxAccount-1)
	printParts(t.Headers())
	return nil
}

// requirePath errors when a required directory flag wasn't given.
func requirePath(flagName, path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("--%s is required: give the table's directory, e.g. --%s /data/table", flagName, flagName)
	}
	return nil
}

// parseSize reads 2G, 512M, 1.5T, 2GB, 2GiB or a plain byte count.
// Units are 1024-based.
func parseSize(s string) (int64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimSuffix(strings.TrimSuffix(s, "B"), "I")
	mult := 1.0
	if s != "" {
		if i := strings.IndexByte("KMGT", s[len(s)-1]); i >= 0 {
			mult = float64(int64(1) << (10 * (i + 1)))
			s = s[:len(s)-1]
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("%q isn't a size like 2G or 512M", s)
	}
	return int64(f * mult), nil
}
