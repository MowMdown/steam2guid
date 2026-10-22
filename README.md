# steam2guid

Precomputes a table of every Steam account's BattlEye GUID, so a GUID can be
turned back into a SteamID64 with a disk read instead of hashing billions of
accounts. Built for ReCON, which reads these tables directly.

A BattlEye GUID is `md5("BE" + SteamID64 as 8 little-endian bytes)`. MD5 can't
be reversed, but there are only 2^32 possible account IDs, so steam2guid hashes
all of them once and stores them sorted by GUID. Lookups after that take
microseconds.

## Layout

```
steam2guid/
├── go.mod             module steam2guid
├── main.go            the command-line tool
└── steamtable/
    ├── steamtable.go  reading tables, checking signatures
    └── build.go       building tables, signing
```

Both files in `steamtable/` are needed to build the tool. A program that only
reads tables needs only `steamtable.go`.

Standard library only; needs Go 1.24 or newer.

```sh
go build -o steam2guid .
```

## Quick start

```sh
# A table of every account in use today (2,147,483,648 accounts, about 8 GiB)
steam2guid --out /data/table --exp 31

# Look a GUID up
steam2guid lookup --dir /data/table 49aacf68461f67163d0a2ecb6a4cee94
```

```
49aacf68461f67163d0a2ecb6a4cee94  https://steamcommunity.com/profiles/76561198023219106  (6µs)
```

The link is clickable in most terminals (Ctrl-click, or Cmd-click on macOS).

## Commands

| Command | What it does |
|---|---|
| `steam2guid [build] --out D [flags]` | Build a table in `D`. `build` is the default command. |
| `steam2guid lookup --dir D GUID...` | Print each GUID's Steam profile link. |
| `steam2guid info --dir D` | Show the table's settings and its part files. |
| `steam2guid keygen --key F` | Make a signing key. See [Signing](#signing-tables). |
| `steam2guid sign --dir D --key F` | Sign an existing table. |
| `steam2guid check --dir D [--pubkey K]` | Check a table's signature and every byte. |

Running `steam2guid` with no arguments prints the help. There is no default
table folder: `--out` and `--dir` are always required.

### Build flags

| Flag | Default | Meaning |
|---|---|---|
| `--out` | (required) | Directory to write the table to |
| `--exp` | | Build a table of 2^n accounts, n = 1 to 32 |
| `--max-account` | 4294967296 | Cover this many accounts (use `--exp` or this, not both) |
| `--bytes` | 4 | Bytes per account: 2, 4 or 8 (see [Entry sizes](#entry-sizes)) |
| `--part-size` | 2G | Largest file size (K, M, G, T; 1024-based); `0` = one file |
| `--parts` | | Split into exactly this many files instead |
| `--cores` | all CPUs | CPU cores to hash with |
| `--mem` | 4G | Memory for sorting; less memory means more passes |
| `--index-bits` | auto | GUID bits used to group entries |
| `--sign-key` | | Private key file to sign the table with when it's built |
| `--force` | | Replace an existing table in `--out` |

`--cores` defaults to the number of CPUs the system reports on each run. Inside
a container limited with `--cpus`, Go still sees every CPU on the host, so pass
`--cores` to match the limit.

### Exit codes

`0` success, `1` error, `2` bad command line, `3` from `lookup` when any GUID
wasn't found.

## Sizes

| `--bytes` | `--exp 32` (every ID) | `--exp 31` | Lookup cost |
|---|---|---|---|
| 8 | ~32 GiB | ~16 GiB | one MD5 |
| 4 (default) | ~16 GiB | ~8 GiB | 3–4 MD5s, microseconds |
| 2 | ~8 GiB | ~4 GiB | millions of MD5s, about a second |

Plus a small index (64 MiB for a full 4-byte table).

`--exp 31` covers every Steam account in use today. ReCON handles newer
accounts on its own: it searches the IDs above the table by brute force.

## Entry sizes

- **4 bytes** (default) stores each account ID. Lookups probe a few entries,
  hashing each to compare.
- **8 bytes** also stores part of each GUID, so a lookup binary-searches and
  hashes once. Twice the disk for little real gain.
- **2 bytes** stores only the low 16 bits of each account ID. Half the disk,
  but a lookup has to try every possible high half: millions of MD5s.

A lookup always re-hashes the account it finds, so a table can never return a
wrong SteamID, only miss.

## Building

The table is bigger than memory, so it is built in passes. Pass 1 counts how
many accounts fall in each group; each later pass hashes every account again
and writes one batch of groups. With the default `--mem 4G`, a full table takes
9 passes and `--exp 31` takes 5. More memory means fewer passes; more cores make
each pass faster.

Part files are written as `steam2guid-NNN.bin.partial` and renamed when the
build finishes, so an interrupted build never leaves something that looks like
a finished table.

## Signing tables

Tables can be signed, so people who download yours can check they came from
you and that no byte has changed. Signing uses Ed25519 from Go's standard
library.

### Publishing

```sh
# Once: make a key. The private half is written readable only by you,
# and an existing file is never overwritten.
steam2guid keygen --key ~/steam2guid.key
```

```
private key: /home/you/steam2guid.key (keep it secret: anyone with it can sign tables as you)
public key:  xQotTaRZ2zKC/RIi37TzPGwCdt698XiP4Cc/VTI1dnk=
```

Put the public key in `TrustedKeys` in `steamtable/steamtable.go` and publish
the source with it:

```go
var TrustedKeys = []string{
	"xQotTaRZ2zKC/RIi37TzPGwCdt698XiP4Cc/VTI1dnk=",
}
```

Then sign while building, or sign a table you already have:

```sh
steam2guid --out /data/table --exp 31 --sign-key ~/steam2guid.key
steam2guid sign --dir /data/table --key ~/steam2guid.key
```

This writes `steam2guid-manifest.sig` next to the part files. Publish it with
them.

### Checking a download

Build steam2guid from the published source, which has the publisher's key
compiled in, and run:

```sh
steam2guid check --dir /path/to/table
```

```
ok: 4 file(s) match the manifest signed by xQotTaRZ2zKC/RIi37TzPGwCdt698XiP4Cc/VTI1dnk=
```

`check` fails, and says why, if:

- the manifest isn't signed by a trusted key, or was edited after signing
- any part file is missing, extra, changed or damaged
- the table has no manifest at all

It reads every byte of every part, so it takes about as long as reading the
table from disk. `--pubkey KEY` (comma-separated for several) trusts extra keys
for one run.

### What signing does and doesn't do

- Trust comes from the source: `check` trusts whatever keys are compiled in,
  so the guarantee is only as good as where the source came from.
- Keep the private key safe. Anyone with it can sign tables as you. If it
  leaks, make a new key and replace the old one in `TrustedKeys`.
- Lookups don't check signatures. Readers only open `steam2guid-*.bin` files
  and ignore the manifest; run `check` after downloading.

### The manifest

Plain text, one line per part, signed as a whole:

```
steam2guid-manifest 1
entry-bytes 4
index-bits 12
max-account 1048576
file steam2guid-000.bin 1403840 6a54ccd15197522ef0b19ed1da13f8d2ebbdaf562ab8096603e47afc7d3aeb8b
file steam2guid-001.bin 1404808 39ec146ef8ecb53041ff720e3d0188c2129cd49af31891d1c7a14b48ea9d1d3c
file steam2guid-002.bin 1402232 2d453ce401ed15ef6fb9ba723b5e5d5f1e7dbceb14d1e46acddcbdc5a094486e
key xQotTaRZ2zKC/RIi37TzPGwCdt698XiP4Cc/VTI1dnk=
signature vkTqzp66HqTsq+DVSjAcEI25JPX35FKvGCBXMztSpP4kk+g0QPLVai5YGXOrmovmXr+FzmlOCC5ApUDLM+zWBg==
```

Each `file` line is the part's name, size in bytes and SHA-256. The signature
covers every line above it.

## Using a table with ReCON

ReCON looks for a table in `STEAM_TABLE_DIR` (default `/steam2guid`) each time
it searches for SteamIDs. GUIDs the table has are answered at once; only
accounts above the table's range are brute-forced. With no table, ReCON
searches as before. The table is opened fresh for every search, so adding or
replacing it needs no restart.

Mount it read-only; several ReCON containers can share one copy:

```yaml
    volumes:
      - /mnt/user/appdata/rcon/deerisle:/data
      - /mnt/user/appdata/steam2guid-table:/steam2guid:ro
```

## File format

Each part file is a 64-byte header, an index of where each group of entries
starts, then the entries sorted by GUID. The full layout is documented at the
top of `steamtable/steamtable.go`.

The format is read in three places: this tool, ReCON's `steam.go` and
steam2guid-reader. A change to the format must be made in all three.
