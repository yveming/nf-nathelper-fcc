# nf-nathelper-fcc

Kernel conntrack + NAT helper modules that let an IPTV set-top box run the
**FCC (Fast Channel Change)** protocol through a Linux router doing plain NAT
— the same role the classic `nf-nathelper-rtsp` plays for RTSP.

| Module | Role |
|---|---|
| `nf_conntrack_fcc.ko` | Conntrack helper `"fcc"` on a configurable UDP port (default 8027) |
| `nf_nat_fcc.ko` | Rewrites the client address/ports embedded in FCC requests and opens the media-channel expectation |

Both operator variants are supported:

- **Telecom** — RTCP feedback FMT 2/3/4/5; media port = signaling port
  (single-port protocol); servers follow **redirect chains**
  (type=3 → the client re-sends the REQ to the next server).
- **Huawei** — RTCP feedback FMT 5/6/8/9; media port = **signaling port − 1**;
  the REQ embeds `client_ip` + `signal_port` and must have `client_ip`
  rewritten; the client sends a **FMT12 punch toward the media server only
  when the response carries the NAT flag with a media IP/port**; the server
  pushes the unicast burst to `client_ip:media_port` and finishes with a
  sync notification before the client joins multicast.

## Design

### Why a POSTROUTING hook

An FCC request is the *first* packet of its UDP flow: at PREROUTING time the
source-NAT mapping does not exist yet, so the public address/ports that must
be advertised inside the payload are simply not knowable there. The NAT side
therefore runs as a POSTROUTING hook at `NF_IP_PRI_NAT_SRC + 10`, reads the
final mapping from the conntrack reply tuple, rewrites the payload and
registers the media expectation.

### Expectation shape and dst-only translation

The expectation matches **any** source host to `client_WAN:media_port` (FCC
media may come from a redirect target, not the signaling server) and maps it
back to the client's LAN `media_port` via `saved_proto`.

The translate function (`fcc_expect_translate()`) is **destination-only** —
it deliberately does *not* rewrite the media source, unlike
`nf_nat_follow_master()`:

- FCC media comes from dedicated servers in a **resource pool**, which is
  rarely the signaling server the expectation's master points at;
- the client has already punched toward the **real** media address, so it
  expects packets from exactly that source;
- rewriting the source would present the STB an address it never talked to.

This keeps the media flow a single plain DNAT — the same shape an RTSP media
flow has.

### Port takeover on redirect chains

Every redirect hop re-sends the REQ from the same client port while
advertising it again, so the previous hop's expectation (same client, 30 s
TTL) still occupies the advertised port — the `-EBUSY`. In that case the
helper **takes the port over**: the stale expectation is removed and a
*fresh* expectation object, with the current hop as master, is inserted on
the same port. The advertised port therefore stays **unchanged across the
whole chain**. If the port is held by another client, it is bumped instead.

Never re-insert an expectation object that already went through a failed
`nf_ct_expect_related()` attempt — always allocate a fresh one per insert.

### The `nf_ct_expect_init()` pitfall

**`nf_ct_expect_init()` resets `expect->expectfn` to NULL and zeroes
`saved_proto`** (verified against the 6.18.52 source). Anything assigned to
those fields *before* the call is silently lost. The expectation is then
consumed by the media flow but translates nothing: the conntrack entry
stays a plain one-way `[UNREPLIED]` record and the STB never sees media.

```
nf_ct_expect_init(exp, ...);          /* first            */
exp->saved_proto.udp.port = port;     /* then — always    */
exp->dir = IP_CT_DIR_REPLY;
exp->expectfn = fcc_expect_translate;
```

This ordering bug produced expectations that were created "successfully",
visible one moment, consumed by the media flow — and delivered nothing. 

## Project layout

```
├── Makefile     OpenWrt package Makefile — the project root IS the package dir
├── src/
│   ├── Kbuild               kbuild rules (obj-m += both modules)
│   ├── nf_fcc.h             shared FCC wire-format definitions
│   ├── nf_conntrack_fcc.c   conntrack helper "fcc"
│   └── nf_nat_fcc.c         payload rewrite + media expectation (POSTROUTING)
└── README.md
```

## Build

`make` in the project directory builds both modules, targets the running kernel by
default:

```bash
make                 # src/*.ko against the running kernel
make KERNEL_DIR=/path/to/linux-build ARCH=arm64 \
     CROSS_COMPILE=aarch64-linux-musl- modules   # explicit tree / cross build
make clean
make modules_install # optional; needs root or INSTALL_MOD_PATH
```

> Cross-building note: `ARCH` is the **kernel** architecture name (`arm64`),
> not the toolchain prefix (`aarch64-...`). In an OpenWrt tree the package
> build sets all of this itself (`make package/fcc-nathelper/compile`).

## OpenWrt package

`openwrt/fcc-nathelper/` is a standard OpenWrt package definition producing
a single signed kmod package, same shape as `kmod-nf-nathelper-rtsp`:

| `kmod-nf-nathelper-fcc` contains | Path on device |
|---|---|
| `nf_conntrack_fcc.ko` + `nf_nat_fcc.ko` | `/lib/modules/<kver>/` |
| autoload list (both modules) | `/etc/modules.d/45-nf-nathelper-fcc` |
| post-install hook | appends an `fcc` section to `/usr/share/firewall4/helpers` and reloads fw4 |

The project root **is** the package directory — its `Makefile` is the
package Makefile and `Build/Prepare` picks up `src/` directly. Symlink the
whole project into an OpenWrt tree and build:

```bash
ln -s "$PWD" ~/openwrt-pon/package/fcc-nathelper
make package/fcc-nathelper/compile          # → kmod-nf-nathelper-fcc-<kver>-r<N>.apk
```

> After editing `kernel/`, remove the package build dir in the OpenWrt tree
> (`rm -rf build_dir/.../fcc-nathelper-1.0.0`) or run
> `make package/fcc-nathelper/clean` — the Prepare step copies sources once.

On the device:

```bash
apk add --no-network /tmp/kmod-nf-nathelper-fcc-<kver>.apk
nft list ruleset | grep -B2 -A2 'ct helper set "fcc"'    # verify assignment rule
```

### Configuration

- **FCC port**: append the module parameter in
  `/etc/modules.d/45-nf-nathelper-fcc`, e.g. `nf_conntrack_fcc port=8030`.
  The helper name is `fcc` for the default 8027 and `fcc-<port>` otherwise —
  update `option name`/`option port` in `/usr/share/firewall4/helpers`
  accordingly.

### Debug

`nf_nat_fcc` takes a `debug` parameter (runtime-writable):

```bash
modprobe nf_nat_fcc debug=1
# or: echo 1 > /sys/module/nf_nat_fcc/parameters/debug
```

Log lines, one per decision (`dmesg | grep nf_nat_fcc`):

| Line | Meaning |
|---|---|
| `media expectation created on port <p>` | fresh expectation inserted |
| `port <p> held by this/another client` | `-EBUSY` clash ownership check |
| `media expectation taken over on port <p>` | redirect-hop takeover succeeded |
| `port <p> held by another client, bumping` | clash from someone else → +1 |
| `telecom: rewriting client_port a -> b` | payload rewrite needed (only when the port was bumped) |
| `flow already handled, skip` | this flow was processed before (`done`) |
| `payload is not an FCC REQ (len N), skip` | TERM/SYN/punch — left untouched |

## Troubleshooting (field-tested)

- **`conntrack -F` before reproducible tests.** Stale entries change what
  the next REQ hits.
- **Media ct frozen at ~31–33 packets with `[HW_OFFLOAD]`: normal.** The
  flowtable/PPE took over after the first few packets; the counter stops
  updating but the hardware keeps forwarding the rest of the burst. Verified
  end to end (STB unicast active → sync → multicast join) on both protocol
  variants.
- **`[UNREPLIED]` on the media ct: normal for Huawei.** The Huawei STB's
  feedback travels via its own FMT12 punch only when NAT flag advertised. It
  is also stale by construction on HW-offloaded flows — PPE-forwarded packets
  update the counters but never set the `SEEN_REPLY`/`ASSURED` status bits.
- **`conntrack -L expect` empty right after media started: success, not
  loss.** A consumed expectation is removed from the table; the media
  conntrack with the DNAT binding is the proof it fired.
- **`conntrack -E` (even `expect`) may show nothing when redirected to a
  file** — stdio full buffering discards it on kill. Do not use it as
  evidence that expectations are not created; use
  `cat /proc/net/nf_conntrack_expect` or `conntrack -L expect` within the
  30 s TTL instead.
- **Do not filter tcpdump on port 8027** when watching for media — the RTP
  burst uses other ports and you will filter it out.
- **Media DNAT'd but the STB seems stuck**: don't read the media ct's
  `[UNREPLIED]` as failure (Huawei feedback travels via the punch path; on
  HW-offloaded flows the status flags go stale too — the picture is the
  signal). A forward-chain accept for expected media was A/B-tested and
  proved **unnecessary** on the target box and is not installed. If your own
  policy drops wan→lan forwarding, add a traffic rule to taste.

## Relationship to fccproxy

The wire-format definitions (RTCP-FB header, FMT sets, FMT-5 length
disambiguation, field offsets) are **ported from the fccproxy userspace
proxy** (`src/fcc*.c|h`) so the two stay wire-compatible; the kernel side
additionally pins the critical offsets with `BUILD_BUG_ON`. No code is
shared: fccproxy is the userspace alternative (full protocol conversion and
proxying), this project is the in-kernel transparent NAT helper for the
common case (STB and server speak the same variant, only NAT is in the way).

## License

GPL-2.0. The kernel modules must be GPL; this project is therefore separate
from (and independent of) the AGPL-licensed fccproxy.
