# nf-nathelper-fcc

Kernel conntrack + NAT helper modules that let an IPTV set-top box run the
**FCC (Fast Channel Change)** protocol through a Linux router doing plain NAT.
Wire format (RTCP feedback framing, field offsets) is ported from the
fccproxy userspace implementation; the kernel side pins critical offsets with
`BUILD_BUG_ON`.

| Module | Role |
|---|---|
| `nf_conntrack_fcc.ko` | Conntrack helper `"fcc"` on a configurable UDP port (default 8027) |
| `nf_nat_fcc.ko` | Rewrites the client address/ports embedded in FCC requests and opens the media-channel expectation |

Operator variants:

- **Telecom** — RTCP feedback FMT 2/3/4/5; media port = signaling port
  (single-port protocol); servers follow redirect chains (type=3 → the
  client re-sends the REQ to the next server).
- **Huawei** — RTCP feedback FMT 5/6/8/9; media port = **signaling port − 1**;
  the REQ embeds `client_ip` + `signal_port`, `client_ip` must be rewritten;
  the client sends a FMT12 punch toward the media server when the response
  carries the NAT flag, and the server pushes the unicast burst to
  `client_ip:media_port` before the client joins multicast.

## Design

### Why a POSTROUTING hook

An FCC request is the *first* packet of its UDP flow: at PREROUTING the
source-NAT mapping does not exist yet, so the public address/ports that must
be advertised inside the payload are unknowable there. The NAT side therefore
runs as a POSTROUTING hook at `NF_IP_PRI_NAT_SRC + 10`, reads the final
mapping from the conntrack reply tuple, rewrites the payload and registers the
media expectation.

### Expectation shape and dst-only translation

The expectation matches **any** source host to `client_WAN:media_port` (FCC
media may come from a redirect target, not the signaling server) and maps it
back to the client's LAN `media_port` via `saved_proto`.

`fcc_expect_translate()` deliberately does *not* rewrite the media source,
unlike `nf_nat_follow_master()`:

- FCC media comes from dedicated servers in a resource pool, rarely the
  signaling server the expectation's master points at;
- the client has already punched toward the real media address and expects
  packets from exactly that source.

The media flow stays a single plain DNAT, the same shape an RTSP media flow
has.

### Port takeover on redirect chains

Every redirect hop re-sends the REQ from the same client port while
advertising it again, so the previous hop's expectation (same client, 30 s
TTL) still occupies the advertised port — the `-EBUSY`. In that case the
helper takes the port over: the stale expectation (matching the same LAN
source address/port) is removed and a *fresh* expectation is inserted with
the current hop as master, keeping the advertised port unchanged across the
whole chain. If the port is held by another client, it is bumped (+1) and the
new value is advertised in the payload. Never re-insert an expectation object
that already went through a failed `nf_ct_expect_related()` attempt — always
allocate a fresh one per insert.

### `nf_ct_expect_init()` ordering pitfall

`nf_ct_expect_init()` resets `expect->expectfn` to NULL and zeroes
`saved_proto`. Anything assigned to those fields *before* the call is
silently lost: the expectation is consumed by the media flow but translates
nothing, and the conntrack entry stays a plain one-way `[UNREPLIED]` record.
Assign after:

```c
nf_ct_expect_init(exp, ...);          /* first            */
exp->saved_proto.udp.port = port;     /* then — always    */
exp->dir = IP_CT_DIR_REPLY;
exp->expectfn = fcc_expect_translate;
```

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

```bash
make                 # src/*.ko against the running kernel
make KERNEL_DIR=/path/to/linux-build ARCH=arm64 \
     CROSS_COMPILE=aarch64-linux-musl- modules   # explicit tree / cross build
make clean
make modules_install # optional; needs root or INSTALL_MOD_PATH
```

`ARCH` is the kernel architecture name (`arm64`), not the toolchain prefix.
Inside an OpenWrt tree the package build sets all of this itself.

## OpenWrt package

The project root doubles as the package directory. Symlink it into an
OpenWrt tree and build:

```bash
ln -s "$PWD" ~/openwrt/package/fcc-nathelper
make package/fcc-nathelper/compile   # → kmod-nf-nathelper-fcc-<kver>-r<N>.apk
```

`kmod-nf-nathelper-fcc` contains both modules, the autoload list
(`/etc/modules.d/45-nf-nathelper-fcc`), and maintainer scripts that
append an `fcc` section (between `# >>>/<<< kmod-nf-nathelper-fcc`
markers) to `/usr/share/firewall4/helpers`. The scripts are
`IPKG_INSTROOT`-aware: during image build they bake the section into
the rootfs, on the device they additionally `modprobe` the module and
reload fw4. `prerm` strips the marked section again on uninstall —
`apk del` only removes files the package owns, the appended block would
otherwise survive. Helper rendering is gated on the module being loaded:
a missing module simply hides the rules instead of breaking the firewall.
After editing kernel sources, remove the package build dir
(`make package/fcc-nathelper/clean`) — the Prepare step copies sources once.

Verify the assignment rule on the device:

```bash
nft list ruleset | grep -B2 -A2 'ct helper set "fcc"'
```

### Configuration

FCC port: append the module parameter in `/etc/modules.d/45-nf-nathelper-fcc`,
e.g. `nf_conntrack_fcc port=8030`. The helper name is `fcc` for the default
8027 and `fcc-<port>` otherwise — update `option name`/`option port` in
`/usr/share/firewall4/helpers` accordingly.

### Debug

`nf_nat_fcc` takes a runtime-writable `debug` parameter that logs one line
per decision:

```bash
echo 1 > /sys/module/nf_nat_fcc/parameters/debug
dmesg | grep nf_nat_fcc
```

| Line | Meaning |
|---|---|
| `media expectation created on port <p>` | fresh expectation inserted |
| `port <p> held by this/another client` | `-EBUSY` clash ownership check |
| `media expectation taken over on port <p>` | redirect-hop takeover succeeded |
| `port <p> held by another client, bumping` | clash from someone else → +1 |
| `telecom: rewriting client_port a -> b` | payload rewrite (only when bumped) |
| `flow already handled, skip` | flow already processed (`done`) |
| `payload is not an FCC REQ (len N), skip` | TERM/SYN/punch — left untouched |

## Troubleshooting

- `conntrack -L expect` empty right after media started is **success**: a
  consumed expectation is removed from the table; the media conntrack with
  the DNAT binding is the proof it fired.
- Media ct frozen at a few dozen packets with `[HW_OFFLOAD]` is normal: the
  flowtable took over and the counters stop updating while forwarding
  continues.
- `[UNREPLIED]` on the Huawei media ct is normal: its feedback travels via
  the FMT12 punch, and offloaded flows never set the status bits.
- Do not filter tcpdump on port 8027 when watching for media: the RTP burst
  uses other ports.
- A forward-chain accept for expected media is not needed on default fw4
  setups; if your policy drops wan→lan forwarding, add a traffic rule.

## License

GPL-2.0. The kernel modules must be GPL; this project is therefore separate
from (and independent of) the AGPL-licensed fccproxy.
