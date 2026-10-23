# Diagnostics

The Diagnostics screen (and `tirnix report`) turns raw numbers into
findings. Each finding has three clearly separated parts:

- **Measured** – values Tirnix actually read, with the time window they
  cover.
- **Possible causes** – hypotheses that would explain the measurement. They
  are not verified by Tirnix.
- **How to verify** – commands to confirm or rule out each hypothesis.
  Commands marked as active tests generate network traffic.

## Avoiding false alarms

- Rules about rates and utilisation fire only when the condition holds in at
  least 80 % of the samples of a **sustain window** (30 s in the TUI, the
  whole sampling period in `tirnix report`), and the samples must cover at
  least 70 % of that window. A single spike never produces a finding.
- Point-in-time facts fire immediately: an almost full filesystem, an OOM
  kill that happened after Tirnix started.
- Thresholds are conservative and documented below.
- If no system data could be read, Tirnix says that diagnostics were not
  evaluated instead of reporting "no anomalies".

## Rules

| Finding | Severity | Condition |
|---|---|---|
| CPU is saturated | warning | CPU busy ≥ 90 % (sustained) |
| High load average while CPUs are not saturated | warning | load1 ≥ 1.5 × CPUs (sustained), CPU not saturated – usually tasks blocked on I/O |
| High CPU steal time | warning | steal ≥ 10 % (sustained) |
| Processes are waiting on disk I/O / a disk is busy | warning | iowait ≥ 20 %, or busiest disk utilisation ≥ 90 %, or I/O PSI ≥ 20 % (sustained) |
| Available memory is low | warning / critical | MemAvailable < 10 % (critical < 5 % or while swapping) (sustained) |
| Memory is exhausted and the system is swapping | critical | low memory + swap in/out ≥ 100 pages/s (sustained) |
| Sustained swap activity | warning | swap in/out ≥ 100 pages/s with enough available memory |
| Tasks stall on memory although RAM is available | warning | memory PSI ≥ 10 % (sustained) – typically a cgroup limit |
| Swap is in use but idle | info | > 25 % of swap used, no swap traffic |
| OOM killer terminated processes | critical | `oom_kill` counter increased since Tirnix started |
| OOM kills earlier since boot | info | `oom_kill` > 0 at start |
| Filesystem is X % full | warning / critical | ≥ 90 % / ≥ 95 % used (writable filesystems) |
| Filesystem is filling up quickly | warning | free space declined steadily for ≥ 10 min and would run out within 24 h at that rate (estimate, labelled as such) |
| Filesystem is running out of inodes | warning / critical | ≥ 90 % / ≥ 95 % of inodes used |
| Damaged frames are received on *iface* | warning | CRC / alignment / length errors in ≥ 3 samples |
| *iface*: network card runs out of receive buffers | warning | missed / FIFO / over errors in ≥ 3 samples; shows which CPUs take the interrupts |
| CPU *n* cannot keep up with incoming packets | warning | receive backlog drops (`softnet_stat`) in ≥ 3 samples; names the CPUs |
| UDP socket *addr* (*process*) drops datagrams | warning | UDP receive buffer errors in ≥ 3 samples; names socket, process and user |
| Connection tracking table full / almost full | critical / warning | conntrack drops / ≥ 90 % of `nf_conntrack_max` |
| TCP is discarding received data inside the kernel | warning | pruned / backlog / receive-queue / out-of-order drops in ≥ 3 samples |
| Frames for unused protocols are discarded | info | `rx_nohandler` on a watched interface (harmless) |
| Packets are dropped for a reason the counters do not show | info | ≥ 1 drop/s (sustained) not explained above; lists what was ruled out |
| Network interface errors | warning | interface errors in most samples, not explained by damaged frames or overruns |
| High TCP retransmission rate (… mostly with *peer*) | warning | ≥ 2 % of sent segments and ≥ 5 retransmits/s (sustained); lists peers and processes |
| TCP connection attempts are not being answered | warning | as above, ≥ 50 % of retransmissions are SYN/SYN-ACK |
| TCP retransmissions are mostly retries to a full listen queue | info | as above while this host's own listen queue drops |
| Incoming TCP connections dropped at *addr* (*process*) | warning | listen queue drops in ≥ 2 samples; names listener, process and queue length |
| Many sockets in TIME_WAIT | info | ≥ 30 000 |
| Tasks persistently blocked on I/O | info | ≥ 2 tasks blocked (sustained) |
| Many zombie processes | info | ≥ 20 zombies; parents listed |
| File handle limit nearly reached | warning / critical | ≥ 80 % / ≥ 95 % of `fs.file-max` |

## Finding the source of network drops

Interface counters say *that* packets are lost; Tirnix tries to say *where*
and *who*. Cheap counters are read on every sample; detailed sources only
while those counters show a problem, at most every 5 seconds:

| Drop location | Source | What Tirnix names |
|---|---|---|
| Damaged frames | `/sys/class/net/<if>/statistics/rx_{crc,frame,length}_errors` | interface |
| NIC receive ring overflow | `rx_{missed,over,fifo}_errors` + `/proc/interrupts` | interface, CPUs taking its interrupts and how busy they are |
| Frames without a protocol handler | `rx_nohandler` | interface (harmless) |
| Kernel receive backlog | `/proc/net/softnet_stat` | CPUs that drop |
| UDP socket buffers | `Udp`/`Udp6 RcvbufErrors`, `/proc/net/udp{,6}` drops column | socket, process, user |
| TCP accept queue | `TcpExt ListenDrops`, `/proc/net/tcp{,6}` listeners | listener, process, user, queue length |
| TCP retransmissions | `Tcp RetransSegs`, `TcpExt TCPSynRetrans`, per-socket retransmit counter | peers, processes, SYN share |
| Connection tracking | `nf_conntrack_count/max`, `/proc/net/stat/nf_conntrack` | table usage, drops |
| TCP memory pressure | `TcpExt RcvPruned`, `TCPBacklogDrop`, `TCPRcvQDrop`, … | breakdown |

Processes are found by matching socket inodes with `/proc/<pid>/fd`. Without
root, other users' processes cannot be inspected; Tirnix then still names
the **user** (from the socket table) and says that the process is hidden.

Drops that none of these counters explain – transmit queue (qdisc) drops,
bond backup members, XDP/eBPF or bridge filtering – are reported as such,
with the list of causes that were ruled out and commands that can locate
them (`tc -s qdisc`, `/proc/net/bonding`, `perf … skb:kfree_skb`).

The **Data sources** list on the Diagnostics screen shows which inputs were
available; a rule whose inputs are missing simply cannot fire.

## Active checks

Passive monitoring never sends anything over the network. The optional
active checks are separate:

1. Configure targets in Settings → Active checks (e.g. `example.com:443`,
   `10.0.0.1:22`), or in the config file under `[active_checks] targets`.
2. Press `a` on the Diagnostics screen.

For each target Tirnix resolves the name with the system resolver and opens
one TCP connection (no data is sent), reporting resolution and connect time
or the error. Nothing runs automatically.
