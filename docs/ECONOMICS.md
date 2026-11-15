# SRP Economics and Latency Analysis

Status: v0.6. Written 2026-11-15 against the v0.5 implementation, then re-measured after the first three fixes in section 6 (persistent connections, listen backlog, snapshot memory). Where a number changed, the v0.5 figure is given for comparison.

This document asks one question and answers it with measured numbers where we have them, cited numbers where we do not, and clearly labelled assumptions everywhere else.

## 1. The question

**When does running RL environments in contributors' spare RAM beat renting the same RAM in a datacenter?**

The decentralized design has three costs a datacenter does not: network round trips between the trainer and the contributor, duplicated work for verification (replay audits), and moving snapshots to home connections. It has one possible advantage: capacity that is cheaper than rented RAM, or free.

Copy-on-Write (CoW) sharing is not an advantage of decentralization. It works just as well inside one datacenter, and it lowers the cost of the alternative SRP is competing with.

## 2. Measured inputs

All measurements come from `python -m benchmarks` (full run). Raw data and the summary table are in [`benchmarks/results/`](../benchmarks/results/RESULTS.md).

| | |
|---|---|
| Library commit | `a0d242e` (v0.5 figures: `1fd35e50f9bc`) |
| Machine | AMD Ryzen 5 5600H laptop, 12 logical CPUs |
| OS | Linux 6.18 under WSL2 (3.5 GB RAM given to the VM) |
| Python | CPython 3.14.4, `cryptography` installed |

These are the bundled simulated environments on a laptop. They describe this reference implementation, not production RL environments.

### 2.1 Step latency

Time per environment step with audits and canaries off ([`env_step_latency.json`](../benchmarks/results/env_step_latency.json)).

| Suite | Node step p50 | Node step p99 | Through coordinator p50 |
|---|---:|---:|---:|
| `srp-env-math` (tactic checker) | 0.18 ms | 0.41 ms | 0.39 ms |
| `srp-env-web` (DOM state machine) | 0.18 ms | 0.38 ms | 0.40 ms |
| `srp-env-spatial` (CAD verifier) | 0.28 ms | 0.51 ms | 0.47 ms |
| `srp-env-code` (sandboxed tests) | 40–80 ms | 100–550 ms | 35–45 ms |

Forking a branch takes 0.05–0.17 ms. Three of the four suites take well under a millisecond per step. The code suite is slower because each step starts an isolated sandbox process, and it varies a lot between runs (its ranges cover four full runs).

### 2.2 Network cost

The coordinator talks to a real `NodeServer` over TCP through a delay proxy that adds a configurable round-trip time (RTT) ([`network_simulation.json`](../benchmarks/results/network_simulation.json)). TLS was off; TLS would add round trips each time a new connection is opened.

`srp-env-web`, one episode at a time:

| RTT | Step p50 | Steps/s | vs. local | v0.5 step p50 | v0.5 vs. local |
|---:|---:|---:|---:|---:|---:|
| 0 ms (loopback) | 1.6 ms | 496 | 100% | 2.5 ms | 100% |
| 5 ms | 7.3 ms | 101 | 20% | 14 ms | 18% |
| 20 ms | 23 ms | 32 | 6.5% | 45 ms | 5.5% |
| 50 ms | 53 ms | 14 | 2.8% | 105 ms | 2.4% |
| 100 ms | 103 ms | 7.2 | 1.5% | 205 ms | 1.2% |
| 200 ms | 203 ms | 3.6 | 0.7% | 406 ms | 0.6% |

The "vs. local" column divides by the fastest local run, which itself got faster (303 to 496 steps/s), so it understates the gain; compare steps/s at each RTT, which roughly doubled.

Findings:

- **Every call now costs one round trip.** Added latency is 1.0 × RTT at every setting (v0.5: 2.0–2.1 × RTT). The transport keeps connections open, so the TCP handshake is paid once per connection: a sequential run of 112 calls used one connection, and 16 concurrent episodes used 15.
- **Halving latency did not change the picture for tight loops.** A sub-millisecond step is still dominated by the network: at 20 ms RTT one episode at a time runs at 32 steps/s instead of 17, against about 500 steps/s locally.
- **The transport itself costs about 1.2 ms per call** at 0 ms RTT, versus 0.35 ms in-process: signing, verifying and JSON.
- **Concurrency recovers throughput, not latency.** With 16 episodes in flight, throughput at 50 ms RTT rose from 14 to 162 steps/s, but each step still took 60 ms.
- **No more stalls under concurrent load.** In v0.5, 16 concurrent episodes with no added latency pushed p95 step time to about 1 second, because the server's listen queue (Python's default of 5) overflowed. With a backlog of 128 and pooled connections, p95 is 53 ms. In one of three runs since the fix, one code-suite condition (5 ms RTT, 16 concurrent) had an unexplained p50 of about 1 s; it did not recur, and looks like CPU contention from 16 sandbox processes on the 12-thread laptop, but it has not been investigated.
- **Bandwidth is not the bottleneck.** A step sends about 0.7–0.85 KB and receives 1.2–1.6 KB.

One fix was itself found by these benchmarks: with connections kept open, Nagle's algorithm on the server held each small response for the client's delayed ACK, adding about 40 ms per call on Linux. The server now disables it (`TCP_NODELAY`), and a regression test pins this.

### 2.3 Memory saved by Copy-on-Write

A 64 MB snapshot made of distinct pages, with N branches that each write 16 KB, measured by the operating system's resident set size (RSS) in a fresh process ([`cow_memory.json`](../benchmarks/results/cow_memory.json)).

| Branches | N full copies | Arena accounting | OS-level RSS | Saved (OS-level) |
|---:|---:|---:|---:|---:|
| 1 | 64 MB | 64 MB | 73.5 MB | −15% |
| 4 | 256 MB | 64 MB | 73.5 MB | 71% |
| 16 | 1,024 MB | 64 MB | 73.5 MB | 93% |
| 64 | 4,096 MB | 65 MB | 73.5 MB | 98% |

Findings:

- **Sharing works.** Branches cost almost nothing beyond their changed pages, so the savings figure grows with the branch count.
- **A pinned snapshot now costs 1.15× its size in RSS** (v0.5: 2.1×, 135 MB for 64 MB). v0.5 kept the original manifest, with the full file contents, alongside the page store; the arena now drops it after pinning. The remaining 15% is Python object overhead per 4 KB page, which the arena's own accounting still leaves out.
- **The per-branch RSS figure is below measurement resolution here.** The allocator reuses memory freed during pinning, so treat "about zero per branch" as "small", not as zero.

### 2.4 Replay audit overhead

The same episodes at different audit settings ([`replay_audit_overhead.json`](../benchmarks/results/replay_audit_overhead.json)). "Duplicated work" is auditor steps divided by provider steps.

| Audit setting | `web` duplicated | `web` wall-clock | `math` duplicated | `code` duplicated |
|---|---:|---:|---:|---:|
| No audits | 0% | +0% | 0% | 0% |
| 5% sampling only | 5% | +4% | 4% | 0% |
| 25% sampling only | 27% | +14% | 23% | 23% |
| 5% + **10%** of rewarded steps (`rewarded_audit_rate=0.1`) | 13% | +10% | 18% | 20% |
| 5% + **25%** of rewarded steps (`rewarded_audit_rate=0.25`) | 30% | +19% | 28% | 23% |
| **Default** (5% + every rewarded step) | **100%** | **+60%** | **100%** | **100%** |
| Audit everything | 100% | +74% | 100% | 100% |

Wall-clock overhead is noisy between runs (the default ranged from +52% to +76% for `web` across four runs); the duplicated-work column is exact. `code` runs only 30 steps, so its sampled rows are coarse.

Findings:

- **The default policy duplicates all the work on these workloads.** Audits are incremental, so auditing the last step of an episode replays the whole episode, and every bundled episode ends in a reward. The default therefore amounts to auditing everything.
- **Sampling rewarded steps cuts that in proportion.** Since v0.6, `rewarded_audit_rate` audits each rewarded or terminal step with a given probability. At 0.1, duplicated work fell from 100% to 13–20%; at 0.25, to 23–30%. The `math` episodes earn partial rewards on intermediate steps too, so they are sampled more than once per episode.
- **The cost is verification strength, not just compute.** A node that fabricates rewards is caught after about `1 / rate` lies on average (10 at 0.1), each uncaught lie reaches the trainer, and a lie on an unaudited final step is never re-checked. SRP-003 §2.2 sets out when a lower rate is acceptable. The default stays at 1.0.

## 3. External inputs

### 3.1 Datacenter RAM prices

Rented servers bundle RAM with CPU, storage and network, so these prices are an upper bound on what RAM alone costs.

| Offer | RAM | Price | Per GiB-hour | Per GiB-month |
|---|---:|---:|---:|---:|
| AWS r7i.16xlarge, on-demand ([Vantage](https://instances.vantage.sh/aws/ec2/r7i.16xlarge)) | 512 GiB | $4.234/h | $0.0083 | $6.04 |
| AWS r7i.16xlarge, 3-year reserved | 512 GiB | $1.920/h | $0.0038 | $2.74 |
| AWS r7i.16xlarge, spot | 512 GiB | $1.863/h | $0.0036 | $2.66 |
| Hetzner AX102 dedicated ([hetzner.com](https://www.hetzner.com/dedicated-rootserver/ax102/)) | 128 GB | €259/month | ~€0.0028 | ~€2.02 |

Prices as listed on 2026-11-15. Hetzner has published a price adjustment for new orders, so its current price may be higher; check before relying on it. The working range is **$0.003–0.008 per GiB-hour**, or roughly $2–6 per GiB-month.

### 3.2 Home broadband round-trip time

- US fixed broadband measured by the FCC (Measuring Broadband America, thirteenth report, autumn 2022 data): idle latency of about **8–14 ms for fiber, 12–24 ms for cable, 20–60 ms for DSL** to nearby test servers ([FCC](https://www.fcc.gov/reports-research/reports/measuring-broadband-america/measuring-fixed-broadband-thirteenth-report)).
- Geostationary satellite: about **600 ms** median ([FCC, eighth report](https://www.fcc.gov/reports-research/reports/measuring-broadband-america/measuring-fixed-broadband-eighth-report)).
- Those figures are to a nearby server. A trainer and a contributor on different continents add distance: light in fiber covers about 200 km per millisecond, so a 3,000 km path adds at least 30 ms of RTT before any routing.

A realistic coordinator-to-contributor RTT is therefore **20–50 ms within a region, 100–250 ms across continents**.

## 4. The model

### 4.1 Latency

For a step of compute time `T_step`, SRP adds about `k × RTT`. Measured: `k ≈ 1` with persistent connections (v0.6), `k ≈ 2` in v0.5. TLS adds round trips only when a connection is opened.

What matters to a trainer is not the step alone but the whole turn. In a multi-turn rollout, each turn is model generation (`T_gen`) followed by an environment step. The fraction of rollout time lost to the network is about:

```
overhead ≈ k × RTT / (T_gen + T_step + k × RTT)
```

`T_gen` depends on the model and the task; it is an **assumption** here, not a measurement.

| `T_gen` per turn (assumed) | RTT 20 ms | RTT 50 ms | RTT 200 ms | RTT 50 ms, v0.5 (k=2) |
|---:|---:|---:|---:|---:|
| 0.1 s | 17% | 33% | 67% | 50% |
| 1 s | 2% | 5% | 17% | 9% |
| 10 s | 0.2% | 0.5% | 2% | 1% |

The first three columns use `k = 1`.

When the environment loop is tight (short generations, sub-millisecond steps), the network dominates and SRP loses badly. When each turn involves seconds of generation, a contributor even 50 ms away adds only a few percent.

### 4.2 Cost

Let `c_dc` be the datacenter price per GiB-hour, `p` the price paid to a contributor per GiB-hour of environment RAM, and `a` the fraction of work duplicated by audits. The auditor runs on trusted (datacenter) hardware, so audits cost roughly `a × c_dc`. Ignoring coordination and network costs, SRP is cheaper only when:

```
p + a × c_dc < c_dc      →      p < (1 − a) × c_dc
```

| Audit duplication `a` | Max contributor price, at c_dc = $0.0036 | at c_dc = $0.0083 |
|---:|---:|---:|
| 100% (default `rewarded_audit_rate = 1.0`, on these workloads) | $0 | $0 |
| 25% (about `rewarded_audit_rate = 0.25`) | $0.0027 | $0.0062 |
| 20% (about `rewarded_audit_rate = 0.1`) | $0.0029 | $0.0066 |
| 5% | $0.0034 | $0.0079 |

This is a rough bound: audits duplicate compute rather than the full RAM-hours, so the true audit cost may be lower. Even so, it sets the scale. In v0.5 the demo ledger paid `0.05` per GB-hour, 6–18 times the entire datacenter price. Since v0.6 the USD and stablecoin reference ledgers default to example rates derived from this bound: **0.002 per GB-hour**, which undercuts the cheapest datacenter price above with up to about 40% audit duplication, and **0.000001 per step**, about 50 ms of a datacenter vCPU (`srp/settlement/base.py`, SRP-004 §4). They are examples, not market prices.

### 4.3 Snapshot distribution

A contributor has to download each snapshot before serving it. At 100 Mbit/s, a 2 GB environment snapshot takes about 2.7 minutes; at 25 Mbit/s, about 11 minutes. With contributors joining and leaving, that time is paid repeatedly. It is negligible for long-lived snapshots and significant for short-lived or frequently updated ones.

## 5. Where SRP wins and where it loses

**SRP loses:**

- **Tight loops with sub-millisecond steps.** At 20 ms RTT, one episode at a time runs at 6.5% of local throughput; at 100 ms, 1.5%.
- **Paid capacity at current prices.** A contributor would have to accept less than about $0.003–0.008 per GiB-hour, and less still once audits are counted. With the default audit policy (`rewarded_audit_rate = 1.0`), which duplicates all work on rewarded episodes, there is no positive price at which it is cheaper; a sampled policy is needed for paid capacity to make sense at all.
- **As an answer to the "RAM wall".** The 98% CoW saving measured here is available inside any datacenter too, so it shrinks the problem for everyone rather than favouring decentralization.
- **Frequently changing snapshots on slow home links.**

**SRP can win:**

- **Donated capacity.** Under the open-science karma model, `p ≈ 0`. An academic or non-profit group without a datacenter budget can trade latency and audit overhead for free RAM.
- **Latency-tolerant multi-turn workloads.** When each turn involves a second or more of model generation and many episodes run in parallel, a contributor in the same region adds a few percent to rollout time.
- **Long-running steps.** Compiling and testing code, running real containers or browsers: steps of hundreds of milliseconds or more make the round trip a small fraction.

## 6. Verdict

As implemented today, **SRP does not beat renting datacenter RAM for paid capacity**, and it is unsuitable for tight environment loops over the internet. Its credible use is **donated capacity for latency-tolerant, multi-turn workloads**, which is a much narrower claim than the README made before v0.6. The fixes below halved network latency and memory overhead, made the audit cost configurable, and brought the example rates under datacenter prices. They did not change the verdict. A sampled audit policy makes paid capacity possible on paper, at contributor rates of about $0.003 per GiB-hour or less, but only by accepting that some fabricated rewards reach the trainer before a cheater is caught. Whether contributors would supply RAM at such rates is untested.

The CoW arena itself is useful regardless of decentralization: forking 64 branches from a 64 MB snapshot used 98% less memory than 64 copies.

Fixes these measurements pointed to, in rough order of payoff (all five are done):

1. **Persistent connections in the transport.** Done in v0.6: k went from 2 to 1.
2. **A larger listen queue in `NodeServer`.** Done in v0.6: the 1-second stalls under concurrent load are gone.
3. **Release snapshot file contents after pinning.** Done in v0.6: a pinned snapshot costs 1.15× its size instead of 2.1×.
4. **An audit policy that does not replay every rewarded episode.** Done in v0.6: `rewarded_audit_rate` (SRP-003 §2.2). The default stays at 1.0; 0.1 cuts duplicated work to 13–20%.
5. **Calibrate example settlement rates.** Done in v0.6: 0.002 per GB-hour and 0.000001 per step (§4.2, SRP-004 §4).

## 7. Reproducing

```bash
pip install -e ".[crypto,dev,bench]"
```

```bash
python -m benchmarks
```

A full run takes about three minutes and overwrites `benchmarks/results/`. `python -m benchmarks --quick --out <dir>` runs a short version, which is what CI does; its numbers are too noisy to cite.
