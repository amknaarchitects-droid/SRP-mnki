# SRP Economics and Latency Analysis

Status: v0.6 analysis of the v0.5 reference implementation. Written 2026-11-15.

This document asks one question and answers it with measured numbers where we have them, cited numbers where we do not, and clearly labelled assumptions everywhere else.

## 1. The question

**When does running RL environments in contributors' spare RAM beat renting the same RAM in a datacenter?**

The decentralized design has three costs a datacenter does not: network round trips between the trainer and the contributor, duplicated work for verification (replay audits), and moving snapshots to home connections. It has one possible advantage: capacity that is cheaper than rented RAM, or free.

Copy-on-Write (CoW) sharing is not an advantage of decentralization. It works just as well inside one datacenter, and it lowers the cost of the alternative SRP is competing with.

## 2. Measured inputs

All measurements come from `python -m benchmarks` (full run). Raw data and the summary table are in [`benchmarks/results/`](../benchmarks/results/RESULTS.md).

| | |
|---|---|
| Library commit | `1fd35e50f9bc` |
| Machine | AMD Ryzen 5 5600H laptop, 12 logical CPUs |
| OS | Linux 6.18 under WSL2 (3.5 GB RAM given to the VM) |
| Python | CPython 3.14.4, `cryptography` installed |

These are the bundled simulated environments on a laptop. They describe this reference implementation, not production RL environments.

### 2.1 Step latency

Time per environment step with audits and canaries off ([`env_step_latency.json`](../benchmarks/results/env_step_latency.json)).

| Suite | Node step p50 | Node step p99 | Through coordinator p50 |
|---|---:|---:|---:|
| `srp-env-math` (tactic checker) | 0.16 ms | 0.31 ms | 0.46 ms |
| `srp-env-web` (DOM state machine) | 0.15 ms | 0.31 ms | 0.35 ms |
| `srp-env-spatial` (CAD verifier) | 0.24 ms | 0.42 ms | 0.45 ms |
| `srp-env-code` (sandboxed tests) | 44 ms | 200 ms | 35 ms |

Forking a branch takes 0.05–0.15 ms. Three of the four suites take well under a millisecond per step. The code suite is slower because each step starts an isolated sandbox process.

### 2.2 Network cost

The coordinator talks to a real `NodeServer` over TCP through a delay proxy that adds a configurable round-trip time (RTT) ([`network_simulation.json`](../benchmarks/results/network_simulation.json)). TLS was off; TLS would add more round trips per call.

`srp-env-web`, one episode at a time:

| RTT | Step p50 | Steps/s | vs. local |
|---:|---:|---:|---:|
| 0 ms (loopback) | 2.5 ms | 303 | 100% |
| 5 ms | 14 ms | 54 | 18% |
| 20 ms | 45 ms | 17 | 5.5% |
| 50 ms | 105 ms | 7.1 | 2.4% |
| 100 ms | 205 ms | 3.7 | 1.2% |
| 200 ms | 406 ms | 1.8 | 0.6% |

Findings:

- **Every call costs about two round trips.** Added latency is 2.0–2.1 × RTT at every setting. SRP's HTTP transport opens a new TCP connection for every command, so each call pays a handshake plus the request. Keeping connections open would halve this.
- **Even at 0 ms RTT the transport costs about 2 ms per call**, versus 0.35 ms in-process: signing, verifying, JSON and a TCP connection.
- **Concurrency recovers throughput, not latency.** With 16 episodes in flight, throughput at 50 ms RTT rose from 7 to 103 steps/s, but each step still took 111 ms.
- **The transport stalls under concurrent load.** With 16 concurrent episodes and no added latency, p95 step time jumped to about 1 second. This matches TCP connection retries when the server's listen queue (Python's default of 5) is full. It is a fixable implementation limit.
- **Bandwidth is not the bottleneck.** A step sends about 0.8–0.9 KB and receives 1.2–1.6 KB.

### 2.3 Memory saved by Copy-on-Write

A 64 MB snapshot made of distinct pages, with N branches that each write 16 KB, measured by the operating system's resident set size (RSS) in a fresh process ([`cow_memory.json`](../benchmarks/results/cow_memory.json)).

| Branches | N full copies | Arena accounting | OS-level RSS | Saved (OS-level) |
|---:|---:|---:|---:|---:|
| 1 | 64 MB | 64 MB | 135 MB | −111% |
| 4 | 256 MB | 64 MB | 138 MB | 46% |
| 16 | 1,024 MB | 64 MB | 138 MB | 87% |
| 64 | 4,096 MB | 65 MB | 138 MB | 97% |

Findings:

- **Sharing works.** Branches cost almost nothing beyond their changed pages, so the savings figure grows with the branch count.
- **The arena under-reports its own memory by about half.** A pinned snapshot costs 2.1× its size in RSS, because the node keeps the original manifest (with the full file contents) alongside the page store. This is fixable, and until it is fixed every capacity figure in the arena's own accounting is optimistic.
- **The per-branch RSS figure is below measurement resolution here.** The allocator reuses memory freed during pinning, so treat "about zero per branch" as "small", not as zero.

### 2.4 Replay audit overhead

The same episodes at different audit settings ([`replay_audit_overhead.json`](../benchmarks/results/replay_audit_overhead.json)). "Duplicated work" is auditor steps divided by provider steps.

| Audit setting | `web` duplicated | `web` wall-clock | `math` duplicated | `code` duplicated |
|---|---:|---:|---:|---:|
| No audits | 0% | +0% | 0% | 0% |
| 5% sampling only | 6% | −1% | 6% | 0% |
| 25% sampling only | 28% | +13% | 25% | 20% |
| **Default** (5% + every rewarded step) | **100%** | **+55%** | **100%** | **100%** |
| Audit everything | 100% | +61% | 100% | 100% |

Finding: **the default policy duplicates all the work on these workloads.** The coordinator always audits rewarded, terminal and timed-out steps, and audits are incremental, so auditing the last step of an episode replays the whole episode. Every bundled episode ends in a reward, so the default amounts to auditing everything. Sampling-only audits cost about what their rate says.

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

For a step of compute time `T_step`, SRP adds about `k × RTT`, where `k ≈ 2` in v0.5 (measured) and could be 1 with persistent connections.

What matters to a trainer is not the step alone but the whole turn. In a multi-turn rollout, each turn is model generation (`T_gen`) followed by an environment step. The fraction of rollout time lost to the network is about:

```
overhead ≈ k × RTT / (T_gen + T_step + k × RTT)
```

`T_gen` depends on the model and the task; it is an **assumption** here, not a measurement.

| `T_gen` per turn (assumed) | RTT 20 ms, k=2 | RTT 50 ms, k=2 | RTT 200 ms, k=2 | RTT 50 ms, k=1 |
|---:|---:|---:|---:|---:|
| 0.1 s | 29% | 50% | 80% | 33% |
| 1 s | 4% | 9% | 29% | 5% |
| 10 s | 0.4% | 1% | 4% | 0.5% |

When the environment loop is tight (short generations, sub-millisecond steps), the network dominates and SRP loses badly. When each turn involves seconds of generation, a contributor even 50 ms away adds only a few percent.

### 4.2 Cost

Let `c_dc` be the datacenter price per GiB-hour, `p` the price paid to a contributor per GiB-hour of environment RAM, and `a` the fraction of work duplicated by audits. The auditor runs on trusted (datacenter) hardware, so audits cost roughly `a × c_dc`. Ignoring coordination and network costs, SRP is cheaper only when:

```
p + a × c_dc < c_dc      →      p < (1 − a) × c_dc
```

| Audit duplication `a` | Max contributor price, at c_dc = $0.0036 | at c_dc = $0.0083 |
|---:|---:|---:|
| 100% (v0.5 default on these workloads) | $0 | $0 |
| 25% | $0.0027 | $0.0062 |
| 5% | $0.0034 | $0.0079 |

This is a rough bound: audits duplicate compute rather than the full RAM-hours, so the true audit cost may be lower. Even so, it sets the scale. For comparison, **the demo ledger pays `0.05` per GB-hour, which is 6–18 times the entire datacenter price**. That rate is a placeholder, not a market price.

### 4.3 Snapshot distribution

A contributor has to download each snapshot before serving it. At 100 Mbit/s, a 2 GB environment snapshot takes about 2.7 minutes; at 25 Mbit/s, about 11 minutes. With contributors joining and leaving, that time is paid repeatedly. It is negligible for long-lived snapshots and significant for short-lived or frequently updated ones.

## 5. Where SRP wins and where it loses

**SRP loses:**

- **Tight loops with sub-millisecond steps.** At 20 ms RTT, one episode at a time runs at 5.5% of local throughput; at 100 ms, 1.2%.
- **Paid capacity at current prices.** A contributor would have to accept less than about $0.003–0.008 per GiB-hour, and less still once audits are counted. With the v0.5 default audit policy, which duplicates all work on rewarded episodes, there is no positive price at which it is cheaper.
- **As an answer to the "RAM wall".** The 97% CoW saving measured here is available inside any datacenter too, so it shrinks the problem for everyone rather than favouring decentralization.
- **Frequently changing snapshots on slow home links.**

**SRP can win:**

- **Donated capacity.** Under the open-science karma model, `p ≈ 0`. An academic or non-profit group without a datacenter budget can trade latency and audit overhead for free RAM.
- **Latency-tolerant multi-turn workloads.** When each turn involves a second or more of model generation and many episodes run in parallel, a contributor in the same region adds a few percent to rollout time.
- **Long-running steps.** Compiling and testing code, running real containers or browsers: steps of hundreds of milliseconds or more make the round trip a small fraction.

## 6. Verdict for v0.5

As implemented today, **SRP does not beat renting datacenter RAM for paid capacity**, and it is unsuitable for tight environment loops over the internet. Its credible use is **donated capacity for latency-tolerant, multi-turn workloads**, which is a much narrower claim than the README made before v0.6.

The CoW arena itself is useful regardless of decentralization: forking 64 branches from a 64 MB snapshot used 97% less memory than 64 copies.

Fixes these measurements point to, in rough order of payoff:

1. **Persistent connections in the transport.** Halves network latency per call (k from 2 to 1).
2. **A larger listen queue in `NodeServer`.** Removes the 1-second stalls under concurrent load.
3. **Release snapshot file contents after pinning.** Halves the RSS cost of a pinned snapshot and makes arena accounting honest.
4. **An audit policy that does not replay every rewarded episode.** For example, sample rewarded episodes at a configurable rate. This is a security trade-off and needs a spec change in SRP-003.
5. **Calibrate example settlement rates** to the datacenter price range above.

## 7. Reproducing

```bash
pip install -e ".[crypto,dev,bench]"
```

```bash
python -m benchmarks
```

A full run takes about three minutes and overwrites `benchmarks/results/`. `python -m benchmarks --quick --out <dir>` runs a short version, which is what CI does; its numbers are too noisy to cite.
