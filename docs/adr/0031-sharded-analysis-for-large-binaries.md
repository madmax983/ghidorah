# ADR-0031: Sharded analysis for large binaries

Status: Accepted
Date: 2026-10-23
Verified by: AC-092, AC-093, AC-094, AC-120a

## Context

- The engine keeps the whole analysis set and the whole work state in memory. Each publish replaces the whole set with one `ReplaceAnalysis` edit. The snapshot is one JSON file.
- The compact records of the `perf/compact-units` branch cut the memory for each code unit. They give a constant factor only. The memory still grows with the size of the binary.
- Some steps read the whole set: the premise walk of the why-records, the noreturn propagation and the gap components. The engine uses one thread.

Measurements in Docker on Linux with a 16 GB limit:

| Binary | Code units | Steps | Time | Peak RSS | Snapshot |
|---|---|---|---|---|---|
| libsystemd.so.0 | 153,111 | 1.8 M | 2.2 s | 70 MB | 48 MB |
| Godot 4.7.2, default load | part | 100.8 M | 183 s | 5.7 GB | 4.7 GB |
| Godot 4.7.2, full analysis | 17,612,335 | 458.5 M | 593 s | 6.3 GB | 5.3 GB |

- The heap of libsystemd.so.0 peaks at 452 bytes for each code unit. Godot peaks at about 360 bytes of RSS for each code unit.
- An executable of 1 GB holds about 250 M instructions. At 400 bytes for each unit, a full analysis then needs about 100 GB of memory and a snapshot of about 75 GB.

## Decision

The work goes in four stages. Each stage is one pull request with its own measurements.

### Stage 2: shards of the analysis set

- A shard is a fixed range of RAM offsets. The size is 4 MiB.
- Each analysis fact belongs to the shard of its address. The address of a reference is its `from` address. The address of a function is its entry. The facts at an address outside RAM go in one shard after the RAM shards.
- Each shard has its own tables and its own why store. The analysis set is a list of shards in address order. A set keeps each shard behind an `Arc`.
- `ReplaceAnalysis` stays the one edit of a publish. A publish builds the shards again and keeps the old `Arc` of each shard with the same facts. So the new set shares each shard with no change, and a commit compares the other shards only. AC-093 does not change.
- A read of one key goes to the shard of the key. A read of the owner of an address also asks each shard with a function body outside the shard. A read of the references to an address asks each shard in address order.
- The snapshot becomes format version 3. `snapshot.json` names one file for each shard: the index and the SHA-256 of its JCS text. A shard keeps its hash, so a snapshot writes the changed shards only. Each shard file uses the sequence of AC-120a. The snapshot file goes last, and the old shard files go after it.
- A reader of format version 2 puts each fact of the one layer in the shard of its key.

### Stage 3: the work state outside memory

- The engine keeps a summary of each function in memory: the entry, the extents, the callees, the noreturn flag and the exits. A summary takes about 100 bytes.
- The work state of a cold shard goes to the project directory through the `Fs` seam. A cache of loaded shards with a fixed size bounds the memory.
- `ghidorah-analysis` stays a pure core crate. It reads and writes shard state through a trait. `ghidorah-tools` gives the implementation.

### Stage 4: analysis in the order of the queries

- A read of an address in a shard with no analysis raises the priority of that shard. The read runs the analysis of the shard in its own fuel budget.
- `analysis_run` continues the other shards in address order. Replies keep `partial: true` until the analysis is complete.
- This stage needs an amendment of ADR-0016.

### Stage 5: parallel workers

- The disassembly and the lift of each function run on scoped threads. The engine merges the results in address order.
- A property test checks that the number of workers does not change the facts, as AC-092 does for the fuel slices.

## Rules that change

- Invariant 6 of design Section 3.11: a why-record keeps no creation order. The rule becomes "the premise graph has no cycle".
- AC-092, AC-093, AC-094 and AC-120a.
- ADR-0016: one `ReplaceAnalysis` edit for each publish.
- The snapshot format and its migration.

## Decisions of the owner

1. The shard size is 4 MiB.
2. The premise walk of the why-records stays global (option A). One walk over the compact records of all shards cuts the premises that close a cycle. So the facts and the premises do not change.
3. The default `max_steps` of `binary_load` stays at 100 M. An agent continues a large binary with `analysis_run`.
4. A why-record keeps no creation order. With a global counter, one new record changes the order of each later record in all shards. Then each publish changes all shards. The check of invariant 6 finds cycles with a walk of the premise graph.

The owner chose decision 4 over option B after a measurement on 2026-10-23. A walk in each shard must cut each premise in a later shard. A simulation of libsystemd.so.0 with 64 KiB shards cut 0.8% of the premises. Then 437 of 2,173 functions and 581 of 4,132 strings had no premise.

## Alternatives

- A database library, for example SQLite. Rejected: the build takes no third-party crate.
- Memory-mapped files. Rejected: they need `unsafe` outside `ghidorah-oracle` (ADR-0025).
- Compact records only, with a higher unit cap. Rejected: the memory still grows with the binary.

## Consequences

- The memory of an analysis depends on the cache size and the summaries, not on the size of the binary.
- A snapshot write and a publish cost time for the changed shards only.
- The format change needs a migration test with each snapshot of format version 2 in the fixtures.
