# ADR-0031: Sharded analysis for large binaries

Status: Proposed
Date: 2026-10-23
Verified by: none yet

## Context

- The engine keeps the whole analysis set and the whole work state in memory. Each publish replaces the whole set with one `ReplaceAnalysis` edit. The snapshot is one JSON file.
- The compact records of the `perf/compact-units` branch cut the memory for each code unit. They give a constant factor only. The memory still grows with the size of the binary.
- Some steps read the whole set: the creation order of the why-records, the noreturn propagation and the gap components. The engine uses one thread.

Measurements in Docker on Linux with a 16 GB limit:

| Binary | Code units | Steps | Time | Peak RSS | Snapshot |
|---|---|---|---|---|---|
| libsystemd.so.0 | 153,111 | 1.8 M | 2.2 s | 70 MB | 48 MB |
| Godot 4.7.2, default load | part | 100.8 M | 183 s | 5.7 GB | 4.7 GB |
| Godot 4.7.2, full analysis | 17,612,335 | 458.5 M | 593 s | 6.3 GB | 5.3 GB |

- The heap of libsystemd.so.0 peaks at 452 bytes for each code unit. Godot peaks at about 360 bytes of RSS for each code unit.
- An executable of 1 GB holds about 250 M instructions. At 400 bytes for each unit, a full analysis then needs about 100 GB of memory and a snapshot of about 75 GB.

## Decision (proposed)

The work goes in four stages. Each stage is one pull request with its own measurements.

### Stage 2: shards of the analysis set

- A shard is a fixed range of RAM offsets. The proposed size is 4 MiB.
- Each analysis fact belongs to the shard of its address. The address of a reference is its `from` address. The address of a function is its entry.
- Each shard has its own tables and its own why store. The analysis set is a list of shards in address order.
- `Edit::ReplaceShard { shard, set }` replaces one shard. A publish commits only the shards that change. AC-093 then applies to each shard.
- The snapshot becomes format version 3: a manifest and one file for each shard. A snapshot writes only the changed shards. Each shard file uses the sequence of AC-120a. The manifest goes last.
- A reader of format version 2 puts the whole set in shard 0.

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

- Invariant 6 of design Section 3.11 and ADR-0023: the creation order of the why-records.
- AC-092, AC-093, AC-094 and AC-120a.
- ADR-0016: one `ReplaceAnalysis` edit for each publish.
- The snapshot format and its migration.

## Open questions for the owner

1. The shard size. A small shard writes less for each change. A large shard has fewer premises that cross a shard edge.
2. The creation order of a premise in another shard. Option A keeps one global walk over compact records, at about 40 bytes for each record. Option B orders each shard by itself and removes a premise that closes a cycle across shards. Option B changes the facts of some binaries.
3. The default `max_steps` of `binary_load`. A full analysis of Godot takes 458.5 M steps, and the default is 100 M.

## Alternatives

- A database library, for example SQLite. Rejected: the build takes no third-party crate.
- Memory-mapped files. Rejected: they need `unsafe` outside `ghidorah-oracle` (ADR-0025).
- Compact records only, with a higher unit cap. Rejected: the memory still grows with the binary.

## Consequences

- The memory of an analysis depends on the cache size and the summaries, not on the size of the binary.
- A snapshot write and a publish cost time for the changed shards only.
- The format change needs a migration test with each snapshot of format version 2 in the fixtures.
