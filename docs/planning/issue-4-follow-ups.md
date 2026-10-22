# Planning record: issue 4 follow-ups

- Date: 2026-10-22.
- Status: decisions for the items of issue 4. The blue hat section gives the decisions.
- Input: issue 4 ("Follow-ups deferred after review round 3 and the AC audit") and a code survey of each item.
- Method: a brainstorm, a reverse brainstorm, then six thinking hats.

## Items

| ID | Item | Area |
|---|---|---|
| I1 | The import order sets the `ext:` addresses and the `state_hash`. | Determinism |
| I2 | Each analysis edit runs analysis again from its start band. | Performance |
| I3 | A varargs call prints its integer arguments before its XMM arguments. | Decompiler |
| I4 | L1 call uses are not narrowed to the XMM count of the callee. | Decompiler |
| I5 | The floating return rule follows only one tail call. | Decompiler |
| I6 | The temporary file sweep reads only the local `/proc`. | Robustness |

## Brainstorm

| ID | Idea | For |
|---|---|---|
| B1 | Give each import `ext = 1 + its rank in the ImportId order`. | I1 |
| B2 | Give each import an `ext` from a hash of its ID. | I1 |
| B3 | Keep the list order, and save a map from the list order in the snapshot. | I1 |
| B4 | Migrate a v1 snapshot and v1 journal lines in memory: map each old `ext:` address to its new address. | I1 |
| B5 | Refuse a v1 snapshot, and replay the journal from the start. | I1 |
| B6 | Write the project files again in the v2 format on the first write open. | I1 |
| B7 | Seed only the edit ranges into the pending sets, and retract the facts that follow from them. | I2 |
| B8 | Give more edit kinds a higher start band. | I2 |
| B9 | Read the Tier-0 `fmt` attribute and the format string. Then put the arguments in the order of the conversions. | I3 |
| B10 | Put the XMM count in `Arity`. Remove the unread XMM registers from the call uses. | I4 |
| B11 | Treat a block that ends in a tail jump as a return site with a call event. | I5 |
| B12 | Keep a temporary file younger than a grace time. Read its age through `Fs`. | I6 |
| B13 | Put the boot ID or the host name in each temporary file name. | I6 |

## Reverse brainstorm

How can the fix fail? Each failure has a guard.

| ID | Failure | Guard |
|---|---|---|
| F1 | The migration changes a string that is not an address, for example a note text. | Change only a string that is exactly one `ext:` address of an import. |
| F2 | An old ghidorah opens a v2 project and reads new addresses as old addresses. | The format version goes to 2. An old reader refuses the project file. |
| F3 | A v1 journal line with an `ext:` edit does not replay. | Migrate v1 lines before the replay. Test a v1 rename of an import label. |
| F4 | Two imports get the same `ext:` address. | Number the rows of the ID map. The map has unique keys. |
| F5 | A slow writer on a shared disk loses its temporary file. | The grace time is one hour. A file with no age stays. |
| F6 | Clock skew gives a file a time in the future. | A future time gives age 0. The file stays. |
| F7 | Mutual tail calls make the walk recurse without end. | Keep a set of the functions on the walk. A function on the walk gives no value. |
| F8 | A hostile format string is long or bad. | Read at most 4,096 bytes and 64 arguments. An unknown or positional conversion keeps the old order. |
| F9 | The format string and the registers do not agree. | Use the new order only when the counts agree exactly. |
| F10 | A wrong XMM count removes a live argument. | Narrow only with a known count: no varargs, no open solve and no stack arguments. |
| F11 | The golden changes hide a regression. | Read each changed golden file in `git diff` before the commit. |
| F12 | Incremental analysis gives another result than a full run (AC-097). | Do not start I2 in this change. |

## Six thinking hats

### White hat (facts)

- `import_rows` in `db` gives `ext = index + 1` in the list order. Only three golden files hold an `ext:0x` address.
- `FORMAT_VERSION` is shared by `project.json` and `snapshot.json`. No migration code exists.
- The journal lines have `"v":1`. A v1 line can hold an `ext:` address in an edit.
- Temporary file names hold only the process ID. `Fs` has no time query.
- `ret_value_in` and `float_ret_in` recurse through `call; ret` chains. A tail jump is no event, so a tail chain stops after one step.
- `Arity` holds only the integer count. `Params.float` holds the XMM count.
- Tier-0 prototypes parse a `fmt(printf, n)` attribute. No code reads it.
- A true incremental re-analysis needs about 2,000 to 4,000 lines in most analyzers. Open PR 7 changes the scheduler.

### Red hat (feelings)

- I1, I3 to I6 are local and testable. They feel safe.
- I2 feels too large and too risky for this change.

### Black hat (risks)

- I1 changes the state hash of every project. A bad migration breaks old projects. F1 to F4 apply.
- I4 renames the `vN` names in most functions. F11 applies.
- I6 keeps dead temporary files for one more hour. That costs only disk space.
- I2 conflicts with PR 7 and needs an ADR (design Section 1.3).

### Yellow hat (benefits)

- I1: the analysis result does not depend on the import order. AC-189a covers imports.
- I3: `printf("%d %f", ..)` prints the arguments in C order.
- I4: the SSA has fewer dead values. Names have fewer gaps.
- I5: a tail chain to a floating function gives the correct return type.
- I6: a shared projects directory keeps the temporary files of live writers.

### Green hat (alternatives)

- I1: B1 is canonical and has no collisions. B2 gives sparse addresses that are hard to read. B3 keeps the order problem.
- I1 migration: B4 keeps old projects. B5 loses no data, but a v1 `ext:` edit fails the replay. B6 writes over the append-only journal.
- I6: B12 works across hosts and PID namespaces. B13 cannot tell if a process on another host is alive.

### Blue hat (decisions)

| ID | Decision |
|---|---|
| D1 | I1: B1 and B4. The project format version is 2. A write open of a v1 project writes `project.json` at version 2. |
| D2 | I1: `ac_189a_seed_order` shuffles the imports. |
| D3 | I3: B9 for SysV `printf`-kind callees only. Other calls keep the old order. |
| D4 | I4: B10. This change blesses the goldens. |
| D5 | I5: B11 and the guard of F7. |
| D6 | I6: B12 with `Fs::age` and a grace time of one hour. |
| D7 | I2 stays deferred. It needs an ADR and waits for PR 7. Issue 4 keeps this item open. |

Order of work: I5, I4, I3, I1, I6. Each step has a RED commit, a GREEN commit and, when necessary, a REFACTOR commit. Items I4 and I3 share one RED and one GREEN commit. So do items I1 and I6.
