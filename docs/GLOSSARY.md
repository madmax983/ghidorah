# Glossary

This glossary lists the approved technical words of the ghidorah docs, comments and agent text.
The STE checker (`testkit::ste`, ADR-0019) reads the verb table. A sentence that starts with a word of that table is an instruction.
Each word has one meaning. Use the word only with that meaning.

## Technical verbs

| Word | Meaning |
|---|---|
| add | Put a new item into a list, a file or a set. |
| apply | Use a change, a patch or a rule on an object. |
| bless | Write golden files again from the current output. |
| build | Compile code, or make a data structure from parts. |
| call | Start a tool or a function with arguments. |
| check | Compare a value with a rule. Report the result. |
| commit | Record a change in git, or close a transaction in the program database. |
| compare | Find the differences between two values. |
| copy | Make a second instance of a file or a value. |
| decode | Change instruction bytes into an instruction record. |
| delete | Remove a file or a record. |
| demangle | Change a symbol name from its compiler form into its source form. |
| disassemble | Decode a range of bytes into instruction text. |
| do | Perform an action. |
| download | Copy a file from a network host. |
| edit | Change the text of a file or the value of a fact. |
| extract | Copy one file out of an archive. |
| fetch | Get objects from a remote git repository. |
| find | Give the location of an item. |
| fuzz | Run a target with many random or changed inputs. |
| get | Read a value. |
| give | Return a value to the caller. |
| install | Put a tool on the host. |
| keep | Not change or not remove an item. |
| lift | Change a decoded instruction into IR operations. |
| list | Give the items of a set in order. |
| load | Read a binary into a program database. |
| make | Create an object. |
| make sure | Check a result. Correct it when it is wrong. |
| merge | Join two branches or two files into one. |
| parse | Read text or bytes into a typed structure. |
| print | Write text to an output stream. |
| put | Move an item to a location. |
| read | Get the contents of a file or a value. |
| rebase | Move a git branch to a new base commit. |
| record | Write a fact or a result for later use. |
| remove | Take an item out of a list, a file or a set. |
| replace | Put a new item in the location of an old item. |
| report | Give a result as output. |
| run | Start a program, a test or a command. |
| scan | Look for a pattern in all items, in order. |
| search | Look for items that match a query. |
| set | Give a value to a variable, a field or an option. |
| show | Give information as output. |
| skip | Not process an item. |
| sort | Put items in a fixed order. |
| split | Divide one item into two or more items. |
| start | Begin a process or an action. |
| stop | End a process or an action. |
| tell | Give information to a person or a program. |
| test | Compare the result of code with the expected result. |
| undo | Reverse the last change. |
| update | Change a value to its new state. |
| use | Operate a tool, a value or a rule for a purpose. |
| verify | Prove a property with Verus. |
| wait | Stop until an event occurs. |
| write | Put data into a file or a stream. |

## Technical nouns

| Word | Meaning |
|---|---|
| AC | An acceptance criterion in design Section 15. |
| ADR | An architecture decision record in `docs/adr/`. |
| agent | An AI program that calls ghidorah tools. |
| basic block | A run of instructions with one entry and one exit. |
| binary | An executable file or a library file that ghidorah reads. |
| crate | One Rust package of the workspace. |
| CFG | The control flow graph of a function. |
| envelope | The JSON object that holds the result of one tool call. |
| fact | One recorded property of the program, with its source and rank. |
| fixture | A checked-in test input, for example a small ELF file. |
| fuel | A count of work steps that bounds a computation. |
| gate | A check that must pass before a merge. |
| golden file | A checked-in expected output. |
| IR | The intermediate representation of lifted code. |
| kernel | A small function with a Verus proof. |
| oracle | A trusted external program that gives expected results. |
| RVA | A relative virtual address: an offset from the image base. |
| SSA | Static single assignment form. |
| STE | ASD-STE100 Simplified Technical English. |
| stub | A small code sequence that jumps to an imported function. |
| thunk | A small function that only jumps or calls to another function. |
| tier 1 | The tests that plain `cargo test` runs. |
| tier 2 | The tests with `#[ignore = "tier2"]`, plus the long CI jobs. |
| VA | A virtual address in the address space of the program. |
| WP | A work package of design Section 14.3. |
| xref | A cross-reference from one address to another address. |
