# vmfuzz

Differential fuzzer for the Quake3e QVM JIT: builds short random QVM
programs, executes each under both the bytecode interpreter and the
JIT compiler for the host architecture, and reports any divergence
in the return value.

The purpose is to catch JIT correctness bugs — cases where the
interpreter and JIT produce different results for the same bytecode.
A clean run is strong evidence that the JIT is sound across the op
classes the generator exercises.

## Building

`vmfuzz` is an optional build target. Enable it at configure time:

```sh
cd build/
cmake -DBUILD_VMFUZZ=ON ..
cmake --build . --target vmfuzz
```

This pulls in the engine's VM sources (`vm.c`, `vm_interpreted.c`,
and the active arch's `vm_*.c`), plus `q_shared.c`, `q_math.c`,
`puff.c`, and the engine-API stubs supplied by `vmfuzz.c` itself.
No external dependencies beyond the engine's own.

Supported host architectures: same as the engine — ppc64le/ppc64,
aarch64, x86_64, x86, armv7l. The right backend is selected
automatically by `cmake`.

## Running

```sh
./vmfuzz [base_seed] [iterations]
```

- `base_seed` (default: time-based): RNG seed of the first iteration.
  Subsequent iterations use `base_seed + 1`, `base_seed + 2`, …, so
  a failing iteration is always reproducible by re-running with the
  same `base_seed` and a focused range.
- `iterations` (default: 1000): how many programs to generate and
  diff.

Exit code is `0` if every iteration agreed between interp and JIT,
`1` if any divergence was found, `2` on internal/setup error.

Example:

```sh
$ ./vmfuzz 1 50000
vmfuzz: seed=1 iter=50000
[1] ok  result=16908286
[101] ok  result=0
...
vmfuzz: done — 0/50000 failing
```

## Unit mode

Pass `--unit` to run a small set of hand-crafted regression
programs instead of fuzzing. These programs target specific
known-tricky shapes (taken/not-taken conditional branches,
multi-function CALL/ARG with self-recursion, plain linear control
flow) and print interp/JIT results side by side with the expected
value:

```sh
$ ./vmfuzz --unit
unit LTI-taken:        interp=100  jit=100  expected=100
unit LTI-fallthrough:  interp=1099 jit=1099 expected=1099
unit linear:           interp=107  jit=107  expected=107
unit CALL/ARG:         interp=147  jit=147  expected=147
```

Useful as a sanity check after modifying the JIT — much faster than
a full fuzz run and deterministic.

## Output on divergence

When interp and JIT disagree, `vmfuzz` writes the failing program
to disk and prints the op stream to stderr:

```
[1886] DIVERGENCE  interp=4095 (0xfff)  jit=0 (0x0)
    0  OP_ENTER    48 (0x30)
    1  OP_CONST    -65536 (0xffff0000)
    2  OP_CONST    -2 (0xfffffffe)
    3  OP_BXOR
    ...
```

Two files are saved per failure:

- `/tmp/vmfuzz-fail-<seed>.qvm` — raw bytecode of the failing
  program (replayable as-is).
- `/tmp/vmfuzz-fail-<seed>.log` — human-readable op stream.

To re-run a single failing seed:

```sh
./vmfuzz <seed> 1
```

To clear old reproducer files between runs:

```sh
rm -f /tmp/vmfuzz-fail-*
```

## Environment knobs

| Variable | Default | Effect |
|---|---|---|
| `VMFUZZ_RTCHECKS` | `15` | Overrides the engine's `vm_rtChecks` cvar.  `0` disables all JIT runtime checks (pStack overflow, opStack overflow, jump-range, data-mask); useful when bisecting whether a setup issue is in the checks themselves. |
| `VMFUZZ_NOBRANCH` | (unset) | Set to `1` to suppress all conditional-branch islands (integer and float compares).  Lets you fuzz the linear-only op subset in isolation when a branch-class bug is outstanding. |
| `VMFUZZ_DEBUG` | (unset) | Set to `1` to dump `vm_t` setup values, the JIT-emitted instruction stream of every program, and the JIT return value.  Verbose — use with a small iteration count or a single seed. |

## What it covers

Each generated program is structured as:

```
ENTER <frame>
CONST <accumulator>
{ random body "island" } * k
LEAVE <frame>
PUSH; LEAVE <frame>      ; end-of-proc marker required by the validator
```

Body islands are drawn at random from:

- **Arithmetic**: ADD, SUB, MULI, MULU, DIVI, DIVU, MODI, MODU
  (divisor guaranteed non-zero)
- **Bitwise**: BAND, BOR, BXOR
- **Shifts**: LSH, RSHI, RSHU (count 0–31)
- **Unary**: NEGI, BCOM, SEX8, SEX16, NEGF
- **Conversions**: CVIF, CVFI
- **Float arithmetic**: ADDF, SUBF, MULF, DIVF
- **Conditional branches**: integer (EQ, NE, LTI, LEI, GTI, GEI,
  LTU, LEU, GTU, GEU) and float (EQF, NEF, LTF, LEF, GTF, GEF),
  with a forward target inside the same proc
- **OP_JUMP** (unconditional indirect jump forward)
- **Safe LOAD/STORE** through a constant (`OP_LOCAL`-relative)
  address — byte, halfword, and word widths
- **Dynamic-address LOAD/STORE** computed via arithmetic — same
  three widths.  Exercises the JIT's runtime data-mask path.
- **OP_BLOCK_COPY** between constant src/dst addresses
- **OP_CALL** to a self-recursive helper `F2`:
  `int F2(int n) { return n > 0 ? F2(n-1) + 1 : 100; }`.
  Exercises call-stack recursion, OP_ARG, OP_RET, intermediate
  OP_LEAVE, and the GTI base-case branch inside the callee.
- **TRAP_SQRT** syscall — the JIT inlines this as an `fsqrts`
  without entering the syscall handler; the interp path goes
  through the engine's `vm_t.systemCall` callback (stubbed in
  `vmfuzz.c` to compute `sqrtf` in C).  Both backends must agree
  bit-for-bit.

Operand values for arithmetic and bitwise ops are sampled from a
table biased toward boundary cases (powers of two, ±2^k boundaries,
0x8000_0000, 0xFFFF_FFFF, ±INT16_MIN, smallest denormal, etc.) to
increase the chance of hitting immediate-encoding and
sign-extension bugs in the JIT.

## What it does not cover

- **System calls** other than `TRAP_SQRT`.  Other engine syscalls
  (memset, memcpy, sin, cos, atan2, …) go through `vm_t.systemCall`
  but aren't generated by the fuzzer because the interp/JIT contract
  for them is plumbing-level and depends on engine state the
  standalone fuzzer doesn't maintain.
- **Multi-distinct-function call graphs** beyond F1 → F2 (self-
  recursive).  Single-callee plus recursion covers depth; multiple
  distinct callees would add little new code-path coverage.
- **`OP_POP`**.  Only valid in the JIT after a syscall-return slot
  with `TYPE_RX` and negative offset; synthetic patterns trigger a
  `dec_opstack_discard` assertion.
- **`OP_UNDEF` / `OP_BREAK`** — would trap at runtime.
- **`OP_IGNORE`** — peephole-emitted by the engine optimizer, not
  by q3lcc; not interesting to fuzz directly.

## Source layout

A single file: `code/tools/vmfuzz/vmfuzz.c`.  Top-down structure:

1. **Engine-API stubs** — `Com_*`, `Z_*`, `Hunk_*`, `Cvar_*`,
   `Cmd_*`, `FS_*`, `Sys_*`, and a `systemCall` handler.  Provide
   the minimum surface the linked engine sources need.
2. **Random program generator** — `build_program()` and the
   per-island helpers.
3. **Bytecode encoder** — `encode_program()` serialises a
   `fuzz_prog_t` into a `vmHeader_t`-prefixed in-memory blob.
4. **VM bring-up** — `run_one()` wraps a `vm_t` around the
   in-memory bytecode and dispatches to either
   `VM_PrepareInterpreter2`/`VM_CallInterpreted2` or
   `VM_Compile`/`VM_CallCompiled`.
5. **`--unit` mode** — hand-crafted regression programs.
6. **`main()`** — arg parsing, RNG seeding, the fuzz loop.

## Extending coverage

To add a new op-class island:

1. Pick a probability slot in the body-island chain in
   `build_program()` (the `r < N` ladder).
2. Emit the QVM ops via `fp_push()` keeping the simulated stack
   depth at 1 entering and leaving the island.
3. If the island uses a forward branch target, record the
   placeholder's index and patch the value once the target is
   known (see the existing branch and call islands as templates).
4. Add a focused regression test to the `--unit` mode if the
   island shape is non-obvious.

Validator constraints to watch for (`vm.c:VM_CheckInstructions`):

- `OP_ENTER` must see opStack=0.
- Conditional-branch (`JUMP`-flagged) targets must have
  `opStack == source.opStack - 8`.
- `OP_ARG` byte offset must be in `[8, pstack-4]` and 4-byte
  aligned.
- `OP_CALL` of a positive target ip must point at an `OP_ENTER`
  and not at ip 0.
- Local-relative addresses in `OP_LOCAL` followed by a load/store
  must be inside the current proc's frame.
