# CLAUDE.md

## The project

`mykmyk` automates a blackbox pentest: a YAML workflow chains scanning tools (nmap, httpx, nuclei,
ffuf, nc, smb, sslscan, rdp) so each one's findings feed the next. Output is an HTML report plus the
raw tool output on disk.

It runs against real networks, often as root. Two consequences shape every decision here:

- **A missing result must never read as a clean result.** A host that failed to scan and a host with
  nothing open look identical unless the code goes out of its way to distinguish them. When in
  doubt, make the gap visible.
- **The working directory is the pentest.** `config.yml`, `hosts`, `status.db`, `mykmyk.log`, the
  report and every `./<target>/` folder are relative to wherever the user ran the command. Commands
  are expected to be run from the pentest folder.

## Layout

- `cmd/cli/cmd/` — cobra commands: `scan`, `status`, `find`, `init`
- `internal/scanner/` — builds executors from config, wires them, runs them, writes the HTML report
- `internal/executor/<tool>/` — one package per tool, all implementing `abstract.Executor`
- `internal/sns/` — in-process pub/sub that connects tasks
- `internal/status/` — `status.db` schema, its writers, and the `status` command's reader
- `internal/scope/` — hosts-file parsing (shared by scan, status and find)
- `internal/binary/` — the single choke point for shelling out to a tool
- `internal/api/` — config structs and `TaskType` constants

Build with `make -C cmd/cli build` (static, on Linux) or `build-native` for local iteration. CGO is
required — go-sqlite3 and grdp — so cross-compiling needs a C cross-compiler.

## How a scan flows

`scanner.Scan` builds one executor per task, starts every one as a goroutine, and lets the pub/sub
decide the order. There is no scheduler and no dependency graph walk.

- A task's `source:` makes it a **consumer** of another task's topic. `waitFor:` is a separate
  barrier, not a data connection.
- The `scope` filesystem task seeds everything by emitting one `model.Message` per hosts-file line.
- `nmap` fans out: one scan result becomes **one message per live host**, which is what lets an ARP
  sweep gate the expensive port scans. `httpx` re-emits URLs. Everything else is a leaf.
- `sns.SendMessage` blocks until *every* consumer accepts. A slow consumer therefore stalls its
  producer, which is why `queueSize` defaults to 256 rather than to the concurrency.

To add a tool: new package implementing `abstract.Executor`, a `TaskType` in `internal/api/types.go`,
an entry in `executor.Registered`.

## Invariants worth knowing before you change anything

**The cache is just the output file.** `./<target>/<taskName>` (`.xml` for nmap) existing *is* the
cache hit. There is no TTL and the arguments are not part of the key — editing a task's args and
re-running in the same folder silently returns the old result. Only nmap validates what it reads
back (`Stats.Finished.Exit == "success"`). Don't add caching cleverness without being asked, but
don't assume a cached result is fresh either.

**Record status above the cache check.** Every executor's `scanTarget` must record a unit *before*
it can return from cache, or a re-run with `useCache: true` writes nothing and `mykmyk status` comes
up empty. Cache hits get `MarkCached`, not silence.

**Never `return err` from a drain loop.** In `for r := range resultCh`, one target's failure must be
recorded (`status.MarkTargetFailed`) and skipped with `continue`. Returning ends the whole task, and
the historical bug was returning the *outer* `err` — nil at that point — so a failure reported
success. `nmap.Run` is the reference implementation.

**A unit of work is not always a host.** `Status.TaskTarget` is a host for most tasks, but
`host:port` for nc and a URL for ffuf and sslscan. That is why a task can read `3/5` for one host,
and why target-scoped helpers exist alongside unit-scoped ones.

**Scope entries may not overlap.** `scope.Load` rejects overlapping CIDRs because results are stored
per IP and would collide — and because non-overlap is what makes "which network did this host come
from" answerable at all.

**`Message.Interface` must survive.** Segments behind a trunk port need the right egress interface;
dropping it silently routes the scan out of the wrong VLAN.

**`status.db` is per-run.** `mykmyk scan` drops and recreates both tables. It is WAL-mode so
`mykmyk status` can read while a scan writes — that mid-scan view is the point of the command.

## Conventions

- **Logging** is stdlib `log` to `mykmyk.log`. No levels, no logger injection. Prefix messages with
  the package name: `log.Printf("nmap: %s done for %s in %s", ...)`.
- **Console output** is `fmt.Printf` straight from executor goroutines and is deliberately separate
  from the log. It is unsynchronised; don't build anything that depends on its ordering.
- **`log.Fatal` is banned in library code.** It kills the run, discards every other task's results,
  and prints nothing to the terminal. Return an error or log and continue.
- **Shell out only through `internal/binary.Run`** — it logs the command line and turns a non-zero
  exit into an error. Don't call `exec.Command` directly.
- **Tests** are table-driven with `cmp.Diff` for comparisons. `internal/status` tests run against a
  real sqlite DB in a temp working directory.
- Comments explain *why*, especially where the code looks wrong but isn't. Match that; don't add
  narration of what the next line does.

## Verifying a change

`go build ./... && go test ./... && gofmt -l ./cmd ./internal`

Necessary but rarely sufficient — most of this code only misbehaves against a real network. An
end-to-end run needs no root and no external network: a hosts file of `127.0.0.0/30` and a config
whose discovery task uses `-sn -Pn` feeding an `-sT` port scan, then `mykmyk scan && mykmyk status
-t hosts`. The `-Pn` matters: on loopback every address answers with reason `localhost-response`,
which `isHostUsable` correctly filters out, so plain `-sn` yields zero hosts downstream.

Exercise these deliberately, because each has been broken before: a **second run in the same folder**
(everything should read `(cached)`, not vanish); a task with a **bogus tool flag** (should read
`FAILED`, while the other tasks still finish and still produce the report); and **`status` while a
scan is running**.

---

# Behavioral guidelines

Guidelines to reduce common LLM coding mistakes.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant
clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to
overcomplication, and clarifying questions come before implementation rather than after mistakes.
