# Tool-call policy (design)

Status: implemented on the `guardrails-policy` branch.

## Why

hax is built as a Unix tool and deliberately ships no per-command approval gate — see the "No
permission prompts" section of [philosophy.md](./philosophy.md). That reasoning holds: an
in-process gate is not a security boundary, and the honest answer for containment is a container
or a VM.

This proposal adds a *restraint* layer for the case philosophy.md leaves open — bounded,
unattended runs where the operator wants the model's reach limited to a known set of commands and
paths. It is deliberately small, off by default, and claims nothing it cannot deliver: it is a
speed bump against accidents and drift, not a sandbox. Isolation against a compromised process
still comes from the operating system.

The design accepts the philosophy.md objection rather than arguing with it, and records the
divergence here so "why does hax have X?" keeps having a written answer.

## Threat model

The decision point sees statement leaders, not shell semantics. `for_each_segment` in
`src/tools/bash_classify.c` is a quote- and escape-aware splitter over `;`, `&&`, `||`, newlines,
and `|`, which means a deny list of commands is defeated by ordinary shell composition:

| Command | deny-list | allow-list |
| --- | --- | --- |
| `echo $(rm -rf /)` | bypasses | denied (`$(…)` is a composition) |
| `` `rm -rf /` `` | bypasses | denied (backtick is a composition) |
| `bash -c 'rm -rf /'` | bypasses | denied unless `bash` is allowed |
| `sudo rm -rf /` | bypasses unless `sudo` is listed | denied |
| `rm -r -f /` | bypasses (flag order) | denied |
| `find . -delete` | bypasses | denied unless `find` is allowed |
| `ls 2>/dev/null` | allowed | allowed |

`command_has_disqualifier` already returns true for command substitution (including inside double
quotes), process substitution, here-documents, background operators, and any redirection other
than stderr to `/dev/null` — exactly the compositions lexical analysis cannot follow.

The consequence shapes the whole design: **an allow list that denies on any composition is a real
restraint; a deny list is a typo-catcher.** Both are offered, but allow-list is the mode worth
using.

## Ask mode

The operator-facing gate is `mode: "ask"`, and it is opt-in: with no `policy` block nothing
prompts. Per-call approval was tried first and rejected — a long session becomes a keystroke
treadmill, and the answer is nearly always yes for work inside the project. The decision that
actually carries information is made once, at launch: **is this folder trusted?**

At startup hax resolves the workspace root (the git worktree root containing the working
directory, else the working directory) and, if it is not already in the trust store, asks:

```
Trust this folder? /home/admin/Projects/hax-guarded
[t] this session   [a] always   [n] no (read-only)
```

The two answers define the mode:

- **Trusted** — tools run without prompting while they stay inside the folder. `bash` is scanned
  for path-shaped words (including `~/`, `..`, redirections, `--flag=path`, and `$HOME`); a word
  that normalizes outside the root escalates to a `y/N` labelled `OUTSIDE THE FOLDER`, and the
  same applies to a `read`/`edit`/`write` path outside it. `bash.dangerous_commands` is the second
  exception: a match asks `DANGEROUS bash: …` with `y/N`, even inside the folder.
- **Untrusted** — read-only. `read` runs only when its path normalizes inside the root,
  `task_wait` runs, and `bash`, `edit` and `write` are denied without prompting. The denial names
  the reason so the model stops retrying and tells the operator to trust the folder.

`[a]` persists the root in `<state>/hax/trust.json`, an auto-managed file kept out of `config.json`
so `/config` writes and hand edits never collide with it. `[t]` lasts for the process. A
non-interactive run (`hax -p`, background dispatch) never prompts and is therefore untrusted unless
the folder is already recorded — the same config, bounded for unattended use.

Dangerous matching considers both the literal statement and its wrapper-stripped form, so `sudo
rm` trips whichever of the two is listed, and a non-interactive run denies rather than confirms.
Containment is a token scan, not a sandbox: it catches explicit paths, and it deliberately does
not try to model commands whose targets are implicit (`git config --global`, a bare `cd`), which
is why trust is still asked for per folder.

### Terminal ownership

The REPL arms the interrupt watcher (`interrupt_arm`) for the whole turn, so during tool dispatch
another thread already owns stdin and is classifying bytes for Esc. Both prompts therefore call
`interrupt_disarm()` before reading and `interrupt_arm()` after; without that handover the two
readers steal each other's keys and every prompt looks like an immediate Esc. Two consequences
follow: prompt text must use `\r\n` because raw mode clears `OPOST`, and the prompt flushes
typed-ahead input before re-arming so leftovers are not read as interrupts.

Keys are decoded rather than taken as raw bytes (`terminal/keyread.c`): a lone Esc (nothing pending
within 30 ms) cancels, while `CSI … u` sequences are mapped to their codepoint so terminals using
the kitty keyboard protocol (kitty, foot, wezterm, Ghostty) work unchanged. Arrows, mouse and focus
sequences are dropped. Enter reprints the options instead of doing nothing silently, and the answer
is echoed. `HAX_APPROVE_DEBUG=1` appends every byte read, as hex, to `<state>/hax/approve.log` for
diagnosing an unfamiliar terminal.

## Configuration

Structured block in `config.json`, read with `config_json_node("policy")` like `catalog.models`.
It is not a registry setting, so it is not editable through `/config`; document it as file-only.
An absent block means the feature is off and behaviour is byte-identical to today.

```json
{
  "policy": {
    "mode": "ask",
    "fail_closed": true,
    "bash": { "dangerous_commands": ["sudo", "rm", "dd", "git reset --hard"] }
  }
}
```

The non-interactive alternative keeps the same block with a static gate:

```json
{
  "policy": {
    "mode": "allow-list",
    "tools": { "allow": ["read", "edit", "write", "bash", "task_wait"] },
    "bash": { "allow_commands": ["ls", "cat", "grep", "rg", "git status", "make"] },
    "paths": { "deny_prefixes": ["/etc", "/usr", "~/.ssh"], "write_only": true }
  }
}
```

`mode` is `off` (default), `ask`, `deny-list`, or `allow-list`. `fail_closed` decides what a
malformed block does: deny everything (true) or behave as off (false). Note that
`config_json_node` does not merge across tiers — a `policy` block in `state.json` wins wholesale
over the one in
`config.json` — and there is no environment override for structured blocks.

## Decision point

There is one core dispatch loop, in `agent_loop.c`, and one place where each call's fate is
decided:

```c
enum agent_loop_tool_action action = AGENT_LOOP_TOOL_RUN;
if (session->n_tools == 0)
    action = AGENT_LOOP_TOOL_REFUSE;
else if (sig == AGENT_LOOP_SIG_ABORT)
    action = AGENT_LOOP_TOOL_SKIP;
else {
    enum policy_verdict verdict = policy_verdict(&session->items[i]);
    if (verdict == POLICY_VERDICT_DENY)
        action = AGENT_LOOP_TOOL_DENY;
    else if (verdict == POLICY_VERDICT_ASK)
        action = AGENT_LOOP_TOOL_ASK;
}
```

Policy is the last branch, so a session with tools disabled keeps refusing and an abort keeps
skipping with interrupted provenance. The loop then hands the action to the frontend hook when one
is installed (`agent.c`), and acts on it directly when none is (`hax -p`); the hook path gains
`DENY` and `ASK`, while the hookless path denies both, because it has no one to ask.

The refusal plumbing already exists and is reused unchanged: `ITEM_ORIGIN_REFUSED` is handled in
`history.c`, `session.c`, and `agent_dispatch.c`, and `agent_tool_result_make` carries the
model-facing text. Only the decision and its reason are new.

Because the check runs on the raw model-issued item before `preprocess_args` rewrites a call
(`agent_tool.c`), an argument rewrite cannot smuggle a command past the gate.

## Module API

Four functions, no new dependency.

```c
typedef int (*bash_statement_fn)(const char *statement, size_t length, void *user_data);

/* Split a command into statements the way the exploration heuristic does. */
void bash_for_each_statement(const char *command, bash_statement_fn fn, void *user);

/* Nonzero when the command composes or substitutes in ways lexical analysis cannot follow. */
int bash_command_has_composition(const char *command);

/* Nonzero when the call is denied by the configured policy. */
int policy_denies(const struct item *call);

/* Allocated model-facing reason for a denied call, or NULL when it is not denied. */
char *policy_deny_reason(const struct item *call);

/* RUN, ASK, or DENY for this call. */
enum policy_verdict policy_verdict(const struct item *call);

/* Nonzero when the call matches bash.dangerous_commands and needs a second confirmation. */
int policy_is_dangerous(const struct item *call);

/* Allocated prompt detail: the command line, the path, or the raw arguments. */
char *policy_call_detail(const struct item *call);

/* Folder trust: the ask-mode gate. A non-interactive frontend never gains it. */
int policy_trust_required(void);
void policy_set_trusted(int trusted);
char *policy_workspace_root(void);
void policy_set_workspace_root(const char *root);
```

The two `bash_classify` additions keep parsing owned by that file and give `policy.c` no access to
its internals. `bash_command_is_exploration` and its documented contract are untouched. The header
comment for `bash_for_each_statement` and `bash_command_has_composition` must state the different
contract: unlike the exploration heuristic, these primitives feed an execution decision.

## Matcher semantics

- **Tools.** `tools.deny` and `tools.allow` are matched against `call->tool_name`. A call with no
  tool name is never denied.
- **Commands.** The `bash` tool's `command` argument is split into statements. Each statement has
  its neutral prefixes stripped — `sudo`, `doas`, `env`, `time`, `nohup`, `command`, `exec`,
  `nice`, `ionice`, `setsid`, `stdbuf`, and variable assignments — and is then matched against a
  pattern at token boundaries with whitespace normalized. A pattern of `git status` matches
  `git status --short` and not `git stash`.
- **allow-list** denies when any statement is unmatched, or when the command composes at all.
  Malformed arguments fail closed.
- **deny-list** denies when any statement matches a deny pattern.
- **ask** is decided by folder trust, read once at launch. Trusted: RUN, except a dangerous
  command, which is ASK. Untrusted: RUN for `task_wait` and for `read` whose path normalizes
  inside the root; DENY for everything else. The root is the git worktree root, else the working
  directory; symlinks are not resolved, like the path matcher.
- **dangerous.** `bash.dangerous_commands` is matched like a deny pattern but against both the
  literal and wrapper-stripped statement, so listing either `sudo` or `rm` catches `sudo rm`. It
  only raises friction; it never blocks.
- **Paths.** `read`, `edit`, and `write` have their `path` argument expanded (`~`), resolved
  against the working directory when relative, and collapsed lexically, then matched against
  `deny_prefixes` on path-component boundaries so `/etc` matches `/etc/passwd` and not
  `/etcetera`. `write_only` restricts path rules to `edit` and `write`.

Resolution happens on every call rather than being cached, which keeps it correct under a
`/config` change and costs only a few JSON lookups between tool calls.

The model-facing result is `error: denied by policy: <tool>`, with `ITEM_ORIGIN_REFUSED`; the
terminal shows a `[denied by policy]` marker. An untrusted folder replaces `<tool>` with the reason
that names the folder, so the model stops retrying and asks the operator to trust it.

## Wiring

| File | Change |
| --- | --- |
| `src/policy.h`, `src/policy.c` | new module |
| `src/agent_loop.h` | add `AGENT_LOOP_TOOL_DENY` and `AGENT_LOOP_TOOL_ASK` |
| `src/agent_loop.c` | policy branch in the dispatch loop; hookless `DENY`/`ASK` |
| `src/agent.c` | `DENY` and `ASK` cases in `repl_loop_tool_call`; prompt wiring |
| `src/terminal/approve.c` / `.h` | dangerous-command confirmation (`y`/`N`) |
| `src/terminal/keyread.c` / `.h` | key decoding: bare Esc, CSI-u, ignored sequences |
| `src/terminal/trust_prompt.c` / `.h` | launch-time trust question |
| `src/trust_store.c` / `.h` | persisted trust list in `<state>/hax/trust.json` |
| `src/trust_gate.c` / `.h` | resolves the root and applies persisted or prompted trust |
| `src/main.c` | calls the gate before either frontend starts |
| `src/agent_dispatch.c` / `.h` | `dispatch_tool_denied`, `dispatch_tool_denied_reason` |
| `src/agent_core.h` | `DENIED_MARKER` |
| `src/tools/bash_classify.c` / `.h` | the two primitives |

The reason is fetched in the frontend rather than threaded through `agent_loop_hooks`, which keeps
the hook signature and every frontend untouched, at the cost of `agent_dispatch.c` including
`policy.h`. That file already includes `agent_core.h`, so the layering is consistent; if the
inversion is unwanted, the alternative is a reason parameter on the `tool_call` hook.

## Testing

`tests/test_policy.c`, registered in `tests/meson.build`, using the `config_load` injection and
`EXPECT` harness the other tests use.

- Off by default: no config denies nothing.
- Tool deny and allow, including a call with no tool name.
- Statement matching: `sudo rm -rf /`, `env X=1 rm /`, and `cd /tmp && rm -rf x` denied; `echo rm
  -rf` allowed.
- Allow-list: multi-statement commands denied when any statement is unmatched; compositions
  (`$(…)`, backticks, `<<<`, `&`) denied; `ls 2>/dev/null` allowed; malformed arguments denied.
- Paths: component-boundary matching, `write_only`, and `..` collapse.
- `fail_closed` on a malformed block.
- Ask, trusted: `ls`, `rg -n main src/main.c`, `ls 2>/dev/null` and `git status` run; `ls -la
  ~/Downloads`, `cat /etc/passwd`, `cat</etc/passwd`, `cd ~/ && ls`, `> /tmp/x`, `--out=/tmp/x`,
  `X=/tmp/x env` and `$HOME/.bashrc` escalate, as does an out-of-root path tool; dangerous commands
  escalate even inside the root.
- Ask, untrusted: runs `read` inside the root and `task_wait` only, denies `bash`/`edit`/`write`,
  denies a read outside the root, denies `..` escapes and the sibling `project-copy`, and names the
  folder in the denial.
- Trust gate: `policy_trust_required()` is true only for `ask`, false for `off`.
- Dangerous: `sudo ls`, `rm -rf`, `env X=1 rm`, and `git reset --hard` flagged; `grep rm file` and
  `echo sudoers` not, and non-bash tools never.
- Integration: `tests/test_agent_loop.c` covers hookless ASK failing closed (never dispatched,
  `ITEM_ORIGIN_REFUSED`, "approval required…") and the hook receiving ASK exactly once;
  `tests/test_agent_dispatch.c` covers `dispatch_tool_denied_reason` emitting the marker with the
  operator's reason and falling back to the generic refusal when it is NULL.
- `terminal/approve.c` and `terminal/trust_prompt.c` are not covered by the suite: they need a
  TTY. They were verified on a pty for `y`/`n`/Esc/Enter and both CSI-u and plain bytes, and the
  whole flow (untrusted denial, session trust, persisted trust, no second prompt, dangerous
  confirmed and refused) against a mock provider driving the real REPL.

## Cost

Roughly 1120 lines: 530 in the policy module, 90 across `keyread`/`approve`/`trust_prompt`, 100
for the trust store and gate, 20 in `bash_classify`, 80 of wiring, 300 of tests, 80 of
documentation. Eight files added, no new dependency, still one binary.

## Limitations

- Not a security boundary. The allow list is defeated by anything the agent can run that is itself
  allowed to do more — a permitted `sh`, `python`, or `make` is a general escape.
- Value-bearing wrapper flags are not resolved: `sudo -u root rm` leaves `root` as the statement
  leader. List the exact form or rely on isolation.
- Paths are resolved lexically, without following symlinks. A symlink inside an allowed directory
  that points at a denied one is not caught.
- `deny-list` mode only catches accidents.

## Rollout

The diff is inert until a `policy` block is configured, which keeps it rebase-safe and makes it
reviewable in three parts: the enum and an always-zero `policy_denies`, then the matcher, then the
frontend reason plumbing.
