# Tool-call policy (design)

Status: proposal. Not implemented.

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

## Configuration

Structured block in `config.json`, read with `config_json_node("policy")` like `catalog.models`.
It is not a registry setting, so it is not editable through `/config`; document it as file-only.
An absent block means the feature is off and behaviour is byte-identical to today.

```json
{
  "policy": {
    "mode": "allow-list",
    "fail_closed": true,
    "tools": { "deny": ["bash"], "allow": ["read", "edit", "write", "bash", "task_wait"] },
    "bash": {
      "allow_commands": ["ls", "cat", "head", "tail", "grep", "rg", "find", "wc",
                         "git status", "git diff", "git log", "go test", "go build", "make"]
    },
    "paths": {
      "deny_prefixes": ["/etc", "/usr", "/boot", "~/.ssh", "~/.pi/agent/auth.json"],
      "write_only": true
    }
  }
}
```

`mode` is `off` (default), `deny-list`, or `allow-list`. `fail_closed` decides what a malformed
block does: deny everything (true) or behave as off (false). Note that `config_json_node` does not
merge across tiers — a `policy` block in `state.json` wins wholesale over the one in
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
else if (policy_denies(&session->items[i]))
    action = AGENT_LOOP_TOOL_DENY;
```

Policy is the last branch, so a session with tools disabled keeps refusing and an abort keeps
skipping with interrupted provenance. The loop then hands the action to the frontend hook when one
is installed (`agent.c`), and acts on it directly when none is (`hax -p`); both paths already
branch on `RUN`/`REFUSE`/`SKIP`, so both gain `DENY` at the same seam.

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
- **Paths.** `read`, `edit`, and `write` have their `path` argument expanded (`~`), resolved
  against the working directory when relative, and collapsed lexically, then matched against
  `deny_prefixes` on path-component boundaries so `/etc` matches `/etc/passwd` and not
  `/etcetera`. `write_only` restricts path rules to `edit` and `write`.

Resolution happens on every call rather than being cached, which keeps it correct under a
`/config` change and costs only a few JSON lookups between tool calls.

The model-facing result is `error: denied by policy: <tool>`, with `ITEM_ORIGIN_REFUSED`; the
terminal shows a `[denied by policy]` marker.

## Wiring

| File | Change |
| --- | --- |
| `src/policy.h`, `src/policy.c` | new module |
| `src/agent_loop.h` | add `AGENT_LOOP_TOOL_DENY` |
| `src/agent_loop.c` | policy branch in the dispatch loop; `DENY` case in the hookless chain |
| `src/agent.c` | `DENY` case in `repl_loop_tool_call` |
| `src/agent_dispatch.c` / `.h` | `dispatch_tool_denied` |
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
- Integration: a `DENY` action yields `ITEM_ORIGIN_REFUSED` and never invokes the tool's `run`;
  `dispatch_tool_denied` emits the marker with that origin.

## Cost

Roughly 570 lines: 260 in the new module, 20 in `bash_classify`, 30 of wiring, 220 of tests, 40 of
documentation. Two files added, no new dependency, still one binary.

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
