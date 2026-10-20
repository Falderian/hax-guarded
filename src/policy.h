/* SPDX-License-Identifier: MIT */
#ifndef HAX_POLICY_H
#define HAX_POLICY_H

#include "provider.h"

/* Config-driven restraint on tool calls, read from the `policy` block of config.json. An absent
 * block leaves every call running and the dispatch loop unchanged. This is a guard against
 * mistakes, not a security boundary: isolation comes from the operating system. See
 * docs/policy-design.md. */

enum policy_verdict {
    POLICY_VERDICT_RUN,
    POLICY_VERDICT_ASK,
    POLICY_VERDICT_DENY,
};

/* Resolved per call, so a config change takes effect without invalidating anything. ASK means the
 * frontend must obtain approval; a frontend without a prompt treats it as DENY. */
enum policy_verdict policy_verdict(const struct item *call);

/* Nonzero when the call is denied by the configured policy. */
int policy_denies(const struct item *call);

/* Allocated model-facing denial text for a denied call, or NULL when the call is not denied. */
char *policy_deny_reason(const struct item *call);

/* Nonzero when the call matches `bash.dangerous_commands`, so it needs a confirmation even in a
 * trusted folder. Wrapper-prefixed forms (`sudo rm`) are matched with the wrapper stripped. */
int policy_is_dangerous(const struct item *call);

/* Allocated display detail for a call: its command line, path, or raw arguments. NULL for
 * anything that is not a tool call. */
char *policy_call_detail(const struct item *call);

/* Ask mode is gated on the folder, not the call: a trusted folder runs everything except
 * dangerous commands, an untrusted one is read-only inside its root. The gate is what the
 * operator answers at launch. */
int policy_trust_required(void);
int policy_is_trusted(void);
void policy_set_trusted(int trusted);

/* The folder trust is decided for: the git worktree root containing the working directory, or the
 * working directory itself. Allocated; the caller owns it. */
char *policy_workspace_root(void);

/* Pin the root the caller resolved (and possibly persisted). Without it the verdict resolves the
 * root on first use, which is what non-interactive runs rely on. */
void policy_set_workspace_root(const char *root);

#endif /* HAX_POLICY_H */
