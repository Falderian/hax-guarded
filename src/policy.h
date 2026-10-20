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

/* Nonzero when the call matches `bash.dangerous_commands`, so an approval needs a second
 * confirmation. Wrapper-prefixed forms (`sudo rm`) are matched with the wrapper stripped. */
int policy_is_dangerous(const struct item *call);

/* Allocated display detail for a call: its command line, path, or raw arguments. NULL for
 * anything that is not a tool call. */
char *policy_call_detail(const struct item *call);

/* Remember an exact (tool, arguments) pair as approved for the rest of the process. The grant is
 * deliberately not a prefix: approving `git status` does not approve `git status --short`. */
void policy_grant_session(const struct item *call);

/* Drop every session grant. For tests; also the way a caller abandons a session. */
void policy_clear_session(void);

#endif /* HAX_POLICY_H */
