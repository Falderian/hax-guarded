/* SPDX-License-Identifier: MIT */
#ifndef HAX_POLICY_H
#define HAX_POLICY_H

#include "provider.h"

/* Config-driven restraint on tool calls, read from the `policy` block of config.json. An absent
 * block leaves policy_denies() a constant zero and the dispatch loop unchanged. This is a guard
 * against accidents, not a security boundary: isolation comes from the operating system. See
 * docs/policy-design.md. */

/* Nonzero when the call is denied by the configured policy. Resolved per call, so a config change
 * takes effect without invalidating anything. */
int policy_denies(const struct item *call);

/* Allocated model-facing denial text for a denied call, or NULL when the call is not denied. */
char *policy_deny_reason(const struct item *call);

#endif /* HAX_POLICY_H */
