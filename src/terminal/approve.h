/* SPDX-License-Identifier: MIT */
#ifndef HAX_TERMINAL_APPROVE_H
#define HAX_TERMINAL_APPROVE_H

/* Which boundary the call crossed, so the operator sees why they are being asked. */
enum approve_kind {
    APPROVE_DANGEROUS,
    APPROVE_OUTSIDE,
};

/* Confirmation for a call the policy escalated. Returns nonzero when the operator typed `y`; every
 * other key, Esc, EOF, and a non-interactive frontend mean no. */
int approve_run(enum approve_kind kind, const char *tool, const char *detail);

#endif /* HAX_TERMINAL_APPROVE_H */
