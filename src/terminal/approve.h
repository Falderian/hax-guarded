/* SPDX-License-Identifier: MIT */
#ifndef HAX_TERMINAL_APPROVE_H
#define HAX_TERMINAL_APPROVE_H

/* Which boundary the call crossed, so the operator sees why they are being asked. */
enum approve_kind {
    APPROVE_DANGEROUS,
    APPROVE_OUTSIDE,
};

enum approve_choice {
    APPROVE_DENY,
    APPROVE_ONCE,
    APPROVE_SESSION,
};

/* Asks what to do with a call the policy escalated. `session` means the exact tool and arguments
 * stop asking until the process ends; `reason` is set only for a deny with a typed reason, and the
 * caller owns it. A non-interactive frontend, EOF, Esc, and Ctrl-C all mean deny. */
enum approve_choice approve_ask(enum approve_kind kind, const char *tool, const char *detail,
                                char **reason);

#endif /* HAX_TERMINAL_APPROVE_H */
