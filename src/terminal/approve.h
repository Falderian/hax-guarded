/* SPDX-License-Identifier: MIT */
#ifndef HAX_TERMINAL_APPROVE_H
#define HAX_TERMINAL_APPROVE_H

enum approve_choice {
    APPROVE_DENY,
    APPROVE_ONCE,
    APPROVE_SESSION,
};

/* Ask the operator whether a tool call may run. `detail` is shown verbatim as the command line or
 * path under review. `dangerous` demands a second confirmation before an approval counts. On
 * APPROVE_DENY, *reason_out receives an allocated operator-supplied reason, or NULL when none was
 * typed; the caller owns it. Without a TTY the answer is APPROVE_DENY. */
enum approve_choice approve_prompt(const char *tool, const char *detail, int dangerous,
                                   char **reason_out);

#endif /* HAX_TERMINAL_APPROVE_H */
