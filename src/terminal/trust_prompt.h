/* SPDX-License-Identifier: MIT */
#ifndef HAX_TERMINAL_TRUST_PROMPT_H
#define HAX_TERMINAL_TRUST_PROMPT_H

enum trust_choice {
    TRUST_NO,
    TRUST_SESSION,
    TRUST_ALWAYS,
};

/* Ask whether the workspace folder may run tools freely. Returns TRUST_NO when stdin or stdout is
 * not a terminal, so a non-interactive run never gains trust. */
enum trust_choice trust_prompt(const char *root);

#endif /* HAX_TERMINAL_TRUST_PROMPT_H */
