/* SPDX-License-Identifier: MIT */
#ifndef HAX_TOOLS_BASH_CLASSIFY_H
#define HAX_TOOLS_BASH_CLASSIFY_H

#include <stddef.h>

/* Return nonzero when `command` appears to be read-only exploration. This heuristic selects only
 * the display preview mode; it never changes execution or model-facing output. */
int bash_command_is_exploration(const char *command);

/* Receives one statement of `command` and its byte length. Return 0 to stop iteration. */
typedef int (*bash_statement_fn)(const char *statement, size_t length, void *user_data);

/* Split a command on the unquoted separators the exploration heuristic recognizes: `;`, `&&`,
 * `||`, newlines, and pipes. Unlike bash_command_is_exploration this feeds execution decisions and
 * makes no claim about what a statement does. */
void bash_for_each_statement(const char *command, bash_statement_fn fn, void *user);

/* Nonzero when the command composes or substitutes in ways lexical analysis cannot follow:
 * command or process substitution, here-documents, background operators, or a redirection other
 * than stderr to /dev/null. An allow-list that denies composed commands cannot be bypassed by
 * wrapping a denied command in `echo $(...)`. */
int bash_command_has_composition(const char *command);

#endif /* HAX_TOOLS_BASH_CLASSIFY_H */
