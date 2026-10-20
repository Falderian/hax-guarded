/* SPDX-License-Identifier: MIT */
#ifndef HAX_TERMINAL_KEYREAD_H
#define HAX_TERMINAL_KEYREAD_H

#include <termios.h>

/* Single-key input for raw-mode prompts. Reads one key, decoding the CSI-u form used by terminals
 * that implement the kitty keyboard protocol, and drops sequences the caller has no use for. */

/* Returns 1 with *out set, 0 for an ignored sequence (arrows, mouse, focus), or -1 on EOF. A lone
 * Esc is reported as 0x1b; Esc followed by a key sequence is decoded. */
int key_read(unsigned char *out);

/* Nonzero when stdin has input waiting within the given timeout. */
int key_pending(int milliseconds);

/* Put the terminal in raw mode for a prompt, saving the previous state. Returns -1 when stdin is
 * not a terminal. */
int key_raw_begin(struct termios *saved);

/* Restore the state saved by key_raw_begin and drop typed-ahead input. */
void key_raw_end(const struct termios *saved);

/* Append one byte as hex to <state>/hax/approve.log when HAX_APPROVE_DEBUG is set. */
void key_debug_byte(unsigned char byte);

#endif /* HAX_TERMINAL_KEYREAD_H */
