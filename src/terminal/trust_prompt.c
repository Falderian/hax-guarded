/* SPDX-License-Identifier: MIT */
#include "terminal/trust_prompt.h"

#include <stdio.h>

#include "terminal/keyread.h"

static void write_text(const char *text)
{
    fputs(text, stdout);
    fflush(stdout);
}

enum trust_choice trust_prompt(const char *root)
{
    struct termios saved;
    if (key_raw_begin(&saved) < 0)
        return TRUST_NO;

    printf("\r\n  Trust this folder? %s\r\n", root ? root : "");
    write_text("  [t] this session   [a] always   [n] no (read-only)\r\n  > ");

    enum trust_choice choice = TRUST_NO;
    for (;;) {
        unsigned char key = 0;
        int kind = key_read(&key);
        if (kind < 0)
            break;
        if (kind == 0)
            continue;
        if (key == 't' || key == 'T') {
            choice = TRUST_SESSION;
            break;
        }
        if (key == 'a' || key == 'A') {
            choice = TRUST_ALWAYS;
            break;
        }
        if (key == 'n' || key == 'N' || key == 0x1b || key == 0x03 || key == 0x04)
            break;
        if (key == '\n' || key == '\r') {
            write_text("\r\n  press t, a, or n\r\n  > ");
        }
    }

    write_text(choice == TRUST_ALWAYS ? "always\r\n"
               : choice == TRUST_SESSION ? "session\r\n"
                                         : "read-only\r\n");

    key_raw_end(&saved);
    write_text("\n");
    return choice;
}
