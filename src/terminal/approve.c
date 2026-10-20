/* SPDX-License-Identifier: MIT */
#include "terminal/approve.h"

#include <stdio.h>

#include "terminal/keyread.h"
#include "xalloc.h"

static void write_text(const char *text)
{
    fputs(text, stdout);
    fflush(stdout);
}

/* Returns the length, or -1 when the operator cancels with Esc or Ctrl-C. */
static int read_line(char *line, size_t size)
{
    size_t length = 0;
    for (;;) {
        unsigned char key = 0;
        int event = key_read(&key);
        if (event < 0)
            return -1;
        if (event == 0)
            continue;
        if (key == '\r' || key == '\n')
            return (int)length;
        if (key == 0x1b || key == 0x03)
            return -1;
        if (key == 0x7f || key == 0x08) {
            if (length) {
                length--;
                write_text("\b \b");
            }
            continue;
        }
        if (key < 0x20 || key >= 0x7f)
            continue;
        if (length + 1 < size) {
            line[length++] = (char)key;
            char echo[2] = {(char)key, '\0'};
            write_text(echo);
        }
    }
}

enum approve_choice approve_ask(enum approve_kind kind, const char *tool, const char *detail,
                                char **reason)
{
    *reason = NULL;
    struct termios saved;
    if (key_raw_begin(&saved) < 0)
        return APPROVE_DENY;

    const char *label = kind == APPROVE_DANGEROUS ? "DANGEROUS" : "OUTSIDE THE FOLDER";
    printf("\r\n  %s %s: %s\r\n", label, tool ? tool : "tool", detail ? detail : "");
    write_text("  [y] once  [s] this session  [n] deny  [r] deny with reason ");

    enum approve_choice choice = APPROVE_DENY;
    unsigned char key = 0;
    if (key_read(&key) == 1) {
        if (key == 'y' || key == 'Y') {
            choice = APPROVE_ONCE;
        } else if (key == 's' || key == 'S') {
            choice = APPROVE_SESSION;
        } else if (key == 'r' || key == 'R') {
            write_text("\r\n  reason: ");
            char line[512] = {0};
            int length = read_line(line, sizeof line);
            write_text("\r\n");
            if (length > 0) {
                while (length > 0 && line[length - 1] == ' ')
                    line[--length] = '\0';
                *reason = xstrdup(line);
            }
        }
    }

    if (choice == APPROVE_ONCE)
        write_text("  > once\r\n");
    else if (choice == APPROVE_SESSION)
        write_text("  > this session\r\n");
    else if (*reason)
        printf("  > denied: %s\r\n", *reason);
    else
        write_text("  > denied\r\n");

    key_raw_end(&saved);
    write_text("\n");
    return choice;
}
