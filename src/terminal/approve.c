/* SPDX-License-Identifier: MIT */
#include "approve.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "xalloc.h"

static int read_byte(unsigned char *out)
{
    for (;;) {
        ssize_t count = read(STDIN_FILENO, out, 1);
        if (count == 1)
            return 0;
        if (count < 0 && errno == EINTR)
            continue;
        return -1;
    }
}

static void write_text(const char *text)
{
    fputs(text, stdout);
    fflush(stdout);
}

/* One line of raw-mode text with backspace and Enter. Esc, Ctrl-C, or EOF yields NULL. */
static char *read_reason(void)
{
    char buffer[512];
    size_t length = 0;
    for (;;) {
        unsigned char byte;
        if (read_byte(&byte) < 0)
            return NULL;
        if (byte == '\n' || byte == '\r')
            break;
        if (byte == 0x03 || byte == 0x1b)
            return NULL;
        if (byte == 0x7f || byte == 0x08) {
            if (length > 0) {
                length--;
                write_text("\b \b");
            }
            continue;
        }
        if (byte < 0x20)
            continue;
        if (length + 1 < sizeof buffer) {
            buffer[length++] = (char)byte;
            fputc(byte, stdout);
            fflush(stdout);
        }
    }
    buffer[length] = '\0';
    return length ? xstrdup(buffer) : NULL;
}

static int enable_raw_mode(struct termios *saved)
{
    if (tcgetattr(STDIN_FILENO, saved) < 0)
        return -1;
    struct termios raw = *saved;
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    raw.c_iflag &= ~(IXON | ICRNL | INPCK | ISTRIP | BRKINT);
    raw.c_oflag &= ~OPOST;
    raw.c_cflag |= CS8;
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    return tcsetattr(STDIN_FILENO, TCSADRAIN, &raw);
}

enum approve_choice approve_prompt(const char *tool, const char *detail, int dangerous,
                                   char **reason_out)
{
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))
        return APPROVE_DENY;

    struct termios saved;
    if (enable_raw_mode(&saved) < 0)
        return APPROVE_DENY;

    printf("\r\n  allow %s? %s\r\n", tool ? tool : "tool", detail ? detail : "");
    write_text("  [a] once   [s] session   [d] deny   [esc] deny\r\n  > ");

    enum approve_choice choice = APPROVE_DENY;
    int reason_requested = 0;
    unsigned char byte;
    for (;;) {
        if (read_byte(&byte) < 0)
            break;
        if (byte == 'a' || byte == 'A')
            choice = APPROVE_ONCE;
        else if (byte == 's' || byte == 'S')
            choice = APPROVE_SESSION;
        else if (byte == 'd' || byte == 'D')
            reason_requested = 1;
        else if (byte != 0x1b && byte != 0x03)
            continue;
        break;
    }

    if (dangerous && (choice == APPROVE_ONCE || choice == APPROVE_SESSION)) {
        write_text("\r\n  DANGEROUS: ");
        write_text(detail ? detail : "");
        write_text("\r\n  press y to confirm, any other key denies\r\n  > ");
        unsigned char confirm;
        if (read_byte(&confirm) < 0 || (confirm != 'y' && confirm != 'Y'))
            choice = APPROVE_DENY;
    }

    char *reason = NULL;
    if (choice == APPROVE_DENY && reason_requested) {
        write_text("\r\n  reason (Enter to skip): ");
        reason = read_reason();
    }

    tcsetattr(STDIN_FILENO, TCSADRAIN, &saved);
    /* Drop typed-ahead bytes so the resumed Esc watcher does not read them as interrupts. */
    tcflush(STDIN_FILENO, TCIFLUSH);
    write_text("\n");

    if (choice == APPROVE_DENY && reason_out)
        *reason_out = reason;
    else
        free(reason);
    return choice;
}
