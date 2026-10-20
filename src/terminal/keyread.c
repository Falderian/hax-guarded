/* SPDX-License-Identifier: MIT */
#include "terminal/keyread.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "system/path.h"
#include "xalloc.h"

static int read_byte(unsigned char *out)
{
    for (;;) {
        ssize_t count = read(STDIN_FILENO, out, 1);
        if (count == 1) {
            key_debug_byte(*out);
            return 0;
        }
        if (count < 0 && errno == EINTR)
            continue;
        return -1;
    }
}

void key_debug_byte(unsigned char byte)
{
    static int enabled = -1;
    if (enabled < 0) {
        const char *value = getenv("HAX_APPROVE_DEBUG");
        enabled = value && *value;
    }
    if (!enabled)
        return;
    char *path = xdg_hax_state_path("approve.log");
    if (!path)
        return;
    FILE *log = fopen(path, "a");
    if (log) {
        fprintf(log, "%02x\n", byte);
        fclose(log);
    }
    free(path);
}

int key_raw_begin(struct termios *saved)
{
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))
        return -1;
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

void key_raw_end(const struct termios *saved)
{
    tcsetattr(STDIN_FILENO, TCSADRAIN, saved);
    tcflush(STDIN_FILENO, TCIFLUSH);
}

int key_pending(int milliseconds)
{
    struct pollfd pending = {.fd = STDIN_FILENO, .events = POLLIN};
    return poll(&pending, 1, milliseconds) > 0 && (pending.revents & POLLIN);
}

int key_read(unsigned char *out)
{
    unsigned char first;
    if (read_byte(&first) < 0)
        return -1;
    if (first != 0x1b) {
        *out = first;
        return 1;
    }
    if (!key_pending(30)) {
        *out = 0x1b;
        return 1;
    }
    unsigned char second;
    if (read_byte(&second) < 0) {
        *out = 0x1b;
        return 1;
    }
    if (second != '[' && second != 'O') {
        *out = second;
        return 1;
    }
    char params[32];
    size_t length = 0;
    for (;;) {
        unsigned char byte;
        if (read_byte(&byte) < 0)
            return 0;
        if (length + 1 < sizeof params)
            params[length++] = (char)byte;
        if (byte >= 0x40 && byte <= 0x7e) {
            params[length] = '\0';
            if (byte == 'u') {
                long codepoint = strtol(params, NULL, 10);
                if (codepoint > 0 && codepoint < 0x80) {
                    *out = (unsigned char)codepoint;
                    return 1;
                }
            }
            return 0;
        }
    }
}
