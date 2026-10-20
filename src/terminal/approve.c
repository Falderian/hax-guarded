/* SPDX-License-Identifier: MIT */
#include "terminal/approve.h"

#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "terminal/keyread.h"
#include "xalloc.h"

#define DETAIL_INDENT 4
#define DETAIL_ROWS 12

static void write_text(const char *text)
{
    fputs(text, stdout);
    fflush(stdout);
}

/* The prompt runs in raw mode, so a bare newline keeps the cursor column. Every row emitted here
 * therefore ends in \r\n. */
static size_t terminal_width(void)
{
    struct winsize size;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_col >= DETAIL_INDENT + 16)
        return size.ws_col;
    return 80;
}

static void write_span(const char *text, size_t length)
{
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)text[i];
        if (c == '\t') {
            write_text("    ");
        } else if (c < 0x20 || c == 0x7f) {
            write_text("?");
        } else {
            char echo[2] = {(char)c, '\0'};
            write_text(echo);
        }
    }
}

/* Multi-line commands (heredocs especially) are common, so show a bounded, width-fitted preview
 * instead of dumping the raw string: that kept the cursor staircase and pushed the question off
 * screen. */
static void write_detail(const char *detail)
{
    if (!detail || !*detail)
        return;
    size_t room = terminal_width() - DETAIL_INDENT;
    size_t total = 1;
    for (const char *cursor = detail; *cursor; cursor++)
        if (*cursor == '\n')
            total++;

    const char *cursor = detail;
    size_t lines = 0;
    size_t rows = 0;
    while (*cursor) {
        if (lines == DETAIL_ROWS || rows == DETAIL_ROWS * 2) {
            printf("    … (%zu more lines)\r\n", total - lines);
            return;
        }
        const char *end = strchr(cursor, '\n');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        size_t offset = 0;
        do {
            size_t take = length - offset;
            if (take > room)
                take = room;
            write_text("    ");
            write_span(cursor + offset, take);
            write_text("\r\n");
            offset += take;
            rows++;
        } while (offset < length);
        lines++;
        if (!end)
            return;
        cursor = end + 1;
    }
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
    printf("\r\n  %s %s:\r\n", label, tool ? tool : "tool");
    write_detail(detail);
    if (terminal_width() < 76)
        write_text("  [y] once [s] session [n] deny [r] reason ");
    else
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
