/* SPDX-License-Identifier: MIT */
#include "terminal/approve.h"

#include <stdio.h>

#include "terminal/keyread.h"

static void write_text(const char *text)
{
    fputs(text, stdout);
    fflush(stdout);
}

int approve_run(enum approve_kind kind, const char *tool, const char *detail)
{
    struct termios saved;
    if (key_raw_begin(&saved) < 0)
        return 0;

    const char *label = kind == APPROVE_DANGEROUS ? "DANGEROUS" : "OUTSIDE THE FOLDER";
    printf("\r\n  %s %s: %s\r\n", label, tool ? tool : "tool", detail ? detail : "");
    write_text("  run it anyway? [y/N] ");

    unsigned char key = 0;
    int event = key_read(&key);
    int allowed = event == 1 && (key == 'y' || key == 'Y');
    write_text(allowed ? "yes\r\n" : "no\r\n");

    key_raw_end(&saved);
    write_text("\n");
    return allowed;
}
