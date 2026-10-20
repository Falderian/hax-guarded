/* SPDX-License-Identifier: MIT */
#include "policy.h"

#include <ctype.h>
#include <jansson.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "system/git.h"
#include "tools/bash_classify.h"
#include "xalloc.h"

/* Neutral words that precede the real command. Stripping them keeps `sudo rm` and `env X=1 rm`
 * from hiding behind `sudo` or `env`; a wrapper's value arguments (`sudo -u root rm`) are not
 * resolved and are documented as a gap. */
static const char *const COMMAND_WRAPPERS[] = {
    "sudo", "doas", "env", "time", "nohup", "command", "exec", "nice", "ionice", "setsid", "stdbuf",
};

static const char *const PATH_TOOLS[] = {"read", "write", "edit"};

enum policy_mode {
    POLICY_OFF,
    POLICY_DENY_LIST,
    POLICY_ALLOW_LIST,
    POLICY_ASK,
};

static const json_t *policy_block(void)
{
    const json_t *node = config_json_node("policy");
    return json_is_object(node) ? node : NULL;
}

static enum policy_mode policy_mode(const json_t *block, int *malformed_out)
{
    *malformed_out = 0;
    if (!block)
        return POLICY_OFF;
    const json_t *node = json_object_get(block, "mode");
    if (!node)
        return POLICY_OFF;
    if (!json_is_string(node)) {
        *malformed_out = 1;
        return POLICY_OFF;
    }
    const char *value = json_string_value(node);
    if (strcmp(value, "off") == 0)
        return POLICY_OFF;
    if (strcmp(value, "deny-list") == 0)
        return POLICY_DENY_LIST;
    if (strcmp(value, "allow-list") == 0)
        return POLICY_ALLOW_LIST;
    if (strcmp(value, "ask") == 0)
        return POLICY_ASK;
    *malformed_out = 1;
    return POLICY_OFF;
}

/* Borrowed pointers into the config document, which outlives the call. Empty strings are skipped
 * so a stray "" cannot match every command. */
static const char **string_array(const json_t *node, size_t *count_out)
{
    *count_out = 0;
    if (!json_is_array(node))
        return NULL;
    const char **out = xcalloc(json_array_size(node), sizeof(*out));
    size_t index;
    json_t *entry;
    json_array_foreach(node, index, entry)
    {
        if (json_is_string(entry) && *json_string_value(entry))
            out[(*count_out)++] = json_string_value(entry);
    }
    if (*count_out == 0) {
        free(out);
        return NULL;
    }
    return out;
}

static int json_array_contains(const json_t *node, const char *value)
{
    if (!json_is_array(node) || !value)
        return 0;
    size_t index;
    json_t *entry;
    json_array_foreach(node, index, entry)
    {
        if (json_is_string(entry) && strcmp(json_string_value(entry), value) == 0)
            return 1;
    }
    return 0;
}

static char *arg_string(const char *args_json, const char *key)
{
    if (!args_json)
        return NULL;
    json_error_t error;
    json_t *root = json_loads(args_json, 0, &error);
    if (!root)
        return NULL;
    const json_t *value = json_object_get(root, key);
    char *copy = json_is_string(value) ? xstrdup(json_string_value(value)) : NULL;
    json_decref(root);
    return copy;
}

static int is_wrapper(const char *token, size_t length)
{
    for (size_t i = 0; i < sizeof(COMMAND_WRAPPERS) / sizeof(COMMAND_WRAPPERS[0]); i++) {
        const char *wrapper = COMMAND_WRAPPERS[i];
        if (strlen(wrapper) == length && strncmp(token, wrapper, length) == 0)
            return 1;
    }
    return 0;
}

static int is_assignment(const char *token, size_t length)
{
    if (length == 0 || !(token[0] == '_' || isalpha((unsigned char)token[0])))
        return 0;
    for (size_t i = 0; i < length; i++)
        if (token[i] == '=')
            return 1;
    return 0;
}

/* Advance past neutral words and their short flags, returning the statement body. */
static const char *strip_prefixes(const char *statement, size_t *length_in_out)
{
    size_t start = 0;
    size_t length = *length_in_out;
    int stripped_wrapper = 0;
    for (;;) {
        while (start < length && (statement[start] == ' ' || statement[start] == '\t'))
            start++;
        size_t end = start;
        while (end < length && statement[end] != ' ' && statement[end] != '\t')
            end++;
        if (end == start)
            break;
        size_t token_length = end - start;
        const char *token = statement + start;
        if (is_wrapper(token, token_length)) {
            stripped_wrapper = 1;
            start = end;
            continue;
        }
        if (is_assignment(token, token_length) || (stripped_wrapper && token[0] == '-')) {
            start = end;
            continue;
        }
        break;
    }
    *length_in_out = length - start;
    return statement + start;
}

/* Match a pattern at the start of the statement body on token boundaries, so `git status` accepts
 * `git status --short` and rejects `git stash`. */
static int statement_matches_with(const char *statement, size_t length, const char *pattern,
                                  int strip_wrappers)
{
    const char *body = strip_wrappers ? strip_prefixes(statement, &length) : statement;
    const char *cursor = pattern;
    while (*cursor) {
        while (*cursor == ' ' || *cursor == '\t')
            cursor++;
        const char *pattern_end = cursor;
        while (*pattern_end && *pattern_end != ' ' && *pattern_end != '\t')
            pattern_end++;
        size_t pattern_length = (size_t)(pattern_end - cursor);
        if (pattern_length == 0)
            break;
        while (length > 0 && (*body == ' ' || *body == '\t')) {
            body++;
            length--;
        }
        size_t token_length = 0;
        while (token_length < length && body[token_length] != ' ' && body[token_length] != '\t')
            token_length++;
        if (token_length != pattern_length || strncmp(body, cursor, token_length) != 0)
            return 0;
        body += token_length;
        length -= token_length;
        cursor = pattern_end;
    }
    return 1;
}

static int statement_matches(const char *statement, size_t length, const char *pattern)
{
    return statement_matches_with(statement, length, pattern, 1);
}

struct command_scan {
    const char **patterns;
    size_t count;
    int matched;
    int unmatched;
};

static int command_scan_visit(const char *statement, size_t length, void *user)
{
    struct command_scan *scan = user;
    int any = 0;
    for (size_t i = 0; i < scan->count && !any; i++)
        any = statement_matches(statement, length, scan->patterns[i]);
    if (any)
        scan->matched = 1;
    else
        scan->unmatched = 1;
    return 1;
}

static void scan_command(const char *command, const json_t *patterns_node,
                         struct command_scan *scan)
{
    scan->patterns = string_array(patterns_node, &scan->count);
    if (scan->patterns)
        bash_for_each_statement(command, command_scan_visit, scan);
}

/* An allow-list denies a composed command outright: `echo $(rm -rf /)` must not pass because
 * `echo` is allowed. A deny-list cannot see through the composition and only catches the literal
 * form, which is why it is a typo-catcher rather than a restraint. */
static int command_denied(enum policy_mode mode, const json_t *bash, const char *command)
{
    if (bash_command_has_composition(command))
        return mode == POLICY_ALLOW_LIST;
    struct command_scan scan = {0};
    if (mode == POLICY_ALLOW_LIST) {
        scan_command(command, json_object_get(bash, "allow_commands"), &scan);
        int denied = !(scan.matched && !scan.unmatched);
        free(scan.patterns);
        return denied;
    }
    scan_command(command, json_object_get(bash, "deny_commands"), &scan);
    int denied = scan.matched;
    free(scan.patterns);
    return denied;
}

/* Expand `~` and relative paths, then collapse `.` and `..` lexically so `/etc/../etc/passwd`
 * is still caught. Symlinks are not resolved; that limit is documented. */
static char *path_normalize(const char *raw)
{
    if (!raw || !*raw)
        return xstrdup("");
    char *expanded;
    if (raw[0] == '~' && (raw[1] == '/' || raw[1] == '\0')) {
        const char *home = getenv("HOME");
        expanded = xasprintf("%s%s", home ? home : "", raw + 1);
    } else if (raw[0] == '/') {
        expanded = xstrdup(raw);
    } else {
        char cwd[PATH_MAX];
        expanded = xasprintf("%s/%s", getcwd(cwd, sizeof cwd) ? cwd : "", raw);
    }
    char *out = xmalloc(strlen(expanded) + 2);
    size_t out_length = 0;
    const char *cursor = expanded;
    while (*cursor) {
        while (*cursor == '/')
            cursor++;
        const char *component = cursor;
        while (*cursor && *cursor != '/')
            cursor++;
        size_t component_length = (size_t)(cursor - component);
        if (component_length == 0)
            continue;
        if (component_length == 1 && component[0] == '.')
            continue;
        if (component_length == 2 && component[0] == '.' && component[1] == '.') {
            while (out_length > 0 && out[out_length - 1] != '/')
                out_length--;
            if (out_length > 0)
                out_length--;
            continue;
        }
        out[out_length++] = '/';
        memcpy(out + out_length, component, component_length);
        out_length += component_length;
    }
    if (out_length == 0)
        out[out_length++] = '/';
    out[out_length] = '\0';
    free(expanded);
    return out;
}

/* Component-boundary match, so `/etc` covers `/etc/passwd` and not `/etcetera`. */
static int path_has_prefix(const char *path, const char *prefix)
{
    char *normalized = path_normalize(prefix);
    size_t length = strlen(normalized);
    int matched = strncmp(path, normalized, length) == 0 &&
                  (length == 1 || path[length] == '\0' || path[length] == '/');
    free(normalized);
    return matched;
}

static int is_path_tool(const char *name)
{
    for (size_t i = 0; i < sizeof(PATH_TOOLS) / sizeof(PATH_TOOLS[0]); i++)
        if (strcmp(PATH_TOOLS[i], name) == 0)
            return 1;
    return 0;
}

static int path_denied(const json_t *paths, const char *tool, const char *raw)
{
    if (json_is_true(json_object_get(paths, "write_only")) && strcmp(tool, "read") == 0)
        return 0;
    size_t count = 0;
    const char **prefixes = string_array(json_object_get(paths, "deny_prefixes"), &count);
    if (!prefixes)
        return 0;
    char *normalized = path_normalize(raw);
    int denied = 0;
    for (size_t i = 0; i < count && !denied; i++)
        denied = path_has_prefix(normalized, prefixes[i]);
    free(normalized);
    free(prefixes);
    return denied;
}

/* --- folder trust ------------------------------------------------------------------ */

static int policy_trusted;
static char *workspace_root_cache;

int policy_trust_required(void)
{
    int malformed = 0;
    return policy_mode(policy_block(), &malformed) == POLICY_ASK && !malformed;
}

int policy_is_trusted(void)
{
    return policy_trusted;
}

void policy_set_trusted(int trusted)
{
    policy_trusted = trusted;
}

char *policy_workspace_root(void)
{
    char *cwd = getcwd(NULL, 0);
    if (!cwd)
        return NULL;
    char *root = git_find_worktree_root(cwd);
    if (root) {
        free(cwd);
        return root;
    }
    return cwd;
}

void policy_set_workspace_root(const char *root)
{
    free(workspace_root_cache);
    workspace_root_cache = root ? xstrdup(root) : NULL;
}

static const char *workspace_root(void)
{
    if (!workspace_root_cache)
        workspace_root_cache = policy_workspace_root();
    return workspace_root_cache;
}

/* Symlinks are not resolved, matching the documented limit of the path matcher. */
static int path_inside_workspace(const char *path)
{
    const char *root = workspace_root();
    if (!path || !root)
        return 0;
    char *normalized = path_normalize(path);
    char *root_normalized = path_normalize(root);
    int inside = path_has_prefix(normalized, root_normalized);
    free(normalized);
    free(root_normalized);
    return inside;
}

/* The agent's tools take a path argument; an untrusted folder grants read only, and a trusted one
 * asks for anything that points outside. */
static int tool_path_inside_workspace(const struct item *call)
{
    char *path = arg_string(call->tool_arguments_json, "path");
    int inside = path_inside_workspace(path);
    free(path);
    return inside;
}

/* Device nodes that cannot name a file the operator cares about. */
static int is_neutral_device(const char *word)
{
    return strcmp(word, "/dev/null") == 0 || strcmp(word, "/dev/stdout") == 0 ||
           strcmp(word, "/dev/stderr") == 0 || strcmp(word, "/dev/tty") == 0;
}

/* One shell word, which may be a path, a flag carrying one (`--out=/tmp/x`), or an assignment. */
static int word_inside_workspace(const char *word)
{
    if (!*word)
        return 1;
    if (*word == '-') {
        const char *value = strchr(word, '=');
        return value ? word_inside_workspace(value + 1) : 1;
    }
    const char *value = strchr(word, '=');
    const char *slash = strchr(word, '/');
    if (value && slash && slash > value)
        return word_inside_workspace(value + 1);
    if (strstr(word, "://"))
        return 1;
    if (is_neutral_device(word))
        return 1;
    if (strstr(word, "$HOME") || strstr(word, "${HOME}"))
        return 0;
    if (word[0] == '~' && word[1] && word[1] != '/')
        return 0;
    return path_inside_workspace(word);
}

/* Best effort: every word that looks like a path must normalize inside the root. Words that are
 * plain names resolve against the working directory, which the caller already keeps inside. The
 * documented gaps are commands whose targets are implicit (`git config --global`, `cd` alone) and
 * variables other than $HOME, which are assumed harmless. */
static int bash_inside_workspace(const char *command)
{
    if (!command)
        return 0;
    char word[PATH_MAX];
    size_t n = 0;
    char quote = 0;
    int inside = 1;
    const char *cursor = command;
    for (;;) {
        char c = *cursor;
        if (c && quote) {
            if (c == quote)
                quote = 0;
            else if (n + 1 < sizeof word)
                word[n++] = c;
            cursor++;
            continue;
        }
        if (c == '\'' || c == '"') {
            quote = c;
            cursor++;
            continue;
        }
        int boundary = c == '\0' || isspace((unsigned char)c) || strchr(";|&<>()", c) != NULL;
        if (!boundary) {
            if (n + 1 < sizeof word)
                word[n++] = c;
            cursor++;
            continue;
        }
        word[n] = '\0';
        n = 0;
        if (!word_inside_workspace(word)) {
            inside = 0;
            break;
        }
        if (!c)
            break;
        cursor++;
    }
    return inside;
}

/* --- decisions --------------------------------------------------------------------- */

static int listed_denied(enum policy_mode mode, const json_t *block, const struct item *call)
{
    const json_t *tools = json_object_get(block, "tools");
    const char *name = call->tool_name;
    int tool_denied = mode == POLICY_DENY_LIST
                          ? json_array_contains(json_object_get(tools, "deny"), name)
                          : !json_array_contains(json_object_get(tools, "allow"), name);

    if (strcmp(name, "bash") == 0) {
        char *command = arg_string(call->tool_arguments_json, "command");
        int denied = command ? command_denied(mode, json_object_get(block, "bash"), command)
                             : mode == POLICY_ALLOW_LIST;
        free(command);
        return denied || tool_denied;
    }

    if (is_path_tool(name)) {
        char *path = arg_string(call->tool_arguments_json, "path");
        int denied = path ? path_denied(json_object_get(block, "paths"), name, path) : 0;
        free(path);
        return denied || tool_denied;
    }

    return tool_denied;
}

enum policy_verdict policy_verdict(const struct item *call)
{
    const json_t *block = policy_block();
    int malformed = 0;
    enum policy_mode mode = policy_mode(block, &malformed);
    if (malformed)
        return json_is_true(json_object_get(block, "fail_closed")) ? POLICY_VERDICT_DENY
                                                                   : POLICY_VERDICT_RUN;
    if (mode == POLICY_OFF || !call || call->kind != ITEM_TOOL_CALL || !call->tool_name)
        return POLICY_VERDICT_RUN;
    if (mode == POLICY_ASK) {
        if (policy_trusted) {
            if (policy_is_dangerous(call))
                return POLICY_VERDICT_ASK;
            if (strcmp(call->tool_name, "bash") == 0) {
                char *command = arg_string(call->tool_arguments_json, "command");
                int inside = bash_inside_workspace(command);
                free(command);
                return inside ? POLICY_VERDICT_RUN : POLICY_VERDICT_ASK;
            }
            if (is_path_tool(call->tool_name))
                return tool_path_inside_workspace(call) ? POLICY_VERDICT_RUN : POLICY_VERDICT_ASK;
            return POLICY_VERDICT_RUN;
        }
        if (strcmp(call->tool_name, "read") == 0)
            return tool_path_inside_workspace(call) ? POLICY_VERDICT_RUN : POLICY_VERDICT_DENY;
        if (strcmp(call->tool_name, "task_wait") == 0)
            return POLICY_VERDICT_RUN;
        return POLICY_VERDICT_DENY;
    }
    return listed_denied(mode, block, call) ? POLICY_VERDICT_DENY : POLICY_VERDICT_RUN;
}

int policy_denies(const struct item *call)
{
    return policy_verdict(call) == POLICY_VERDICT_DENY;
}

char *policy_deny_reason(const struct item *call)
{
    if (!policy_denies(call))
        return NULL;
    int malformed = 0;
    if (policy_mode(policy_block(), &malformed) == POLICY_ASK && !policy_trusted) {
        if (call->tool_name && strcmp(call->tool_name, "read") == 0)
            return xstrdup("error: denied by policy: folder not trusted; reads are limited to it");
        return xstrdup("error: denied by policy: folder not trusted; restart hax here and answer "
                       "[t] or [a]");
    }
    return xasprintf("error: denied by policy: %s", call->tool_name ? call->tool_name : "tool");
}

/* --- dangerous commands ------------------------------------------------------------ */

struct dangerous_scan {
    const char **patterns;
    size_t count;
    int matched;
};

/* Match both the literal statement and the wrapper-stripped form, so `sudo rm` trips on either
 * `sudo` or `rm` no matter which one the operator listed. */
static int dangerous_visit(const char *statement, size_t length, void *user)
{
    struct dangerous_scan *scan = user;
    for (size_t i = 0; i < scan->count && !scan->matched; i++) {
        if (statement_matches_with(statement, length, scan->patterns[i], 0) ||
            statement_matches_with(statement, length, scan->patterns[i], 1))
            scan->matched = 1;
    }
    return 1;
}

char *policy_call_detail(const struct item *call)
{
    if (!call || call->kind != ITEM_TOOL_CALL || !call->tool_name)
        return NULL;
    if (strcmp(call->tool_name, "bash") == 0)
        return arg_string(call->tool_arguments_json, "command");
    if (is_path_tool(call->tool_name))
        return arg_string(call->tool_arguments_json, "path");
    return call->tool_arguments_json ? xstrdup(call->tool_arguments_json) : NULL;
}

int policy_is_dangerous(const struct item *call)
{
    const json_t *block = policy_block();
    if (!block || !call || call->kind != ITEM_TOOL_CALL || !call->tool_name)
        return 0;
    if (strcmp(call->tool_name, "bash") != 0)
        return 0;
    char *command = arg_string(call->tool_arguments_json, "command");
    if (!command)
        return 0;
    size_t count = 0;
    const json_t *bash = json_object_get(block, "bash");
    const char **patterns = string_array(json_object_get(bash, "dangerous_commands"), &count);
    int dangerous = 0;
    if (patterns) {
        struct dangerous_scan scan = {.patterns = patterns, .count = count};
        bash_for_each_statement(command, dangerous_visit, &scan);
        dangerous = scan.matched;
        free(patterns);
    }
    free(command);
    return dangerous;
}
