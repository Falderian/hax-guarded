/* SPDX-License-Identifier: MIT */
#include "trust_store.h"

#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "system/fs.h"
#include "system/path.h"
#include "xalloc.h"

static char *trust_path(void)
{
    return xdg_hax_state_path("trust.json");
}

static char *strip_trailing_slashes(const char *path)
{
    size_t length = strlen(path);
    while (length > 1 && path[length - 1] == '/')
        length--;
    char *out = xmalloc(length + 1);
    memcpy(out, path, length);
    out[length] = '\0';
    return out;
}

static json_t *load_trust(void)
{
    char *path = trust_path();
    if (!path)
        return json_object();
    size_t length = 0;
    char *body = fs_read_file(path, &length);
    free(path);
    if (!body)
        return json_object();
    json_error_t error;
    json_t *root = json_loads(body, 0, &error);
    free(body);
    if (!json_is_object(root)) {
        if (root)
            json_decref(root);
        return json_object();
    }
    return root;
}

int trust_store_contains(const char *root)
{
    if (!root || !*root)
        return 0;
    char *normalized = strip_trailing_slashes(root);
    json_t *store = load_trust();
    json_t *list = json_object_get(store, "trusted");
    int found = 0;
    size_t index;
    json_t *entry;
    json_array_foreach(list, index, entry)
    {
        if (!json_is_string(entry))
            continue;
        char *candidate = strip_trailing_slashes(json_string_value(entry));
        found = strcmp(candidate, normalized) == 0;
        free(candidate);
        if (found)
            break;
    }
    json_decref(store);
    free(normalized);
    return found;
}

int trust_store_add(const char *root)
{
    if (!root || !*root)
        return -1;
    char *normalized = strip_trailing_slashes(root);
    json_t *store = load_trust();
    json_t *list = json_object_get(store, "trusted");
    if (!json_is_array(list)) {
        json_object_set_new(store, "trusted", json_array());
        list = json_object_get(store, "trusted");
    }
    if (!trust_store_contains(normalized))
        json_array_append_new(list, json_string(normalized));

    char *dump = json_dumps(store, JSON_INDENT(2) | JSON_SORT_KEYS);
    json_decref(store);
    if (!dump) {
        free(normalized);
        return -1;
    }
    char *path = trust_path();
    if (!path) {
        free(dump);
        free(normalized);
        return -1;
    }
    int result = 0;
    char *parent = xstrdup(path);
    char *slash = strrchr(parent, '/');
    if (slash) {
        *slash = '\0';
        result = fs_mkdir_p(parent);
    }
    free(parent);
    if (result == 0) {
        size_t length = strlen(dump);
        char *body = xasprintf("%s\n", dump);
        result = fs_write_atomic(path, body, length + 1, 1);
        free(body);
    }
    free(path);
    free(dump);
    free(normalized);
    return result;
}
