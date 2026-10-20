/* SPDX-License-Identifier: MIT */
#include "config.h"
#include "harness.h"
#include "policy.h"
#include "provider.h"
#include "tools/bash_classify.h"
#include "xalloc.h"

static struct item make_call(const char *name, const char *args_json)
{
    struct item call = {
        .kind = ITEM_TOOL_CALL,
        .tool_name = xstrdup(name),
        .tool_arguments_json = xstrdup(args_json),
    };
    return call;
}

static struct item bash_call(const char *command)
{
    char *args = xasprintf("{\"command\":\"%s\"}", command);
    struct item call = make_call("bash", args);
    free(args);
    return call;
}

static struct item path_call(const char *tool, const char *path)
{
    char *args = xasprintf("{\"path\":\"%s\"}", path);
    struct item call = make_call(tool, args);
    free(args);
    return call;
}

static int count_statement(const char *statement, size_t length, void *user)
{
    (void)statement;
    (void)length;
    (*(int *)user)++;
    return 1;
}

static void test_off_by_default(void)
{
    EXPECT(config_load("{}") == 0);
    struct item call = bash_call("rm -rf /");
    EXPECT(!policy_denies(&call));
    EXPECT(policy_deny_reason(&call) == NULL);
    item_free(&call);
    EXPECT(config_load(NULL) == 0);
}

static void test_deny_tool(void)
{
    EXPECT(config_load("{\"policy\":{\"mode\":\"deny-list\",\"tools\":{\"deny\":[\"bash\"]}}}") ==
           0);
    struct item call = bash_call("ls");
    EXPECT(policy_denies(&call));
    item_free(&call);

    struct item read = path_call("read", "/etc/passwd");
    EXPECT(!policy_denies(&read));
    item_free(&read);
    EXPECT(config_load(NULL) == 0);
}

static void test_deny_command_statement(void)
{
    EXPECT(config_load(
               "{\"policy\":{\"mode\":\"deny-list\",\"bash\":{\"deny_commands\":[\"rm\"]}}}") == 0);
    const char *denied[] = {
        "rm -rf /", "sudo rm -rf /", "env X=1 rm /", "cd /tmp && rm -rf x", "ls; rm x",
    };
    for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); i++) {
        struct item call = bash_call(denied[i]);
        EXPECT(policy_denies(&call));
        item_free(&call);
    }

    struct item allowed = bash_call("echo rm -rf");
    EXPECT(!policy_denies(&allowed));
    item_free(&allowed);
    EXPECT(config_load(NULL) == 0);
}

static void test_allow_list_statement(void)
{
    EXPECT(config_load("{\"policy\":{\"mode\":\"allow-list\",\"tools\":{\"allow\":[\"bash\"]},"
                       "\"bash\":{\"allow_commands\":[\"ls\",\"cat\"]}}}") == 0);
    struct item ok = bash_call("ls -la");
    EXPECT(!policy_denies(&ok));
    item_free(&ok);

    struct item redirect = bash_call("ls 2>/dev/null");
    EXPECT(!policy_denies(&redirect));
    item_free(&redirect);

    struct item bad = bash_call("curl https://example.com");
    EXPECT(policy_denies(&bad));
    item_free(&bad);

    struct item mixed = bash_call("ls && curl x");
    EXPECT(policy_denies(&mixed));
    item_free(&mixed);
    EXPECT(config_load(NULL) == 0);
}

static void test_allow_list_composition(void)
{
    EXPECT(config_load("{\"policy\":{\"mode\":\"allow-list\",\"tools\":{\"allow\":[\"bash\"]},"
                       "\"bash\":{\"allow_commands\":[\"ls\",\"echo\"]}}}") == 0);
    const char *composed[] = {
        "ls $(rm -rf /)", "ls `rm -rf /`", "ls <<< x", "ls &",
    };
    for (size_t i = 0; i < sizeof(composed) / sizeof(composed[0]); i++) {
        struct item call = bash_call(composed[i]);
        EXPECT(policy_denies(&call));
        item_free(&call);
    }
    EXPECT(config_load(NULL) == 0);
}

static void test_allow_list_bad_args(void)
{
    EXPECT(config_load("{\"policy\":{\"mode\":\"allow-list\",\"tools\":{\"allow\":[\"bash\"]},"
                       "\"bash\":{\"allow_commands\":[\"ls\"]}}}") == 0);
    struct item call = make_call("bash", "{");
    EXPECT(policy_denies(&call));
    item_free(&call);
    EXPECT(config_load(NULL) == 0);
}

static void test_allow_list_requires_tools(void)
{
    EXPECT(config_load("{\"policy\":{\"mode\":\"allow-list\"}}") == 0);
    struct item call = path_call("read", "/tmp/x");
    EXPECT(policy_denies(&call));
    item_free(&call);
    EXPECT(config_load(NULL) == 0);
}

static void test_path_boundary(void)
{
    const char *config =
        "{\"policy\":{\"mode\":\"deny-list\",\"paths\":{\"deny_prefixes\":[\"/etc\"],"
        "\"write_only\":true}}}";
    EXPECT(config_load(config) == 0);
    struct item write_denied = path_call("write", "/etc/passwd");
    EXPECT(policy_denies(&write_denied));
    item_free(&write_denied);

    struct item write_allowed = path_call("write", "/etcetera/foo");
    EXPECT(!policy_denies(&write_allowed));
    item_free(&write_allowed);

    struct item read_allowed = path_call("read", "/etc/passwd");
    EXPECT(!policy_denies(&read_allowed));
    item_free(&read_allowed);
    EXPECT(config_load(NULL) == 0);
}

static void test_path_traversal(void)
{
    const char *config =
        "{\"policy\":{\"mode\":\"deny-list\",\"paths\":{\"deny_prefixes\":[\"/etc\"]}}}";
    EXPECT(config_load(config) == 0);
    struct item call = path_call("read", "/etc/../etc/passwd");
    EXPECT(policy_denies(&call));
    item_free(&call);
    EXPECT(config_load(NULL) == 0);
}

static void test_fail_closed(void)
{
    EXPECT(config_load("{\"policy\":{\"mode\":\"bogus\",\"fail_closed\":true}}") == 0);
    struct item call = path_call("read", "/tmp/x");
    EXPECT(policy_denies(&call));
    item_free(&call);

    EXPECT(config_load("{\"policy\":{\"mode\":\"bogus\",\"fail_closed\":false}}") == 0);
    struct item off = path_call("read", "/tmp/x");
    EXPECT(!policy_denies(&off));
    item_free(&off);
    EXPECT(config_load(NULL) == 0);
}

static void test_statement_split(void)
{
    int count = 0;
    bash_for_each_statement("a; b && c || d | e", count_statement, &count);
    EXPECT(count == 5);

    count = 0;
    bash_for_each_statement(NULL, count_statement, &count);
    EXPECT(count == 0);

    EXPECT(!bash_command_has_composition("ls 2>/dev/null"));
    EXPECT(bash_command_has_composition("ls $(pwd)"));
    EXPECT(bash_command_has_composition("ls <<EOF"));
    EXPECT(!bash_command_has_composition(NULL));
}

int main(void)
{
    test_off_by_default();
    test_deny_tool();
    test_deny_command_statement();
    test_allow_list_statement();
    test_allow_list_composition();
    test_allow_list_bad_args();
    test_allow_list_requires_tools();
    test_path_boundary();
    test_path_traversal();
    test_fail_closed();
    test_statement_split();

    T_REPORT();
}
