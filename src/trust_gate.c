/* SPDX-License-Identifier: MIT */
#include "trust_gate.h"

#include <stdlib.h>

#include "diag.h"
#include "policy.h"
#include "terminal/trust_prompt.h"
#include "trust_store.h"

void trust_gate_establish(void)
{
    if (!policy_trust_required())
        return;
    char *root = policy_workspace_root();
    if (!root)
        return;
    policy_set_workspace_root(root);
    if (trust_store_contains(root)) {
        policy_set_trusted(1);
    } else {
        enum trust_choice choice = trust_prompt(root);
        if (choice == TRUST_ALWAYS && trust_store_add(root) != 0)
            hax_err("could not record folder trust in the state directory");
        policy_set_trusted(choice != TRUST_NO);
    }
    free(root);
}
