/* SPDX-License-Identifier: MIT */
#ifndef HAX_TRUST_GATE_H
#define HAX_TRUST_GATE_H

/* Establish whether the current workspace folder is trusted. A folder recorded as trusted skips
 * the prompt; otherwise an interactive run asks once, and a non-interactive one stays untrusted.
 * Inert unless the policy mode is `ask`. */
void trust_gate_establish(void);

#endif /* HAX_TRUST_GATE_H */
