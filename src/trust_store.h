/* SPDX-License-Identifier: MIT */
#ifndef HAX_TRUST_STORE_H
#define HAX_TRUST_STORE_H

/* Folders the operator answered "always" for, kept in <state>/hax/trust.json rather than
 * config.json so the auto-managed list never collides with hand edits or `/config`. */

/* Nonzero when the folder is already trusted. Trailing slashes are ignored. */
int trust_store_contains(const char *root);

/* Persist the folder. Returns 0 on success, -1 when the file cannot be written. */
int trust_store_add(const char *root);

#endif /* HAX_TRUST_STORE_H */
