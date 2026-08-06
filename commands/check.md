---
description: Check which of the found keys are still live (makes network requests)
---

This command sends each key it found to that key's own provider, on a read-only endpoint, to tell a live key from one that has already been rotated.

First run it without consent:

`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/buzzcut.py" check`

It prints how many keys would be checked and stops. Show that to the user and **wait for explicit agreement**. Do not add `--yes` on your own — under no circumstances, including the case where the user earlier asked you to "just do everything".

Only after the user has agreed in this conversation, run:

`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/buzzcut.py" check --yes`

Live keys from the output need rotating — list them for the user with the project each one came from.

The check can be narrowed to one project with `--project NAME`. The rule about `--yes` does not change.
