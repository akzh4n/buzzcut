---
description: Cut secrets out of Claude Code and Codex logs, with a mandatory backup
---

Always start with a dry run:

`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/buzzcut.py" clean --dry-run`

Show how many occurrences and files would be touched, and wait for the user to confirm. Only then run it without `--dry-run`.

Arguments, if the user asked to limit the scope:
- `--project <name>` — one project only (substring match)
- `--backup <path>` — where to put the copies (default `~/.buzzcut-backup`)

Codex logs and the copies in Codex's databases are cleaned with masks of the same length, and only while no process holds them. If clean says Codex is running, tell the user to quit Codex completely and run it again.

The backup still holds the keys: tell the user to delete it once they've checked that everything works.

What the user needs to hear: cleaning removes the values from the history, but it **does not undo the leak**. A key that reached a transcript should be treated as compromised and rotated. `/buzzcut:check` tells you which ones still matter.
