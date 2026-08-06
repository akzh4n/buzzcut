---
description: Cut secrets out of the transcripts, with a mandatory backup
---

Always start with a dry run:

`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/buzzcut.py" clean --dry-run`

Show how many occurrences and files would be touched, and wait for the user to confirm. Only then run it without `--dry-run`.

Arguments, if the user asked to limit the scope:
- `--project <name>` — one project only (substring match)
- `--backup <path>` — where to put the copies (default `~/.claude/projects.buzzcut-backup`)

What the user needs to hear: cleaning removes the values from the history, but it **does not undo the leak**. A key that reached a transcript should be treated as compromised and rotated. `/buzzcut:check` tells you which ones still matter.
