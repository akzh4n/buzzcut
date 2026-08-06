---
description: Find credentials left behind in Claude Code transcripts (read-only)
---

Run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/buzzcut.py" scan` and show the output to the user as it is.

The command only reads `~/.claude/projects` and changes nothing. It never prints key values — types, projects and counts only.

**The scan covers every project, not the current one.** That is deliberate: transcripts live globally, and a key leaked in a neighbouring project is just as live. If the user asks about one project, add `--project NAME` (substring match; worktrees come along with their parent project). A full pass over a large `~/.claude/projects` takes a couple of minutes.

Afterwards, if anything was found, briefly mention that `/buzzcut:check` (which of those keys still work) and `/buzzcut:clean` (cut them out of the files) exist. Do not run either of them yourself.
