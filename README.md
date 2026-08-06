<h1 align="center">buzzcut</h1>

<p align="center">
  <em>Your agent read <code>.env</code> once, six weeks ago.<br>It's still sitting on your disk in plaintext.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/akzh4n/buzzcut?style=flat-square&color=111111&label=stars" alt="Stars">
  <img src="https://img.shields.io/badge/tests-122-111111?style=flat-square" alt="122 tests">
  <img src="https://img.shields.io/badge/license-MIT-111111?style=flat-square" alt="MIT license">
  <img src="https://img.shields.io/badge/deps-none-111111?style=flat-square" alt="No dependencies">
</p>

<p align="center">
  <strong>116 live keys &middot; 1,065 occurrences &middot; 234 files</strong><br>
  <sub>Found on one working developer machine, accumulated over two months of normal use.
  Nobody pasted a key anywhere. The agent ran <code>cat .env</code> to debug something, and
  Claude Code wrote the output to disk — where it stays forever.
  <a href="#what-this-actually-found">Methodology</a>.</sub>
</p>

---

## The problem

Claude Code records every session to `~/.claude/projects/**/*.jsonl`. Everything a tool prints goes in — including the contents of any credential file the agent opened. `.gitignore` does not apply; this is not your repository.

Anthropic knows. Two issues report it with real incidents — [#58043](https://github.com/anthropics/claude-code/issues/58043) (a `PINECONE_API_KEY` leaked during routine debugging) and [#59094](https://github.com/anthropics/claude-code/issues/59094) (live brokerage credentials leaked *despite* an explicit project rule forbidding it).

**Both are closed as `not planned`.** Labels: `area:security`, `stale`. Remediation is your problem.

## Install

```
/plugin marketplace add akzh4n/buzzcut
/plugin install buzzcut@buzzcut
```

Just want to look first? Nothing is installed, nothing is modified:

```
npx buzzcut scan
```

## What it does

| | |
|---|---|
| `/buzzcut:scan` | Reports what's in your transcripts. Read-only. Never prints key values — types, projects and counts only, so you can paste the output into a ticket |
| `/buzzcut:check` | **Which of those keys still work.** Asks each provider over a read-only endpoint. Network access, explicit consent required |
| `/buzzcut:clean` | Cuts the values out of the files. Mandatory backup, `--dry-run` first |
| hook | Redacts secrets from tool output *before the model sees them* — so they never reach the context or the disk |

## The part nobody else does

Every other tool stops at *"this string looks like a key."*

That's the wrong end of the problem. **1,065 matches** is noise you scroll past. **"Three keys an attacker could use right now"** is an incident you act on. `buzzcut check` asks the provider.

```
  LIVE — rotate now
    OpenAI          sk-pro…Xe4     flowly
    GitHub PAT      ghp_4m…kM2     flowly

  DEAD — 20, already rotated, just clean them out

  YOUR CALL — 91
    private key, database URLs, internal service secrets
```

## Before / after

```
⏺ Bash(cat backend/.env)
  ⎿  NODE_ENV=production
     DATABASE_URL=postgres://flowly:***REDACTED by buzzcut***@10.0.0.4/prod
     OPENAI_API_KEY=***REDACTED by buzzcut: openai***

  ✂ buzzcut: 2 secrets cut from Bash output
```

The command still ran. The agent got the file it asked for, minus the values. It does not start debugging a "broken" command — which is what happens when a tool rewrites the command itself with a `sed` filter instead of editing the result.

## What this actually found

Numbers above come from a real machine: 4,306 transcripts, 1.9 GB, roughly two months of daily agent use across seven projects.

A naive scanner reports **1,585** hits on that data. That number is a lie: 60% of it is `PYTHONPATH=/a/b`, `HEAD=<sha>`, `WT=/path/DEV-604` — shell variables holding paths and git refs. A redaction hook that cuts those breaks your agent on every step.

buzzcut gates `ENV`-shaped findings on the *variable name*, which drops the count to **1,061 across 116 unique keys** — and what survives is `POSTGRES_PASSWORD`, `TIKTOK_CLIENT_SECRET`, `COOKIES_ENCRYPTION_KEY`, `ALTEGIO_WEBHOOK_TOKEN`. Real ones.

False positives cost more than misses here, so the test suite has more cases asserting what must **not** be cut than what must.

## Limits

- **Cleaning does not un-leak anything.** A key that reached a transcript is compromised. Rotate it. `check` tells you which ones still matter.
- AWS, Google API keys, database URLs and internal secrets are **not** probed automatically — that needs request signing or a connection to your own production. Those are listed for you to judge.
- The detector is a heuristic. It does not replace `gitleaks` on your repo; it covers a surface `gitleaks` never looks at.

## Development

```
python3 -m pytest tests/ -q     # 122 tests, no dependencies
```

MIT.
