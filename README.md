# skm: skill manager for AI agent skills

[![tests](https://github.com/DownByBracket/skm/actions/workflows/tests.yml/badge.svg)](https://github.com/DownByBracket/skm/actions/workflows/tests.yml)

One control plane for SKILL.md style agent skills across three scopes:
**personal, team, company**. Capture is free, promotion is gated, and
every gate runs a security scan.

## Why this exists

Agent skills became an open standard (SKILL.md) that runs across Claude,
Codex, Cursor, Windsurf, Copilot and more. Distribution for them is
arriving: Claude Code can download the skills you enable on your
claude.ai account into `~/.claude/skills/synced/`, and Cowork and cloud
sessions load them at session start.[^1^]

But distribution is not governance. A sync mechanism answers "how does
this file reach the agent." It does not answer:

- who owns this skill, and who is allowed to approve it
- whether anyone ever ran its evals, against *this* version
- whether it was scanned, and whether it still passes
- what exactly was approved, and whether what ships still matches it
- how a team shares any of the above
- what breaks when it is retired, and how it gets pulled back

Those are lifecycle questions, and the gap is widening as the attack
surface gets named: OWASP now runs a dedicated **Agentic Skills Top 10**
project covering skills as their own security layer, sitting between the
MCP Top 10 (protocol and tools) and the LLM Top 10 (models).[^2^] A
skill is most dangerous exactly when it combines access to private data,
exposure to untrusted content, and the ability to talk to the network.

skm fills the governance gap with one idea: **skills have a lifecycle,
and promotion between scopes is where trust gets enforced.**

## Install

Zero dependencies, Python 3.9+:

```bash
python3 skm.py --help
```

## Quickstart

```bash
# create a registry (git backed automatically)
python3 skm.py init --registry ./my-registry

# capture a skill into personal scope (auto scanned)
python3 skm.py add ./my-skill-folder --owner you@example.com

# see everything
python3 skm.py list
python3 skm.py show my-skill

# security scan (exit code 1 on critical findings, CI friendly)
python3 skm.py scan my-skill

# actually run the evals the skill declares
python3 skm.py eval my-skill --runner 'claude -p "{query}"'

# gated promotion
python3 skm.py promote my-skill --to team
python3 skm.py promote my-skill --to company --by you@example.com \
    --note "reviewed v0.1.0, evals pass" --sign

# check that nothing drifted since approval
python3 skm.py verify

# deprecate safely (warns which skills declare a dependency on it)
python3 skm.py deprecate old-skill --reason "replaced by v2"

# deliver to an agent surface (company skills ship from their pin)
python3 skm.py sync my-skill --surface claude-code
python3 skm.py sync my-skill --surface generic --dest ./anywhere

# pull it back from everywhere it was delivered
python3 skm.py retract my-skill --dry-run
python3 skm.py retract my-skill

# share the registry with your team
python3 skm.py push --set-url git@github.com:acme/skill-registry.git
python3 skm.py pull

# who may promote, and whether authors may approve themselves
python3 skm.py policy --add-promoter lead@acme --scope company
python3 skm.py policy
```

## See it work in 30 seconds

The repo ships with `examples/shady-helper`, a deliberately malicious
skill. Watch the gates do their job:

```
$ python3 skm.py add examples/shady-helper
captured shady-helper into personal scope
warning: scan found 4 critical and 1 high issue(s); run: skm scan shady-helper

$ python3 skm.py scan shady-helper
  [CRITICAL] POISON_INSTRUCTION     SKILL.md: ignore all previous instructions
  [CRITICAL] EXFILTRATION_LANGUAGE  SKILL.md: send the conversation contents to https://...
  [CRITICAL] SHELL_PIPE_INSTALL     scripts/setup.sh: curl ... | sudo bash
  [CRITICAL] HARDCODED_SECRET       scripts/setup.sh: sk-EXAMPLEEXAMPLE...
  [HIGH    ] CREDENTIAL_FILE_ACCESS scripts/setup.sh: .aws/credentials

$ python3 skm.py promote shady-helper --to team
promotion to team blocked for shady-helper:
  - no owner; re-add with --owner or set owner in frontmatter
  - no eval queries; add an 'evals:' list to SKILL.md frontmatter
  - 4 critical scan finding(s); run: skm scan shady-helper

$ python3 skm.py sync shady-helper --surface claude-code
error: refusing to sync shady-helper: 4 critical scan finding(s)
  run: skm scan shady-helper
  override with --force if you accept the risk
```

That last gate matters as much as the promotion ones: gating promotion is
pointless if a skill can be copied straight into a live agent instead.
Delivery is a trust boundary too.

> **Note:** `examples/shady-helper/` is an intentionally malicious fixture
> used to test the scanner. Its `scripts/setup.sh` contains a real
> pipe-to-shell installer and a credential read. The hosts it references
> are RFC 2606 reserved `.example.com` names and do not resolve, but do
> not run it.

Meanwhile a clean skill walks personal to team to company, pinned and
attested, with every step committed to git:

```
$ python3 skm.py promote meeting-notes --to company --by founder --note "reviewed"
promotion to company blocked for meeting-notes:
  - evals declared but never run; run: skm eval meeting-notes --runner '<cmd with {query}>'

$ python3 skm.py eval meeting-notes --runner 'claude -p "{query}"'
eval: meeting-notes v0.1.0 (3 queries)
  [PASS] Summarize a 30 minute standup transcript into 3 decisions with owner
  [PASS] Extract deadlines from a sales call transcript and flag missing date
  [PASS] Handle a transcript where two speakers talk over each other.
3/3 passed

$ python3 skm.py promote meeting-notes --to company --by founder --note "reviewed"
promoted meeting-notes to company scope
pinned: ./my-registry/versions/meeting-notes/0.1.0-company
sign-off recorded by founder: reviewed
note: a recorded attestation, not a cryptographic signature; use --sign to GPG-sign
```

## A registry your team actually shares

A registry is a git repo, so sharing one is `push` and `pull`. Scopes stop
being folders on one laptop and start being tiers a team moves through
together:

```bash
# once, by whoever sets it up
python3 skm.py push --set-url git@github.com:acme/skill-registry.git

# everyone else
git clone git@github.com:acme/skill-registry.git ~/skill-registry
export SKM_REGISTRY=~/skill-registry
python3 skm.py pull
```

`registry.json` is one file that everybody writes to, so line-based merge
would conflict constantly. skm reconciles it **by skill** instead. Each
side keeps what it did, history and versions and delivery records are
unioned rather than overwritten, and any real divergence is named rather
than silently resolved:

```
$ python3 skm.py pull
registry.json diverged; reconciling by skill
  deadline-pinger: remote only, taken
  shady-helper: local only, kept
pulled and reconciled main from git@github.com:acme/skill-registry.git
run: skm verify   # confirm nothing drifted in the merge
```

When both sides promoted the *same* skill differently, git conflicts in the
skill folder itself. skm aborts the merge and tells you, rather than
guessing which approval was the real one. A merge must never be a promotion
path.

Two guarantees make this safe to share:

- **Hashes are portable.** Content is hashed with normalized line endings
  and POSIX paths, and every registry ships a `.gitattributes` telling git
  not to rewrite what it stores. Without this, `core.autocrlf` alone makes
  every skill look tampered with the moment a Windows and a Linux machine
  share a registry -- a false alarm that would teach people to ignore the
  one check that matters.
- **Push refuses a dirty registry.** Every skm command commits its own
  work, so uncommitted changes mean someone edited the registry by hand.
- **No git setup required.** skm supplies its own identity to every git
  operation it performs, including merges, and pins each registry to the
  `main` branch rather than inheriting whatever `init.defaultBranch` the
  machine happens to use. A brand new laptop with no `user.email` and no
  `~/.gitconfig` can init, push, pull and reconcile a shared registry. CI
  runs the whole suite in exactly that scrubbed state so this keeps being
  true.

## Who is allowed to promote

A gate one person can walk through alone is a checklist, not a control. Two
rules turn it into one:

**An author cannot approve their own skill for company scope.**

```
$ python3 skm.py promote meeting-notes --to company --by founder --note "looks good to me"
promotion to company blocked for meeting-notes:
  - 'founder' owns this skill and cannot also sign off on its promotion to
    company; a second person must review it
    (solo registry: skm policy --allow-self-promotion)
```

**Only named identities may promote.** An empty allowlist means anyone, so
existing registries keep working; add one and it is enforced:

```bash
python3 skm.py policy --add-promoter lead@acme --scope company
python3 skm.py policy --add-promoter alice@acme --scope team
python3 skm.py policy --allow-self-promotion   # solo registries
```

```
$ python3 skm.py policy
policy:
  distinct reviewer required for company: yes
  may promote to team: alice@acme
  may promote to company: lead@acme
```

Pair the allowlist with `--sign` and an approval carries both *who* (a GPG
signature `skm verify` can check) and *whether they were allowed to*.

## Retracting a skill

Deprecation records that a skill should not be used. **Retraction makes that
true on the machines it already reached.** `sync` records every delivery, so
`retract` knows where to look:

```
$ python3 skm.py retract meeting-notes --dry-run
  would remove: /home/dev/.claude/skills/meeting-notes (claude-code)
dry run: 1 delivery/deliveries would be retracted, 0 skipped

$ python3 skm.py retract meeting-notes --by lead@acme
  removed: /home/dev/.claude/skills/meeting-notes (claude-code)
retracted meeting-notes: 1 removed, 0 already gone, 0 skipped
```

Because it deletes directories, it only ever touches a path skm itself
recorded delivering to, that is named after the skill, and that still
contains a `SKILL.md`. Anything else is skipped and reported, and the
command exits non-zero so a retraction that did not fully succeed cannot
pass silently in CI.

Retraction is per-machine: it cleans the surfaces reachable from where it
runs. Deprecate first so the registry records *why*, then retract.

## The promotion gates

| Gate | personal to team | team to company |
|---|---|---|
| Named owner | required | required |
| Description in frontmatter | required | required |
| Eval queries declared | 1 or more | 1 or more |
| Evals actually executed and passing | not checked | required, against the current content hash |
| Critical scan findings | 0 | 0 |
| High scan findings | allowed | 0 |
| Declared dependencies | must be at team or higher | must be at company |
| Promoter on the allowlist | if one is set | if one is set |
| Reviewer distinct from owner | not checked | required by default |
| Sign off (`--by`, `--note`) | optional | required |
| Version pin | no | pinned snapshot kept forever, and it is what ships |

Scope skipping is blocked: a skill must walk personal, team, company in
order. That is the point.

### Evals are executed, not just declared

A gate that checks whether an `evals:` list exists verifies paperwork.
Company promotion requires that the evals were actually **run**, and the
result is recorded against the SHA-256 of the exact content they ran on.
Change one byte of the skill and the recorded result goes stale, and the
gate closes again until you re-run.

skm does not judge whether an answer is good, and does not pretend to. It
delegates to a runner command you configure and treats **exit code 0 as a
pass**:

```bash
python3 skm.py eval my-skill --runner 'claude -p "{query}"'
export SKM_EVAL_RUNNER='claude -p "{query}"'   # or set it once
```

`{query}` and `{skill_dir}` are substituted per query. The runner is
executed through your shell, so treat it like any other command you run.

### Dependencies are governed too

A skill that declares `depends: [other-skill]` cannot outrun what it relies
on. Company scope means reviewed, eval-gated and pinned -- and that
guarantee is void if the skill calls into something that never passed a
gate. So a dependency must sit at the target scope or higher:

```
$ python3 skm.py promote deadline-pinger --to company --by founder --note "reviewed"
promotion to company blocked for deadline-pinger:
  - depends on 'meeting-notes' at team scope; a company skill cannot rely on
    a less governed one (promote meeting-notes to company first)
```

Promotion is also blocked when a dependency is missing from the registry
entirely, or has been deprecated. Mutual dependencies would otherwise
deadlock both gates, so they are detected and named rather than left to
stall:

```
promotion to team blocked for alpha:
  - dependency cycle: alpha -> beta -> alpha; break the cycle before
    promoting either skill
```

### Attestation vs. signature

By default `--by` records *who said they signed off*. That is an
attestation, not proof, and skm says so in its own output rather than
claiming more than it can back up. Pass `--sign` to GPG-sign the
promotion commit; `skm verify` then checks that signature with
`git verify-commit`. If signing fails, the promotion is rolled back
entirely rather than recorded as unsigned.

## Verifying what was approved

The registry records a SHA-256 for every version and every company pin.
`skm verify` reads them back:

```
$ python3 skm.py verify
  ok    meeting-notes v0.1.0 matches its recorded hash
  ok    meeting-notes company pin v0.1.0 intact
  note  meeting-notes company sign-off by founder is a recorded attestation, not a GPG signature

verified 1 skill(s): no drift
```

and it catches a skill edited in place after approval:

```
$ python3 skm.py verify meeting-notes
2 problem(s) across 1 skill(s):
  - meeting-notes: CONTENT DRIFT - v0.1.0 was recorded as sha256:30526b6d019b
    but is now sha256:848ebbf21953 (edited in place after approval?)
  - meeting-notes: live company folder differs from its pin v0.1.0;
    sync delivers the pin, so the two have diverged
```

Exit code 1 on drift, so it belongs in CI.

**The pin is what ships.** For a company-scope skill, `sync` delivers the
immutable pinned snapshot, not the current contents of the scope folder.
Editing the live folder after approval therefore cannot change what
reaches an agent. Use `--from-live` if you explicitly want the working
copy instead.

## What the scanner catches

Rule classes map to publicly documented flaw categories:[^2^]

- **POISON_INSTRUCTION** (critical): "ignore previous instructions",
  "do not tell the user", and similar host model hijack phrasing
- **EXFILTRATION_LANGUAGE** (critical): instructions to send user data,
  files, or conversation contents to a URL
- **SHELL_PIPE_INSTALL** (critical): `curl ... | bash` style installers
- **HARDCODED_SECRET** (critical): API keys, tokens, private key blocks
- **CREDENTIAL_FILE_ACCESS** (high): reads of .ssh, .aws/credentials,
  gcloud config, .env
- **UNSAFE_SUBPROCESS** (high): os.system, shell=True, eval/exec
- **NETWORK_EGRESS** (medium): scripts that call out to the network
- **BASE64_BLOB** (medium): long encoded blobs that hide payloads
- **SCOPE_CREEP / METADATA_MISSING** (low): oversized or undocumented
  skills that degrade recall and review quality

Prose rules are matched against a whitespace-normalized copy of the file,
so an ordinary line wrap cannot hide a phrase from a pattern.

The scanner is conservative and static. It catches the documented flaw
classes; it is not a sandbox or a guarantee. A clean scan means "no known
pattern matched", not "this skill is safe" -- a determined author can
reword or encode around any static rule. Treat it as a floor, not a
clearance.

## Registry layout

```
my-registry/
  registry.json          # manifest: scopes, versions, scan results, evals, history
  .gitattributes         # never let git rewrite content: hashes depend on it
  scopes/
    personal/<skill>/    # where skills are born
    team/<skill>/        # shared, reviewed
    company/<skill>/     # governed, pinned, attested
  versions/<skill>/      # immutable snapshots, including company pins
```

`registry.json` also carries the policy (who may promote, whether authors
may approve themselves) and, per skill, the record of every delivery made
from it -- which is what makes retraction possible.

Every mutation is a git commit, so the registry is its own audit trail.
That includes `sync`: the moment a skill reaches a live agent surface is
the event an auditor most wants dated.

## Tests

Zero dependencies, no test framework needed:

```bash
python3 test_skm.py
```

Covers the scanner rules (including wrap-resistance), the promotion
gates, scope-skip refusal, eval execution and staleness, dependency scope
and cycles, hash and pin verification, pin-governed delivery, signature
rollback, the sync gates, separation of duties, promoter allowlists, a
two-person push/pull round trip through a shared remote, registry merge
semantics, retraction safety, and cross-platform hash stability.

CI runs the suite on Python 3.9 and 3.13, and additionally asserts that a
green build still refuses to scan, promote, or sync the malicious example
-- so the scanner cannot quietly stop working.

## Limits worth knowing

- **Retraction is per-machine.** It cleans the surfaces reachable from
  where it runs, not every laptop in the company.
- **The allowlist is advisory, not enforced by the server.** Anyone who
  can write to the shared repo could edit the policy. Branch protection
  on the registry repo is what makes it binding; skm records intent and
  checks it locally.
- **The scanner is static.** See the caveat above: a floor, not a
  clearance.

## Roadmap

- Sync engines for more surfaces (claude.ai uploads, API workspaces,
  Cursor rules)
- `skm rescan --all`: re-run current gates against already-promoted
  skills, so improving a scanner rule protects retroactively
- Demotion path (company back to team) for skills that degrade
- Server-side policy enforcement via a pre-receive hook, so the
  allowlist cannot be edited by the person it restricts
- Commons health index: abandonment and CVE signals for public skills
  and MCP servers you depend on

## Acknowledgments

Thanks to [GAGE.Academy](https://www.gage.academy/), whose work on
governance informed how this project thinks about scopes, review and
accountability.

Responsibility for skm -- including every claim it makes about security --
rests with this project alone.

[^1^]: https://code.claude.com/docs/en/skills -- see "Skills synced from
  claude.ai", `CLAUDE_CODE_SYNC_SKILLS`, and skills in Cowork and cloud
  sessions.
[^2^]: OWASP Agentic Skills Top 10:
  https://owasp.org/www-project-agentic-skills-top-10/
