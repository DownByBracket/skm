#!/usr/bin/env python3
"""
skm: a skill manager for AI agent skills.

One control plane for SKILL.md style agent skills across three scopes:
personal, team, company. Capture is free, promotion is gated, and every
gate runs a security scan, because recent audits keep finding that a
large share of public skills carry real flaws.

Zero dependencies, Python 3.9+, Git optional (used for history when the
registry is a git repo).
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

SCOPES = ["personal", "team", "company"]
REGISTRY_FILE = "registry.json"

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Frontmatter (minimal YAML subset: scalars and dash lists)
# ---------------------------------------------------------------------------

def parse_frontmatter(text):
    meta = {}
    body = text
    if not text.startswith("---"):
        return meta, body
    end = text.find("\n---", 3)
    if end == -1:
        return meta, body
    raw = text[3:end].strip("\n")
    body = text[end + 4:].lstrip("\n")
    current_key = None
    for line in raw.splitlines():
        if re.match(r"^\s+-\s+", line):
            if current_key is not None:
                if not isinstance(meta.get(current_key), list):
                    meta[current_key] = []
                meta[current_key].append(re.sub(r"^\s+-\s+", "", line).strip())
            continue
        m = re.match(r"^([A-Za-z0-9_\-]+):\s*(.*)$", line)
        if m:
            current_key = m.group(1)
            value = m.group(2).strip()
            meta[current_key] = value if value else []
    return meta, body


def parse_list(value):
    """Accept a dash list (already a list) or an inline '[a, b]' string."""
    if isinstance(value, list):
        return [v for v in value if v]
    if isinstance(value, str):
        v = value.strip()
        if v.startswith("[") and v.endswith("]"):
            inner = v[1:-1].strip()
            return [x.strip().strip("'\"") for x in inner.split(",") if x.strip()]
        if v:
            return [v]
    return []


def sanitize_name(name):
    name = name.strip().lower().replace(" ", "-").replace("_", "-")
    name = re.sub(r"[^a-z0-9\-]", "", name)
    name = re.sub(r"\-+", "-", name).strip("-")
    return name or "unnamed-skill"


# ---------------------------------------------------------------------------
# Registry storage
# ---------------------------------------------------------------------------

def registry_path(root):
    return os.path.join(root, REGISTRY_FILE)


def require_registry(root):
    if not os.path.isfile(registry_path(root)):
        print(f"error: no registry at {root} (run: skm init --registry {root})")
        sys.exit(2)


def load_registry(root):
    with open(registry_path(root), "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_registry(root, reg, commit_msg=None, sign=False):
    for info in reg.get("skills", {}).values():
        info.pop("_name", None)
    with open(registry_path(root), "w", encoding="utf-8") as fh:
        json.dump(reg, fh, indent=2, sort_keys=False)
        fh.write("\n")
    if commit_msg:
        return git_commit(root, commit_msg, sign=sign)
    return None


def git_commit(root, msg, sign=False):
    """Commit the registry. Returns the commit sha, or None if not committed.

    Raises RuntimeError when sign=True but signing fails, so a caller asking
    for a signature never silently records an unsigned promotion.
    """
    if not shutil.which("git"):
        if sign:
            raise RuntimeError("git not found; cannot sign")
        return None
    if not os.path.isdir(os.path.join(root, ".git")):
        if sign:
            raise RuntimeError(f"{root} is not a git repo; cannot sign")
        return None
    cmd = ["git", "-C", root, "-c", "user.name=skm",
           "-c", "user.email=skm@localhost", "commit", "-m", msg, "--quiet"]
    if sign:
        cmd.append("-S")
    try:
        subprocess.run(["git", "-C", root, "add", "-A"],
                       check=True, capture_output=True)
        subprocess.run(cmd, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or b"").decode("utf-8", "ignore").strip()
        if sign:
            raise RuntimeError(f"signed commit failed: {detail}")
        return None
    r = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"],
                       capture_output=True, text=True)
    return r.stdout.strip() or None


def git_verify_commit(root, sha):
    """Returns (ok, detail) for a commit's GPG signature."""
    if not shutil.which("git") or not sha:
        return False, "git unavailable"
    r = subprocess.run(["git", "-C", root, "verify-commit", sha],
                       capture_output=True, text=True)
    lines = (r.stderr or r.stdout or "").strip().splitlines()
    return r.returncode == 0, (lines[0] if lines else "")


def canonical_bytes(data):
    """Content as it means the same thing everywhere.

    Git rewrites line endings on checkout (core.autocrlf), so the same skill
    is different bytes on Windows and Linux. Hash the normalized text instead,
    or the raw bytes when the file is not text.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def hash_tree(path):
    """SHA-256 over a skill folder, stable across platforms and git configs."""
    h = hashlib.sha256()
    entries = []
    for base, dirs, files in os.walk(path):
        dirs.sort()
        for f in files:
            fp = os.path.join(base, f)
            # POSIX separators so a tree hashed on Windows matches Linux
            rel = os.path.relpath(fp, path).replace(os.sep, "/")
            entries.append((rel, fp))
    for rel, fp in sorted(entries):
        h.update(rel.encode("utf-8"))
        with open(fp, "rb") as fh:
            h.update(canonical_bytes(fh.read()))
    return h.hexdigest()


def scope_dir(root, scope, name):
    return os.path.join(root, "scopes", scope, name)


def skill_dir(root, info):
    return scope_dir(root, info["scope"], info["_name"])


def log_event(info, event, by, detail=""):
    info.setdefault("history", []).append({
        "event": event,
        "date": now_utc(),
        "by": by or info.get("owner") or "unknown",
        "detail": detail,
    })


def snapshot_version(root, name, version, src_dir, tag=None):
    label = version + (f"-{tag}" if tag else "")
    dest = os.path.join(root, "versions", name, label)
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    shutil.copytree(src_dir, dest)
    return dest


def pin_dir(root, info):
    """Where a company pin lives. Derived rather than read from stored state,
    so a registry stays valid after it is moved or cloned."""
    pin = info.get("company_pin")
    if not pin:
        return None
    return os.path.join(root, "versions", info["_name"],
                        pin["version"] + "-company")


def recorded_hash(info):
    """The hash recorded for the current version, or None."""
    for v in reversed(info.get("versions", [])):
        if v.get("version") == info.get("current_version"):
            return v.get("hash")
    return None


def bump_version(v):
    parts = v.split(".")
    if len(parts) >= 3 and all(p.isdigit() for p in parts[:3]):
        parts[2] = str(int(parts[2]) + 1)
        return ".".join(parts[:3])
    if len(parts) == 2 and all(p.isdigit() for p in parts):
        return v + ".1"
    return v + ".1"


# ---------------------------------------------------------------------------
# Security scanner
#
# Rule classes map to publicly documented flaw categories: prompt injection
# and tool poisoning inside instruction files, unsafe command execution and
# pipe-to-shell installers, hardcoded secrets, credential file access, and
# unexpected network egress. Metadata and size rules catch recall and
# governance problems rather than exploits.
# ---------------------------------------------------------------------------

SCRIPT_EXTS = {".py", ".sh", ".bash", ".js", ".ts", ".mjs", ".ps1", ".rb"}
DOC_EXTS = {".md", ".markdown", ".txt", ".rst"}

# (rule_id, severity, description, regex, file kinds: doc, script, any)
SCAN_RULES = [
    ("POISON_INSTRUCTION", "critical",
     "prompt injection phrasing aimed at the host model",
     r"(?i)(ignore (all |any |the )?(previous|prior|above) instructions|"
     r"do not (tell|inform|show|reveal to) (the )?user|"
     r"hide (this|these|the) (action|step|command)s? from the user)",
     "doc"),
    ("EXFILTRATION_LANGUAGE", "critical",
     "instructions to send user data or files to an external party",
     r"(?i)(exfiltrat\w+|send (the )?(user'?s? |all |any )?"
     r"(data|files?|contents?|conversation|history|tokens?|keys?) "
     r"\w*\s*to\s+https?://)",
     "doc"),
    ("SHELL_PIPE_INSTALL", "critical",
     "downloads a remote script and pipes it straight into a shell",
     r"(?i)(curl|wget)\s+[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b",
     "any"),
    ("HARDCODED_SECRET", "critical",
     "looks like a hardcoded credential or private key",
     r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|"
     r"xox[baprs]-[A-Za-z0-9\-]{10,}|"
     r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)",
     "any"),
    ("CREDENTIAL_FILE_ACCESS", "high",
     "reads local credential stores (ssh, aws, gcloud, env files)",
     r"(?i)(~/\.ssh|\.aws/credentials|\.config/gcloud|/(etc/)?shadow\b|"
     r"read\w*\s*\(\s*[\"'][^\"']*\.env[\"'])",
     "script"),
    ("UNSAFE_SUBPROCESS", "high",
     "shell execution primitives (os.system, shell=True, eval/exec)",
     r"(os\.system\s*\(|shell\s*=\s*True|\b(os\.)?popen\s*\(|"
     r"(?<!\.)\beval\s*\(|(?<!\.)\bexec\s*\()",
     "script"),
    ("NETWORK_EGRESS", "medium",
     "script reaches out to the network; verify the destination",
     r"https?://[^\s\"')]+",
     "script"),
    ("BASE64_BLOB", "medium",
     "long base64 blob can hide payloads from review",
     r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/=])",
     "any"),
]

SCOPE_CREEP_FILES = 30
SCOPE_CREEP_LINES = 400


def normalize_doc(text):
    """Collapse runs of whitespace in prose so that a rule cannot be defeated
    by an ordinary line wrap. SKILL.md files wrap at 72-80 columns as a matter
    of course, which would otherwise hide a phrase from a space-separated
    pattern (e.g. "send the
conversation contents to https://...")."""
    return re.sub(r"\s+", " ", text)


def classify_file(relpath):
    ext = os.path.splitext(relpath)[1].lower()
    if ext in SCRIPT_EXTS:
        return "script"
    if ext in DOC_EXTS:
        return "doc"
    return "other"


def scan_skill(path):
    """Static scan of one skill folder. Returns findings, counts, metadata."""
    findings = []
    skill_md = os.path.join(path, "SKILL.md")
    meta = {}
    file_count = 0
    md_lines = 0

    if os.path.isfile(skill_md):
        with open(skill_md, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
        meta, _ = parse_frontmatter(text)
        md_lines = text.count("\n") + 1
        if not meta.get("name"):
            findings.append({"severity": "low", "rule": "METADATA_MISSING",
                             "file": "SKILL.md",
                             "detail": "frontmatter has no name field"})
        if not meta.get("description"):
            findings.append({"severity": "low", "rule": "METADATA_MISSING",
                             "file": "SKILL.md",
                             "detail": "frontmatter has no description field"})
    else:
        findings.append({"severity": "high", "rule": "METADATA_MISSING",
                         "file": ".",
                         "detail": "no SKILL.md found; not a valid skill"})

    for base, dirs, files in os.walk(path):
        dirs.sort()
        for f in sorted(files):
            fp = os.path.join(base, f)
            rel = os.path.relpath(fp, path)
            file_count += 1
            kind = classify_file(rel)
            if kind == "other":
                continue
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue
            # Prose is matched against a whitespace-normalized copy so that
            # line wrapping cannot hide a phrase; scripts keep exact bytes.
            haystack = normalize_doc(content) if kind == "doc" else content
            for rule_id, severity, desc, pattern, applies in SCAN_RULES:
                if applies != "any" and applies != kind:
                    continue
                m = re.search(pattern, haystack)
                if m:
                    snippet = m.group(0)
                    if len(snippet) > 80:
                        snippet = snippet[:77] + "..."
                    findings.append({"severity": severity, "rule": rule_id,
                                     "file": rel,
                                     "detail": f"{desc}: {snippet}"})

    if file_count > SCOPE_CREEP_FILES or md_lines > SCOPE_CREEP_LINES:
        findings.append({"severity": "low", "rule": "SCOPE_CREEP",
                         "file": ".",
                         "detail": (f"{file_count} files, {md_lines} SKILL.md "
                                    f"lines; oversized skills degrade recall "
                                    f"and review quality")})

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f_ in findings:
        counts[f_["severity"]] += 1
    return {"date": now_utc(), "findings": findings,
            "counts": counts, "meta": meta}


def print_scan(scan, name):
    c = scan["counts"]
    print(f"scan: {name}  ({scan['date']})")
    print(f"  critical: {c['critical']}  high: {c['high']}  "
          f"medium: {c['medium']}  low: {c['low']}")
    if not scan["findings"]:
        print("  no findings")
        return
    for sev in SEVERITY_ORDER:
        for f_ in scan["findings"]:
            if f_["severity"] == sev:
                print(f"  [{sev.upper():8s}] {f_['rule']:22s} "
                      f"{f_['file']}: {f_['detail']}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(args):
    root = os.path.abspath(args.registry)
    os.makedirs(root, exist_ok=True)
    for scope in SCOPES:
        os.makedirs(os.path.join(root, "scopes", scope), exist_ok=True)
    os.makedirs(os.path.join(root, "versions"), exist_ok=True)
    if not os.path.isfile(registry_path(root)):
        save_registry(root, {"version": 1, "created": now_utc(),
                             "policy": json.loads(json.dumps(DEFAULT_POLICY)),
                             "skills": {}})
    # Registries are content addressed, so git must not rewrite what it
    # stores. This keeps working copies byte identical across machines.
    ga = os.path.join(root, ".gitattributes")
    if not os.path.isfile(ga):
        with open(ga, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("# skm registries are content addressed: never let git\n"
                     "# rewrite line endings, or hashes stop matching across\n"
                     "# machines.\n"
                     "* -text\n")

    if not args.no_git and shutil.which("git") and \
            not os.path.isdir(os.path.join(root, ".git")):
        try:
            subprocess.run(["git", "-C", root, "init", "--quiet"],
                           check=True, capture_output=True)
            git_commit(root, "skm: init registry")
        except subprocess.CalledProcessError:
            pass
    print(f"registry ready at {root}")
    print("scopes: personal -> team -> company (promotion is gated)")


def cmd_add(args):
    root = os.path.abspath(args.registry)
    require_registry(root)
    src = os.path.abspath(args.path)
    if not os.path.isfile(os.path.join(src, "SKILL.md")):
        print(f"error: {src} has no SKILL.md")
        sys.exit(2)

    with open(os.path.join(src, "SKILL.md"), "r", encoding="utf-8",
              errors="ignore") as fh:
        meta, _ = parse_frontmatter(fh.read())

    name = sanitize_name(args.name or str(meta.get("name") or
                         os.path.basename(src)))
    owner = args.owner or (meta.get("owner") if isinstance(meta.get("owner"), str)
                           else None)

    reg = load_registry(root)
    skills = reg.setdefault("skills", {})

    if name in skills:
        info = skills[name]
        info["_name"] = name
        old_version = info["current_version"]
        new_version = args.version or bump_version(old_version)
        snapshot_version(root, name, old_version, skill_dir(root, info))
        dest = skill_dir(root, info)
        shutil.rmtree(dest)
        shutil.copytree(src, dest)
        info["current_version"] = new_version
        if owner:
            info["owner"] = owner
        info["versions"].append({"version": new_version,
                                 "hash": hash_tree(dest), "date": now_utc()})
        log_event(info, "update", args.by,
                  f"{old_version} -> {new_version} (snapshot kept)")
        action = f"updated {name} {old_version} -> {new_version}"
    else:
        dest = scope_dir(root, "personal", name)
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        shutil.copytree(src, dest)
        info = {
            "scope": "personal",
            "owner": owner,
            "current_version": args.version or "0.1.0",
            "versions": [{"version": args.version or "0.1.0",
                          "hash": hash_tree(dest), "date": now_utc()}],
            "history": [],
            "deprecated": None,
        }
        log_event(info, "add", args.by, "captured into personal scope")
        skills[name] = info
        action = f"captured {name} into personal scope"

    scan = scan_skill(dest)
    info["scan"] = {"date": scan["date"], "counts": scan["counts"],
                    "findings": scan["findings"][:50]}
    save_registry(root, reg, commit_msg=f"skm: {action}")
    print(action)
    c = scan["counts"]
    if c["critical"] or c["high"]:
        print(f"warning: scan found {c['critical']} critical and "
              f"{c['high']} high issue(s); run: skm scan {name}")
    elif c["medium"] or c["low"]:
        print(f"note: scan found {c['medium']} medium and {c['low']} low "
              f"issue(s); run: skm scan {name}")


def cmd_list(args):
    root = os.path.abspath(args.registry)
    require_registry(root)
    reg = load_registry(root)
    rows = []
    for name, info in sorted(reg.get("skills", {}).items()):
        if args.scope and info["scope"] != args.scope:
            continue
        c = (info.get("scan") or {}).get("counts") or {}
        rows.append({
            "scope": info["scope"],
            "name": name,
            "version": info["current_version"],
            "owner": info.get("owner") or "",
            "scan": f"{c.get('critical', 0)}c/{c.get('high', 0)}h/"
                    f"{c.get('medium', 0)}m/{c.get('low', 0)}l",
            "deprecated": "yes" if info.get("deprecated") else "",
        })
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        print("registry is empty; capture a skill with: skm add <folder>")
        return
    headers = ["scope", "name", "version", "owner", "scan", "deprecated"]
    widths = [max(len(h), max(len(str(r[h])) for r in rows)) for h in headers]
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print("  ".join(str(r[h]).ljust(w) for h, w in zip(headers, widths)))


def cmd_show(args):
    root = os.path.abspath(args.registry)
    require_registry(root)
    reg = load_registry(root)
    name = sanitize_name(args.name)
    info = reg.get("skills", {}).get(name)
    if not info:
        print(f"error: no skill named {name}")
        sys.exit(2)
    info["_name"] = name
    if args.json:
        out = dict(info)
        out.pop("_name", None)
        print(json.dumps(out, indent=2))
        return
    print(f"{name}  v{info['current_version']}  scope: {info['scope']}  "
          f"owner: {info.get('owner') or '(none)'}")
    if info.get("deprecated"):
        d = info["deprecated"]
        print(f"  DEPRECATED {d['date']} by {d['by']}: {d['reason']}")
    scan = info.get("scan")
    if scan:
        c = scan["counts"]
        print(f"  last scan {scan['date']}: {c['critical']} critical, "
              f"{c['high']} high, {c['medium']} medium, {c['low']} low")
    print("  versions:")
    for v in info.get("versions", []):
        print(f"    {v['version']}  {v['date']}  sha256:{v['hash'][:12]}...")
    print("  history:")
    for ev in info.get("history", []):
        print(f"    {ev['date']}  {ev['event']:10s} by {ev['by']}  "
              f"{ev.get('detail', '')}")
    for target in (["team"] if info["scope"] == "personal" else
                   ["company"] if info["scope"] == "team" else []):
        ok, blockers = gate_check(root, reg, name, target)
        state = "ready" if ok else "blocked"
        print(f"  promotion to {target}: {state}")
        for b in blockers:
            print(f"    - {b}")


# ---------------------------------------------------------------------------
# Promotion gates
# ---------------------------------------------------------------------------

DEFAULT_POLICY = {"promoters": {s: [] for s in SCOPES},
                  "require_distinct_reviewer": True}


def get_policy(reg):
    """Read the policy, filling in defaults for registries created earlier."""
    pol = reg.get("policy") or {}
    promoters = pol.get("promoters") or {}
    normalized = {s: list(promoters.get(s, [])) for s in SCOPES}
    out = {"promoters": normalized,
           "require_distinct_reviewer": bool(
               pol.get("require_distinct_reviewer", True))}
    reg["policy"] = out
    return out


def norm_id(value):
    return (value or "").strip().lower()


def policy_blockers(reg, info, target, by):
    """Authorization checks, kept separate from the quality gates.

    Two rules: an allowlist of who may promote into a scope, and separation
    of duties -- the person who owns a skill cannot also be the one who signs
    off on sending it company wide. A gate one person can walk through alone
    is a checklist, not a control.
    """
    pol = get_policy(reg)
    blockers = []
    allowed = [norm_id(x) for x in pol["promoters"].get(target, []) if x]
    who = norm_id(by)
    if allowed:
        if not who:
            blockers.append(
                f"promotion to {target} is restricted; pass --by <identity> "
                f"(authorized: {', '.join(sorted(allowed))})")
        elif who not in allowed:
            blockers.append(
                f"'{by}' is not authorized to promote to {target} "
                f"(authorized: {', '.join(sorted(allowed))}; change with: "
                f"skm policy --add-promoter <id> --scope {target})")
    if target == "company" and pol["require_distinct_reviewer"]:
        owner = norm_id(info.get("owner"))
        if who and owner and who == owner:
            blockers.append(
                f"'{by}' owns this skill and cannot also sign off on its "
                f"promotion to company; a second person must review it "
                f"(solo registry: skm policy --allow-self-promotion)")
    return blockers


def cmd_policy(args):
    root = os.path.abspath(args.registry)
    require_registry(root)
    reg = load_registry(root)
    pol = get_policy(reg)
    scopes = [args.scope] if args.scope else ["team", "company"]
    changed = []

    for who in args.add_promoter or []:
        for scope in scopes:
            if norm_id(who) not in [norm_id(x) for x in
                                    pol["promoters"][scope]]:
                pol["promoters"][scope].append(who)
                changed.append(f"{who} may now promote to {scope}")
    for who in args.remove_promoter or []:
        for scope in scopes:
            keep = [x for x in pol["promoters"][scope]
                    if norm_id(x) != norm_id(who)]
            if len(keep) != len(pol["promoters"][scope]):
                pol["promoters"][scope] = keep
                changed.append(f"{who} may no longer promote to {scope}")
    if args.allow_self_promotion:
        pol["require_distinct_reviewer"] = False
        changed.append("self promotion allowed (no distinct reviewer "
                       "required)")
    if args.require_distinct_reviewer:
        pol["require_distinct_reviewer"] = True
        changed.append("a distinct reviewer is now required for company "
                       "promotion")

    if changed:
        save_registry(root, reg, commit_msg="skm: policy update")

    if args.json:
        print(json.dumps(pol, indent=2))
        return
    for c in changed:
        print(c)
    print("policy:")
    print(f"  distinct reviewer required for company: "
          f"{'yes' if pol['require_distinct_reviewer'] else 'no'}")
    for scope in ("team", "company"):
        who = pol["promoters"][scope]
        print(f"  may promote to {scope}: "
              f"{', '.join(who) if who else 'anyone (no allowlist set)'}")


SCOPE_RANK = {scope: i for i, scope in enumerate(SCOPES)}


def read_depends(root, reg, name):
    """The skills `name` declares a dependency on, normalized."""
    info = reg.get("skills", {}).get(name)
    if not info:
        return []
    info["_name"] = name
    md = os.path.join(skill_dir(root, info), "SKILL.md")
    if not os.path.isfile(md):
        return []
    with open(md, "r", encoding="utf-8", errors="ignore") as fh:
        meta, _ = parse_frontmatter(fh.read())
    deps = parse_list(meta.get("depends") or meta.get("dependencies"))
    return [sanitize_name(d) for d in deps]


def find_dependency_cycle(root, reg, name):
    """Return a path name -> ... -> name if one exists, else None.

    Without this, two skills that depend on each other deadlock: each gate
    demands the other be promoted first, with no hint as to why.
    """
    stack = [(name, [name])]
    seen = set()
    while stack:
        cur, path = stack.pop()
        for dep in read_depends(root, reg, cur):
            if dep == name:
                return path + [dep]
            if dep in seen or dep not in reg.get("skills", {}):
                continue
            seen.add(dep)
            stack.append((dep, path + [dep]))
    return None


def dependency_blockers(root, reg, name, target):
    """A governed skill must not rest on an ungoverned one.

    Company scope means reviewed, eval-gated and pinned. That guarantee is
    void if the skill relies on something that never passed a gate, so a
    dependency has to sit at the target scope or higher.
    """
    blockers = []
    cycle = find_dependency_cycle(root, reg, name)
    if cycle:
        return ["dependency cycle: " + " -> ".join(cycle) +
                "; break the cycle before promoting either skill"]
    for dep in read_depends(root, reg, name):
        if dep == name:
            continue
        dep_info = reg.get("skills", {}).get(dep)
        if not dep_info:
            blockers.append(f"declares a dependency on '{dep}', which is not "
                            f"in the registry; add it first")
            continue
        if dep_info.get("deprecated"):
            blockers.append(f"depends on '{dep}', which is deprecated: "
                            f"{dep_info['deprecated'].get('reason', '')}")
        if SCOPE_RANK[dep_info["scope"]] < SCOPE_RANK[target]:
            blockers.append(
                f"depends on '{dep}' at {dep_info['scope']} scope; a {target} "
                f"skill cannot rely on a less governed one "
                f"(promote {dep} to {target} first)")
    return blockers


def gate_check(root, reg, name, target, by=None):
    """Returns (ok, blockers). Re-scans the live folder, never stale data."""
    info = reg["skills"][name]
    info["_name"] = name
    blockers = []
    current = info["scope"]
    expected = {"team": "personal", "company": "team"}[target]
    if current != expected:
        blockers.append(f"scope is {current}; promotion to {target} "
                        f"must come from {expected}")
        return False, blockers

    src = skill_dir(root, info)
    scan = scan_skill(src)
    meta = scan["meta"]
    counts = scan["counts"]

    if not info.get("owner"):
        blockers.append("no owner; re-add with --owner or set owner in "
                        "frontmatter")
    if not meta.get("description"):
        blockers.append("SKILL.md frontmatter has no description")
    evals = parse_list(meta.get("evals") or meta.get("eval_queries"))
    if len(evals) < 1:
        blockers.append("no eval queries; add an 'evals:' list to SKILL.md "
                        "frontmatter (3 to 5 representative queries)")
    if counts["critical"] > 0:
        blockers.append(f"{counts['critical']} critical scan finding(s); "
                        f"run: skm scan {name}")
    blockers.extend(dependency_blockers(root, reg, name, target))
    blockers.extend(policy_blockers(reg, info, target, by))

    if target == "company" and counts["high"] > 0:
        blockers.append(f"{counts['high']} high scan finding(s); company "
                        f"scope requires zero critical and zero high")

    # Team asks that evals be declared. Company asks that they were actually
    # executed against this exact content and passed: a promotion gate that
    # only checks for the presence of a list verifies paperwork, not behavior.
    if target == "company":
        run = info.get("eval_run")
        if not run:
            blockers.append(f"evals declared but never run; run: "
                            f"skm eval {name} --runner '<cmd with {{query}}>'")
        elif run.get("hash") != hash_tree(src):
            blockers.append(f"eval results are stale (skill changed since the "
                            f"last run); re-run: skm eval {name}")
        elif run.get("failed", 0) > 0:
            blockers.append(f"{run['failed']} of {run['total']} eval(s) failed "
                            f"in the last run; run: skm eval {name}")
    return (len(blockers) == 0), blockers


def cmd_scan(args):
    root = os.path.abspath(args.registry)
    require_registry(root)
    reg = load_registry(root)
    name = sanitize_name(args.name)
    info = reg.get("skills", {}).get(name)
    if not info:
        print(f"error: no skill named {name}")
        sys.exit(2)
    info["_name"] = name
    scan = scan_skill(skill_dir(root, info))
    info["scan"] = {"date": scan["date"], "counts": scan["counts"],
                    "findings": scan["findings"][:50]}
    save_registry(root, reg, commit_msg=f"skm: scan {name}")
    if args.json:
        print(json.dumps(scan, indent=2))
    else:
        print_scan(scan, name)
    sys.exit(1 if scan["counts"]["critical"] > 0 else 0)


def cmd_promote(args):
    root = os.path.abspath(args.registry)
    require_registry(root)
    reg = load_registry(root)
    name = sanitize_name(args.name)
    info = reg.get("skills", {}).get(name)
    if not info:
        print(f"error: no skill named {name}")
        sys.exit(2)
    info["_name"] = name

    if args.to == "company" and (not args.by or not args.note):
        print("error: company promotion requires --by <who> and "
              "--note <sign-off reason>")
        sys.exit(2)

    ok, blockers = gate_check(root, reg, name, args.to, by=args.by)
    if not ok:
        print(f"promotion to {args.to} blocked for {name}:")
        for b in blockers:
            print(f"  - {b}")
        sys.exit(1)

    with open(registry_path(root), "rb") as fh:
        registry_backup = fh.read()

    src = skill_dir(root, info)
    expected_scope = info["scope"]
    dest = scope_dir(root, args.to, name)
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    shutil.move(src, dest)
    info["scope"] = args.to
    if args.to == "company":
        snapshot_version(root, name, info["current_version"], dest,
                         tag="company")
        info["company_pin"] = {
            "version": info["current_version"],
            "hash": hash_tree(dest),
            # A recorded attestation, not a cryptographic signature. It only
            # becomes one when --sign puts a verifiable GPG signature on the
            # promotion commit, recorded below.
            "attested_by": args.by,
            "note": args.note,
            "date": now_utc(),
            "signature": None,
        }
        log_event(info, "promote", args.by,
                  f"team -> company, pinned; attested by {args.by}: "
                  f"{args.note}")
    else:
        log_event(info, "promote", args.by, "personal -> team")

    pin_path = pin_dir(root, info) if args.to == "company" else None
    try:
        sha = save_registry(root, reg,
                            commit_msg=f"skm: promote {name} to {args.to}",
                            sign=args.sign)
    except RuntimeError as exc:
        # Roll back fully: the move already happened and save_registry already
        # wrote the manifest, so restoring one without the other would leave a
        # skill filed under a scope it was never granted.
        if os.path.isdir(dest) and not os.path.isdir(src):
            shutil.move(dest, src)
        if pin_path and os.path.isdir(pin_path):
            shutil.rmtree(pin_path)
        with open(registry_path(root), "wb") as fh:
            fh.write(registry_backup)
        print(f"error: {exc}")
        print(f"  {name} left at {expected_scope} scope; nothing was "
              f"recorded")
        print("  configure git commit signing (git config user.signingkey "
              "<key>) and retry")
        sys.exit(2)

    if args.to == "company" and args.sign and sha:
        info["company_pin"]["signature"] = {"commit": sha}
        save_registry(root, reg,
                      commit_msg=f"skm: record signature for {name}")

    print(f"promoted {name} to {args.to} scope")
    if args.to == "company":
        print(f"pinned: {pin_path}")
        if args.sign and sha:
            print(f"signed: GPG signature on commit {sha[:12]}; "
                  f"check it with: skm verify {name}")
        else:
            print(f"sign-off recorded by {args.by}: {args.note}")
            print("note: a recorded attestation, not a cryptographic "
                  "signature; use --sign to GPG-sign the promotion")


def cmd_eval(args):
    """Run the eval queries a skill declares, and record the result against
    the exact content hash they ran on.

    skm cannot judge whether an answer is good, so it does not pretend to:
    it delegates to a runner command you configure and treats exit code 0 as
    a pass. What it contributes is the part a gate needs -- proof the evals
    were executed against this exact version, and refusal to accept a result
    that belongs to different content.
    """
    root = os.path.abspath(args.registry)
    require_registry(root)
    reg = load_registry(root)
    name = sanitize_name(args.name)
    info = reg.get("skills", {}).get(name)
    if not info:
        print(f"error: no skill named {name}")
        sys.exit(2)
    info["_name"] = name
    src = skill_dir(root, info)

    runner = args.runner or os.environ.get("SKM_EVAL_RUNNER")
    if not runner:
        print("error: no eval runner configured")
        print("  pass --runner or set SKM_EVAL_RUNNER, for example:")
        print("    skm eval " + name + " --runner 'claude -p \"{query}\"'")
        print("  {query} and {skill_dir} are substituted per query;")
        print("  the runner runs in your shell and exit code 0 means pass")
        sys.exit(2)

    meta = {}
    md = os.path.join(src, "SKILL.md")
    if os.path.isfile(md):
        with open(md, "r", encoding="utf-8", errors="ignore") as fh:
            meta, _ = parse_frontmatter(fh.read())
    queries = parse_list(meta.get("evals") or meta.get("eval_queries"))
    if not queries:
        print(f"error: {name} declares no evals in SKILL.md frontmatter")
        sys.exit(2)

    print(f"eval: {name} v{info['current_version']} ({len(queries)} queries)")
    results = []
    passed = 0
    for q in queries:
        cmd = runner.replace("{query}", q).replace("{skill_dir}", src)
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=args.timeout)
            code = r.returncode
            out = ((r.stdout or "") + (r.stderr or "")).strip()
        except subprocess.TimeoutExpired:
            code, out = 124, f"timed out after {args.timeout}s"
        ok = code == 0
        passed += 1 if ok else 0
        print(f"  [{'PASS' if ok else 'FAIL'}] {q[:68]}")
        if not ok and out:
            print(f"         exit {code}: {out.splitlines()[-1][:68]}")
        results.append({"query": q, "ok": ok, "exit": code,
                        "output_tail": out[-400:]})

    failed = len(results) - passed
    info["eval_run"] = {"date": now_utc(), "hash": hash_tree(src),
                        "version": info["current_version"], "runner": runner,
                        "total": len(results), "passed": passed,
                        "failed": failed, "results": results}
    log_event(info, "eval", args.by,
              f"{passed}/{len(results)} passed via: {runner}")
    run_record = info["eval_run"]
    save_registry(root, reg,
                  commit_msg=f"skm: eval {name} "
                             f"({passed}/{len(results)} passed)")
    if args.json:
        print(json.dumps(run_record, indent=2))
    else:
        print(f"{passed}/{len(results)} passed")
    sys.exit(1 if failed else 0)


def cmd_verify(args):
    """Re-hash what is on disk and compare it to what was recorded.

    The registry already stores a hash for every version and every company
    pin. Recording them is only useful if something reads them back, which is
    what this does: it catches a skill edited in place after approval, a pin
    that no longer matches, and a GPG signature that does not verify.
    """
    root = os.path.abspath(args.registry)
    require_registry(root)
    reg = load_registry(root)
    only = sanitize_name(args.name) if args.name else None

    problems = []
    checked = 0
    for name, info in sorted(reg.get("skills", {}).items()):
        if only and name != only:
            continue
        info["_name"] = name
        checked += 1
        d = skill_dir(root, info)
        version = info.get("current_version")

        if not os.path.isdir(d):
            problems.append(f"{name}: skill folder missing at {d}")
            continue

        live = hash_tree(d)
        rec = recorded_hash(info)
        if rec is None:
            problems.append(f"{name}: no hash recorded for v{version}")
        elif live != rec:
            problems.append(
                f"{name}: CONTENT DRIFT - v{version} was recorded as "
                f"sha256:{rec[:12]} but is now sha256:{live[:12]} "
                f"(edited in place after approval?)")
        else:
            print(f"  ok    {name} v{version} matches its recorded hash")

        pin = info.get("company_pin")
        if not pin:
            continue
        pd = pin_dir(root, info)
        if not os.path.isdir(pd):
            problems.append(f"{name}: company pin missing at {pd}")
        else:
            ph = hash_tree(pd)
            if ph != pin.get("hash"):
                problems.append(
                    f"{name}: PIN TAMPERED - company pin v{pin['version']} "
                    f"no longer matches the hash recorded at promotion")
            elif live != ph:
                problems.append(
                    f"{name}: live company folder differs from its pin "
                    f"v{pin['version']}; sync delivers the pin, so the two "
                    f"have diverged")
            else:
                print(f"  ok    {name} company pin v{pin['version']} intact")

        sig = pin.get("signature") or {}
        if sig.get("commit"):
            good, detail = git_verify_commit(root, sig["commit"])
            if good:
                print(f"  ok    {name} promotion commit "
                      f"{sig['commit'][:12]} GPG signature verified")
            else:
                problems.append(
                    f"{name}: GPG signature on commit {sig['commit'][:12]} "
                    f"did NOT verify ({detail})")
        else:
            print(f"  note  {name} company sign-off by "
                  f"{pin.get('attested_by') or 'unknown'} is a recorded "
                  f"attestation, not a GPG signature")

    if only and checked == 0:
        print(f"error: no skill named {only}")
        sys.exit(2)

    print()
    if problems:
        print(f"{len(problems)} problem(s) across {checked} skill(s):")
        for pr in problems:
            print(f"  - {pr}")
        sys.exit(1)
    print(f"verified {checked} skill(s): no drift")


def git_out(root, *args):
    """Run a git command, returning (returncode, stdout, stderr)."""
    r = subprocess.run(["git", "-C", root] + list(args),
                       capture_output=True, text=True)
    return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()


def require_git_registry(root):
    if not shutil.which("git"):
        print("error: git not found; push and pull need git")
        sys.exit(2)
    if not os.path.isdir(os.path.join(root, ".git")):
        print(f"error: {root} is not a git repo")
        print("  a shared registry must be git backed; re-create it with: "
              "skm init")
        sys.exit(2)


def git_remote_url(root, remote):
    code, out, _ = git_out(root, "remote", "get-url", remote)
    return out if code == 0 else None


def git_current_branch(root):
    code, out, _ = git_out(root, "rev-parse", "--abbrev-ref", "HEAD")
    return out if code == 0 and out and out != "HEAD" else "main"


def git_is_dirty(root):
    code, out, _ = git_out(root, "status", "--porcelain")
    return bool(out)


def last_event_date(info):
    return max([h.get("date", "") for h in info.get("history") or []] or [""])


def merge_history(a, b):
    """Union two history lists, deduped, in date order."""
    seen = set()
    out = []
    for ev in (a.get("history") or []) + (b.get("history") or []):
        key = (ev.get("date"), ev.get("event"), ev.get("by"),
               ev.get("detail"))
        if key in seen:
            continue
        seen.add(key)
        out.append(ev)
    return sorted(out, key=lambda e: e.get("date", ""))


def merge_deliveries(a, b):
    """Union deliveries, keeping the most recent record per destination."""
    by_dest = {}
    for d in (a.get("deliveries") or []) + (b.get("deliveries") or []):
        dest = d.get("dest")
        if dest not in by_dest or d.get("date", "") > by_dest[dest].get(
                "date", ""):
            by_dest[dest] = d
    return [by_dest[k] for k in sorted(by_dest)]


def merge_versions(a, b):
    """Union version records, deduped by (version, hash), in date order."""
    seen = set()
    out = []
    for v in (a.get("versions") or []) + (b.get("versions") or []):
        key = (v.get("version"), v.get("hash"))
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return sorted(out, key=lambda v: v.get("date", ""))


def merge_policy(a, b):
    """Union the promoter allowlists; the stricter reviewer rule wins."""
    pa = a.get("policy") or {}
    pb = b.get("policy") or {}
    promoters = {}
    for scope in SCOPES:
        merged = list((pa.get("promoters") or {}).get(scope, []))
        for who in (pb.get("promoters") or {}).get(scope, []):
            if who not in merged:
                merged.append(who)
        promoters[scope] = sorted(merged)
    strict = bool(pa.get("require_distinct_reviewer", True)) or \
        bool(pb.get("require_distinct_reviewer", True))
    return {"promoters": promoters, "require_distinct_reviewer": strict}


def merge_registries(ours, theirs):
    """Reconcile two registries that diverged.

    Per skill the side with the newer last history event wins, because that
    is the side that acted most recently. History, versions and deliveries
    are unioned rather than replaced, so an audit trail is never lost to a
    merge. Divergence is reported, never silently resolved.
    """
    notes = []
    created = [d for d in (ours.get("created"), theirs.get("created")) if d]
    merged = {
        "version": ours.get("version") or theirs.get("version") or 1,
        "created": min(created) if created else now_utc(),
        "policy": merge_policy(ours, theirs),
        "skills": {},
    }
    names = sorted(set(ours.get("skills") or {}) |
                   set(theirs.get("skills") or {}))
    for name in names:
        a = (ours.get("skills") or {}).get(name)
        b = (theirs.get("skills") or {}).get(name)
        if a and not b:
            merged["skills"][name] = a
            notes.append(f"{name}: local only, kept")
            continue
        if b and not a:
            merged["skills"][name] = b
            notes.append(f"{name}: remote only, taken")
            continue
        da, db = last_event_date(a), last_event_date(b)
        if da >= db:
            winner, side = a, "local"
        else:
            winner, side = b, "remote"
        m = json.loads(json.dumps(winner))
        m["history"] = merge_history(a, b)
        m["versions"] = merge_versions(a, b)
        m["deliveries"] = merge_deliveries(a, b)
        merged["skills"][name] = m
        if a.get("scope") != b.get("scope"):
            notes.append(
                f"{name}: SCOPE DIVERGED (local {a.get('scope')} vs remote "
                f"{b.get('scope')}); took {side} ({m.get('scope')}) -- "
                f"confirm with: skm show {name}")
        elif a != b:
            notes.append(f"{name}: diverged, took {side} (newer)")
    return merged, notes


def reconcile_scopes(root, reg):
    """Make the manifest agree with what is actually on disk.

    After a merge, git has already decided where each skill folder lives. If
    the manifest disagrees, disk is the truth: a merge must never leave a
    skill filed under a scope whose folder does not exist.
    """
    notes = []
    for name, info in (reg.get("skills") or {}).items():
        info["_name"] = name
        if os.path.isdir(skill_dir(root, info)):
            continue
        for scope in SCOPES:
            if os.path.isdir(scope_dir(root, scope, name)):
                notes.append(f"{name}: manifest said {info['scope']}, found "
                             f"on disk at {scope}; manifest corrected")
                info["scope"] = scope
                break
        else:
            notes.append(f"{name}: no folder on disk in any scope; "
                         f"run: skm verify")
    return notes


def normalize_remote_url(url):
    """Resolve a local path remote, since git runs with -C <registry>."""
    if not url:
        return url
    if "://" in url or url.startswith("git@"):
        return url
    if os.path.exists(url):
        return os.path.abspath(url)
    return url


def cmd_push(args):
    """Publish the registry so other people can pull it."""
    root = os.path.abspath(args.registry)
    require_registry(root)
    require_git_registry(root)

    if args.set_url:
        url = normalize_remote_url(args.set_url)
        if git_remote_url(root, args.remote) is None:
            git_out(root, "remote", "add", args.remote, url)
        else:
            git_out(root, "remote", "set-url", args.remote, url)
        print(f"remote {args.remote} -> {url}")

    url = git_remote_url(root, args.remote)
    if not url:
        print(f"error: no git remote named '{args.remote}'")
        print(f"  set one: skm push --set-url <git-url>")
        sys.exit(2)

    if git_is_dirty(root):
        print("error: the registry has uncommitted changes")
        print("  every skm command commits its own work, so this means the "
              "registry was edited by hand")
        print("  review with: git -C " + root + " status")
        sys.exit(2)

    branch = args.branch or git_current_branch(root)
    code, out, err = git_out(root, "push", "--set-upstream", args.remote,
                             branch)
    if code != 0:
        print(f"error: push failed")
        for line in (err or out).splitlines():
            print("  " + line)
        if "rejected" in (err + out):
            print("  the remote has commits you do not: run skm pull first")
        sys.exit(1)
    print(f"pushed {branch} to {url}")


def cmd_pull(args):
    """Fetch and reconcile another copy of the registry."""
    root = os.path.abspath(args.registry)
    require_registry(root)
    require_git_registry(root)

    url = git_remote_url(root, args.remote)
    if not url:
        print(f"error: no git remote named '{args.remote}'")
        print("  set one: skm push --set-url <git-url>")
        sys.exit(2)
    if git_is_dirty(root):
        print("error: the registry has uncommitted changes; commit or "
              "discard them before pulling")
        sys.exit(2)

    branch = args.branch or git_current_branch(root)
    code, out, err = git_out(root, "fetch", args.remote, branch)
    if code != 0:
        print("error: fetch failed")
        for line in (err or out).splitlines():
            print("  " + line)
        sys.exit(1)

    code, out, err = git_out(root, "merge", "--no-edit", "FETCH_HEAD")
    if code == 0:
        if "Already up to date" in out:
            print(f"already up to date with {url}")
        else:
            print(f"pulled {branch} from {url}")
            for line in out.splitlines()[:5]:
                print("  " + line)
        _post_merge_report(root)
        return

    _, conflicts, _ = git_out(root, "diff", "--name-only", "--diff-filter=U")
    conflicted = [c for c in conflicts.splitlines() if c.strip()]
    if conflicted != [REGISTRY_FILE]:
        git_out(root, "merge", "--abort")
        print("error: the merge conflicts in files skm cannot reconcile:")
        for c in conflicted:
            print("  - " + c)
        print("  this usually means the same skill was promoted differently "
              "on both sides")
        print("  the merge was aborted; nothing changed")
        sys.exit(1)

    # Only the manifest conflicts, which is the case skm can resolve on its
    # own terms rather than by line-based diffing of JSON.
    print("registry.json diverged; reconciling by skill")
    ok_a, ours_raw, _ = git_out(root, "show", ":2:" + REGISTRY_FILE)
    ok_b, theirs_raw, _ = git_out(root, "show", ":3:" + REGISTRY_FILE)
    if ok_a != 0 or ok_b != 0:
        git_out(root, "merge", "--abort")
        print("error: could not read both sides of the conflict; "
              "merge aborted")
        sys.exit(1)
    try:
        merged, notes = merge_registries(json.loads(ours_raw),
                                         json.loads(theirs_raw))
    except ValueError as exc:
        git_out(root, "merge", "--abort")
        print(f"error: unreadable registry on one side ({exc}); "
              f"merge aborted")
        sys.exit(1)

    notes += reconcile_scopes(root, merged)
    with open(registry_path(root), "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=2, sort_keys=False)
        fh.write(chr(10))
    git_out(root, "add", REGISTRY_FILE)
    # -c options configure git; they must precede the subcommand, or git
    # reads "-c" as "reuse the message from this commit".
    code, out, err = git_out(root, "-c", "user.name=skm",
                             "-c", "user.email=skm@localhost",
                             "commit", "--no-edit", "--quiet")
    if code != 0:
        print("error: could not commit the reconciled registry")
        for line in (err or out).splitlines():
            print("  " + line)
        sys.exit(1)
    for n in notes:
        print("  " + n)
    print(f"pulled and reconciled {branch} from {url}")
    _post_merge_report(root)


def _post_merge_report(root):
    reg = load_registry(root)
    notes = reconcile_scopes(root, reg)
    if notes:
        save_registry(root, reg, commit_msg="skm: reconcile scopes after pull")
        for n in notes:
            print("  " + n)
    print("run: skm verify   # confirm nothing drifted in the merge")


def cmd_deprecate(args):
    root = os.path.abspath(args.registry)
    require_registry(root)
    reg = load_registry(root)
    name = sanitize_name(args.name)
    info = reg.get("skills", {}).get(name)
    if not info:
        print(f"error: no skill named {name}")
        sys.exit(2)
    info["_name"] = name
    info["deprecated"] = {"date": now_utc(), "by": args.by or "unknown",
                          "reason": args.reason}
    log_event(info, "deprecate", args.by, args.reason)

    dependents = []
    for other_name, other in reg["skills"].items():
        if other_name == name:
            continue
        other["_name"] = other_name
        md = os.path.join(skill_dir(root, other), "SKILL.md")
        if not os.path.isfile(md):
            continue
        with open(md, "r", encoding="utf-8", errors="ignore") as fh:
            meta, _ = parse_frontmatter(fh.read())
        deps = parse_list(meta.get("depends") or meta.get("dependencies"))
        if name in deps:
            dependents.append(other_name)

    save_registry(root, reg, commit_msg=f"skm: deprecate {name}")
    print(f"deprecated {name}: {args.reason}")
    if dependents:
        print("warning: these skills declare a dependency on it and will "
              "break or degrade:")
        for d in dependents:
            print(f"  - {d}")
    else:
        print("no dependents declare this skill")


def safe_to_remove(dest, name):
    """Guard rails for a destructive operation.

    Only ever removes a path skm itself recorded delivering to, that is named
    after the skill, and that still looks like a skill folder.
    """
    if not dest:
        return False, "no destination recorded"
    path = os.path.abspath(dest)
    if os.path.basename(path.rstrip(os.sep)) != name:
        return False, f"path is not named '{name}'"
    parent = os.path.dirname(path.rstrip(os.sep))
    if not parent or parent == path.rstrip(os.sep):
        return False, "refusing to touch a filesystem root"
    depth = len([p for p in path.replace("\\", "/").split("/") if p])
    if depth < 2:
        return False, "path is suspiciously shallow"
    if not os.path.isfile(os.path.join(path, "SKILL.md")):
        return False, "no SKILL.md there; not a skill folder"
    return True, ""


def cmd_retract(args):
    """Pull a skill back from the surfaces it was delivered to.

    Deprecation records that a skill should not be used. Retraction is the
    part that makes that true on the machines it already reached.
    """
    root = os.path.abspath(args.registry)
    require_registry(root)
    reg = load_registry(root)
    name = sanitize_name(args.name)
    info = reg.get("skills", {}).get(name)
    if not info:
        print(f"error: no skill named {name}")
        sys.exit(2)
    info["_name"] = name

    deliveries = list(info.get("deliveries") or [])
    if not deliveries:
        print(f"{name} has no recorded deliveries; nothing to retract")
        return

    removed, absent, skipped = [], [], []
    for d in deliveries:
        dest = d.get("dest")
        path = os.path.abspath(dest) if dest else None
        if path and not os.path.isdir(path):
            absent.append(d)
            continue
        ok, why = safe_to_remove(dest, name)
        if not ok:
            skipped.append((dest, why))
            continue
        if args.dry_run:
            removed.append(d)
            continue
        try:
            shutil.rmtree(path)
            removed.append(d)
        except OSError as exc:
            skipped.append((dest, str(exc)))

    verb = "would remove" if args.dry_run else "removed"
    for d in removed:
        print(f"  {verb}: {d['dest']} ({d.get('surface', '?')})")
    for d in absent:
        print(f"  already gone: {d['dest']}")
    for dest, why in skipped:
        print(f"  SKIPPED {dest}: {why}")

    if args.dry_run:
        print(f"dry run: {len(removed)} delivery/deliveries would be "
              f"retracted, {len(skipped)} skipped")
        return

    gone = {d["dest"] for d in removed} | {d["dest"] for d in absent}
    info["deliveries"] = [d for d in deliveries if d.get("dest") not in gone]
    log_event(info, "retract", args.by,
              f"{len(removed)} removed, {len(absent)} already gone, "
              f"{len(skipped)} skipped")
    save_registry(root, reg, commit_msg=f"skm: retract {name}")

    print(f"retracted {name}: {len(removed)} removed, {len(absent)} already "
          f"gone, {len(skipped)} skipped")
    if skipped:
        print("warning: some deliveries could not be retracted and remain "
              "on disk")
        sys.exit(1)


def cmd_sync(args):
    root = os.path.abspath(args.registry)
    require_registry(root)
    reg = load_registry(root)
    name = sanitize_name(args.name)
    info = reg.get("skills", {}).get(name)
    if not info:
        print(f"error: no skill named {name}")
        sys.exit(2)
    info["_name"] = name
    src = skill_dir(root, info)

    # A company pin that does not govern delivery is decorative. Ship the
    # immutable snapshot that was approved, not whatever is in the scope
    # folder right now.
    pin_note = ""
    if (info["scope"] == "company" and info.get("company_pin")
            and not args.from_live):
        pd = pin_dir(root, info)
        if os.path.isdir(pd):
            src = pd
            pin_note = f" from company pin v{info['company_pin']['version']}"
        else:
            print(f"warning: company pin missing at {pd}; "
                  f"delivering live folder (run: skm verify {name})")

    # Delivery is a trust boundary too: promotion gates are worthless if a
    # skill with critical findings can be copied straight into a live agent.
    scan = scan_skill(src)
    critical = scan["counts"]["critical"]
    if critical and not args.force:
        print(f"error: refusing to sync {name}: {critical} critical scan "
              f"finding(s)")
        print(f"  run: skm scan {name}")
        print("  override with --force if you accept the risk")
        sys.exit(1)
    if info.get("deprecated"):
        d = info["deprecated"]
        print(f"warning: {name} is deprecated ({d['date']} by {d['by']}): "
              f"{d['reason']}")

    if args.dest:
        dest_root = os.path.abspath(os.path.expanduser(args.dest))
    elif args.surface == "claude-code":
        dest_root = os.path.expanduser("~/.claude/skills")
    else:
        dest_root = os.path.abspath("skills-sync")
    dest = os.path.join(dest_root, name)
    os.makedirs(dest_root, exist_ok=True)
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    shutil.copytree(src, dest)
    # Record the delivery so it can be retracted later. Without this, the
    # answer to "we found a problem, remove it everywhere" is a manual hunt.
    deliveries = [d for d in (info.get("deliveries") or [])
                  if d.get("dest") != dest]
    deliveries.append({"surface": args.surface, "dest": dest,
                       "version": info["current_version"],
                       "hash": hash_tree(dest), "date": now_utc(),
                       "from_pin": bool(pin_note)})
    info["deliveries"] = sorted(deliveries, key=lambda d: d["dest"])

    detail = f"{args.surface}{pin_note} -> {dest}"
    if critical:
        detail += f" (FORCED past {critical} critical finding(s))"
    log_event(info, "sync", args.by, detail)
    # Reaching a live agent surface is the event an auditor most wants dated,
    # so it belongs in the git trail like every other mutation.
    save_registry(root, reg, commit_msg=f"skm: sync {name} to {args.surface}")
    print(f"synced {name} (scope: {info['scope']}, "
          f"v{info['current_version']}){pin_note} to {dest}")
    if critical:
        print(f"warning: forced past {critical} critical finding(s); "
              f"this is recorded in the registry history")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--registry",
                        default=os.environ.get("SKM_REGISTRY",
                                               "skm-registry"),
                        help="registry root (env: SKM_REGISTRY, "
                             "default: ./skm-registry)")

    p = argparse.ArgumentParser(
        prog="skm",
        description="Governance for AI agent skills: personal -> team -> "
                    "company, where every promotion is gated on a security "
                    "scan, executed evals, and a second reviewer. Shared "
                    "through a git registry; approved versions are pinned, "
                    "verified, and retractable.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", parents=[common], help="create a registry")
    s.add_argument("--no-git", action="store_true",
                   help="do not git init the registry")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("add", parents=[common],
                       help="capture or update a skill (personal scope)")
    s.add_argument("path", help="folder containing SKILL.md")
    s.add_argument("--name")
    s.add_argument("--owner")
    s.add_argument("--version")
    s.add_argument("--by")
    s.set_defaults(func=cmd_add)

    s = sub.add_parser("list", parents=[common], help="list skills")
    s.add_argument("--scope", choices=SCOPES)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("show", parents=[common],
                       help="detail, history, and gate readiness")
    s.add_argument("name")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("scan", parents=[common],
                       help="security scan (exit 1 on critical findings)")
    s.add_argument("name")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("promote", parents=[common],
                       help="gated promotion: personal -> team -> company")
    s.add_argument("name")
    s.add_argument("--to", required=True, choices=["team", "company"])
    s.add_argument("--by")
    s.add_argument("--note", help="sign-off reason (required for company)")
    s.add_argument("--sign", action="store_true",
                   help="GPG-sign the promotion commit (a real signature; "
                        "without it --by is only a recorded attestation)")
    s.set_defaults(func=cmd_promote)

    s = sub.add_parser("eval", parents=[common],
                       help="run the evals a skill declares (exit 1 on "
                            "failure)")
    s.add_argument("name")
    s.add_argument("--runner",
                   help="shell command per query; {query} and {skill_dir} "
                        "are substituted (env: SKM_EVAL_RUNNER)")
    s.add_argument("--timeout", type=int, default=120,
                   help="per-query timeout in seconds (default: 120)")
    s.add_argument("--json", action="store_true")
    s.add_argument("--by")
    s.set_defaults(func=cmd_eval)

    s = sub.add_parser("verify", parents=[common],
                       help="check recorded hashes, pins, and signatures "
                            "against what is on disk (exit 1 on drift)")
    s.add_argument("name", nargs="?", help="one skill, or all if omitted")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("deprecate", parents=[common],
                       help="mark deprecated, warn about dependents")
    s.add_argument("name")
    s.add_argument("--reason", required=True)
    s.add_argument("--by")
    s.set_defaults(func=cmd_deprecate)

    s = sub.add_parser("policy", parents=[common],
                       help="who may promote, and whether authors may "
                            "approve their own skills")
    s.add_argument("--add-promoter", action="append", metavar="ID")
    s.add_argument("--remove-promoter", action="append", metavar="ID")
    s.add_argument("--scope", choices=["team", "company"],
                   help="limit the change to one scope (default: both)")
    s.add_argument("--allow-self-promotion", action="store_true",
                   help="let an owner sign off on their own skill "
                        "(solo registries)")
    s.add_argument("--require-distinct-reviewer", action="store_true",
                   help="require a second person for company promotion "
                        "(the default)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_policy)

    s = sub.add_parser("push", parents=[common],
                       help="publish the registry to a shared git remote")
    s.add_argument("--remote", default="origin")
    s.add_argument("--branch")
    s.add_argument("--set-url", metavar="URL",
                   help="set the remote URL before pushing")
    s.set_defaults(func=cmd_push)

    s = sub.add_parser("pull", parents=[common],
                       help="fetch a shared registry and reconcile it")
    s.add_argument("--remote", default="origin")
    s.add_argument("--branch")
    s.set_defaults(func=cmd_pull)

    s = sub.add_parser("retract", parents=[common],
                       help="remove a skill from the surfaces it was "
                            "delivered to")
    s.add_argument("name")
    s.add_argument("--dry-run", action="store_true",
                   help="show what would be removed and stop")
    s.add_argument("--by")
    s.set_defaults(func=cmd_retract)

    s = sub.add_parser("sync", parents=[common],
                       help="copy a skill to an agent surface")
    s.add_argument("name")
    s.add_argument("--surface", default="claude-code",
                   choices=["claude-code", "generic"])
    s.add_argument("--dest", help="override destination directory")
    s.add_argument("--force", action="store_true",
                   help="sync even with critical scan findings")
    s.add_argument("--from-live", action="store_true",
                   help="deliver the live scope folder instead of the "
                        "company pin")
    s.add_argument("--by")
    s.set_defaults(func=cmd_sync)

    return p


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
