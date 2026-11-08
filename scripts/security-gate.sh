#!/usr/bin/env sh
# Security gate: parse a pip-audit JSON report and a Trivy JSON report,
# classify HIGH/CRITICAL findings, and emit a verdict:
#
#   pass         -> no HIGH/CRITICAL vulnerabilities at all
#   questionable -> vulnerabilities exist but NO fix is released yet
#                   (nothing to update to; a human decides whether to ship)
#   fail         -> fixable vulnerabilities present (a patch exists and we
#                   are not using it; never release this)
#
# Usage: security-gate.sh <pip-audit.json> <trivy.json>
# Writes security-summary.md; sets verdict=<...> in $GITHUB_OUTPUT when
# running in Actions. Always exits 0 — callers branch on the verdict.
set -eu

python3 - "$1" "$2" <<'PYEOF'
import json, os, sys

def load(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return None  # missing/unparseable report -> gate fails closed

fixable, unfixed = {}, {}
broken = []

pa = load(sys.argv[1])
if pa is None:
    broken.append(f"pip-audit report missing or unparseable: {sys.argv[1]}")
    pa = {}
for dep in pa.get("dependencies", []):
    for v in dep.get("vulns", []):
        key = f"{dep.get('name')}:{v.get('id')}"
        fixes = v.get("fix_versions") or []
        line = f"`{dep.get('name')} {dep.get('version')}` — {v.get('id')}"
        if fixes:
            fixable[key] = line + f" (fix: {', '.join(fixes)})"
        else:
            unfixed[key] = line + " (no fix released)"

tv = load(sys.argv[2])
if tv is None:
    broken.append(f"trivy report missing or unparseable: {sys.argv[2]}")
    tv = {}
for res in tv.get("Results") or []:
    for v in res.get("Vulnerabilities") or []:
        if v.get("Severity") not in ("HIGH", "CRITICAL"):
            continue
        key = f"{v.get('PkgName')}:{v.get('VulnerabilityID')}"
        line = (f"`{v.get('PkgName')} {v.get('InstalledVersion')}` — "
                f"{v.get('VulnerabilityID')} [{v.get('Severity')}]")
        if v.get("FixedVersion"):
            fixable[key] = line + f" (fix: {v.get('FixedVersion')})"
        else:
            unfixed[key] = line + " (no fix released)"

verdict = "fail" if (fixable or broken) else ("questionable" if unfixed else "pass")

lines = [f"## Security gate: **{verdict.upper()}**", ""]
if broken:
    lines += ["### Scanner problems (gate fails closed)", ""]
    lines += [f"- {l}" for l in broken] + [""]
if fixable:
    lines += ["### Fixable vulnerabilities (release blocked)", ""]
    lines += [f"- {l}" for l in sorted(fixable.values())] + [""]
if unfixed:
    lines += ["### Vulnerabilities with no released fix (judgment call)", ""]
    lines += [f"- {l}" for l in sorted(unfixed.values())] + [""]
if not fixable and not unfixed:
    lines += ["No HIGH/CRITICAL vulnerabilities found by pip-audit or Trivy.", ""]

summary = "\n".join(lines)
with open("security-summary.md", "w") as fh:
    fh.write(summary + "\n")
print(summary)

out = os.environ.get("GITHUB_OUTPUT")
if out:
    with open(out, "a") as fh:
        fh.write(f"verdict={verdict}\n")
step = os.environ.get("GITHUB_STEP_SUMMARY")
if step:
    with open(step, "a") as fh:
        fh.write(summary + "\n")
PYEOF
