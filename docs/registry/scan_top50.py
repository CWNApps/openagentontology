"""scan_top50.py — proactively scan a roster of real agent/MCP/LLM-app repos.

Idempotent driver for the Agent Governance Registry: for each repo not already
scanned, shallow-clone it to a temp dir, scan it with OpenAgentOntology using a
CLEAN bare-name source (no local path in atom_id/source), write the four scan
artifacts to docs/scans/<slug>/ plus a _meta.json (repo_url, commit, kind=real),
then delete the clone. Per-repo clone+scan timeouts keep one bad repo from stalling
the run. Re-running skips repos that already have a trust_profile.json.

  python docs/registry/scan_top50.py            # scan all not-yet-scanned
  python docs/registry/scan_top50.py --limit 10 # scan up to 10 more

Stays STAGED — produces artifacts only; nothing is published.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OSS = HERE.parents[1]                       # oss/openagentontology
SCANS = HERE.parent / "scans"
CLONE_ROOT = Path(tempfile.gettempdir()) / "oao_scan_roster"
CLONE_TIMEOUT = 150
SCAN_TIMEOUT = 150

# Real, recognizable agents / MCP servers / LLM apps. owner/repo. Roughly small->large.
ROSTER = [
    "yoheinakajima/babyagi", "openai/swarm", "simonw/llm", "huggingface/smolagents",
    "stanfordnlp/dspy", "pydantic/pydantic-ai", "guidance-ai/guidance",
    "langroid/langroid", "letta-ai/letta", "fetchai/uAgents", "camel-ai/camel",
    "agno-agi/agno", "reworkd/AgentGPT", "assafelovic/gpt-researcher",
    "TransformerOptimus/SuperAGI", "crewAIInc/crewAI", "browser-use/browser-use",
    "Skyvern-AI/skyvern", "mem0ai/mem0", "e2b-dev/e2b", "stitionai/devika",
    "Pythagora-io/gpt-pilot", "princeton-nlp/SWE-agent", "All-Hands-AI/OpenHands",
    "block/goose", "continuedev/continue", "sourcegraph/cody", "microsoft/UFO",
    "OpenBMB/ChatDev", "geekan/MetaGPT", "microsoft/autogen", "langchain-ai/langgraph",
    "run-llama/llama_index", "deepset-ai/haystack", "microsoft/semantic-kernel",
    "BerriAI/litellm", "Significant-Gravitas/AutoGPT", "khoj-ai/khoj",
    "danny-avila/LibreChat", "Mintplex-Labs/anything-llm", "open-webui/open-webui",
    "zylon-ai/private-gpt", "mckaywrigley/chatbot-ui", "modelcontextprotocol/servers",
    "github/github-mcp-server",
]


def _slug(owner_repo: str) -> str:
    return owner_repo.split("/", 1)[1].lower().replace("_", "-").replace(".", "-")


def _scanned(slug: str) -> bool:
    return (SCANS / slug / "trust_profile.json").exists()


def _run(cmd, cwd=None, env=None, timeout=120):
    return subprocess.run(cmd, cwd=cwd, env=env, timeout=timeout,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def scan_one(owner_repo: str) -> dict:
    slug = _slug(owner_repo)
    if _scanned(slug):
        return {"repo": owner_repo, "slug": slug, "status": "skip(exists)"}
    CLONE_ROOT.mkdir(parents=True, exist_ok=True)
    clone_dir = CLONE_ROOT / slug
    if clone_dir.exists():
        shutil.rmtree(clone_dir, ignore_errors=True)
    url = f"https://github.com/{owner_repo}.git"
    try:
        _run(["git", "clone", "--depth", "1", "--single-branch", url, slug],
             cwd=str(CLONE_ROOT), timeout=CLONE_TIMEOUT)
    except Exception as e:
        return {"repo": owner_repo, "slug": slug, "status": f"clone-fail({type(e).__name__})"}
    if not clone_dir.exists():
        return {"repo": owner_repo, "slug": slug, "status": "clone-fail(missing)"}
    # short commit
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(clone_dir),
                                capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:
        commit = ""
    # scan with clean bare-name source (cwd = clone parent, arg = slug), PYTHONPATH = oss
    env = dict(os.environ, PYTHONPATH=str(OSS))
    out_dir = SCANS / slug
    try:
        _run([sys.executable, "-m", "openagentontology", slug, "--out", str(out_dir)],
             cwd=str(CLONE_ROOT), env=env, timeout=SCAN_TIMEOUT)
    except Exception as e:
        shutil.rmtree(clone_dir, ignore_errors=True)
        return {"repo": owner_repo, "slug": slug, "status": f"scan-fail({type(e).__name__})"}
    finally:
        shutil.rmtree(clone_dir, ignore_errors=True)

    tier, score = "?", 0
    tp = out_dir / "trust_profile.json"
    if tp.exists():
        prof = json.loads(tp.read_text(encoding="ascii"))
        tier, score = prof.get("tier", "?"), prof.get("score", 0)
        # editorial metadata for the registry generator (verifiable facts only)
        (out_dir / "_meta.json").write_text(json.dumps({
            "display": owner_repo.replace("/", " / "),
            "kind": "real",
            "repo_url": f"https://github.com/{owner_repo}",
            "commit": commit,
            "note": "Scanned from the public repo.",
        }, indent=2), encoding="ascii")
        return {"repo": owner_repo, "slug": slug, "status": "ok", "tier": tier, "score": score}
    return {"repo": owner_repo, "slug": slug, "status": "no-profile"}


def main() -> int:
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])
    todo = [r for r in ROSTER if not _scanned(_slug(r))]
    if limit:
        todo = todo[:limit]
    print(f"roster={len(ROSTER)}  already_scanned={len(ROSTER)-len([r for r in ROSTER if not _scanned(_slug(r))])}  to_scan={len(todo)}")
    results = []
    for i, repo in enumerate(todo, 1):
        r = scan_one(repo)
        results.append(r)
        extra = f"{r.get('tier','')} {r.get('score','')}" if r["status"] == "ok" else ""
        print(f"[{i}/{len(todo)}] {r['status']:<22} {repo}  {extra}", flush=True)
    ok = [r for r in results if r["status"] == "ok"]
    print(f"\nDONE: {len(ok)} scanned ok, {len(results)-len(ok)} skipped/failed")
    from collections import Counter
    print("tiers:", dict(Counter(r.get("tier") for r in ok)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
