"""_gen_registry.py — build the public OAO Agent Governance Registry page.

Reads every scan under docs/scans/<slug>/ (trust_profile.json + ontology.json +
receipt.json), joins the editorial manifest.json (verifiable repo/commit facts
only), and emits a single self-contained, DDU-themed index.html plus a
machine-readable data.json for AEO.

INVARIANT (pol.must_do.143): every tier, score, count, framework and atom_id on
the page is read from the scan artifacts. The generator computes nothing about
governance itself; it only lays out what the scanner already signed.

  python docs/registry/_gen_registry.py        # writes docs/registry/{index.html,data.json}

stdlib only. No network. No execution of scanned code.
"""
from __future__ import annotations

import html
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCS = HERE.parent
SCANS = DOCS / "scans"
SAFE_TIERS = {"SOVEREIGN", "HARDENED"}           # ENTERPRISE_SAFE gate (== certify())
TIER_RANK = {"SOVEREIGN": 3, "HARDENED": 2, "DEVELOPING": 1, "UNGOVERNED": 0}


def _load(p: Path) -> dict:
    # scan artifacts are ASCII; the hand-authored manifest is UTF-8 — utf-8 reads both.
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _counts(onto: dict) -> dict:
    """Asserted / inferred / ungoverned action counts — mirrors cli._json_payload."""
    ams = onto.get("action_maps", [])
    asserted = sum(1 for a in ams if a.get("matched_via") == "asserted_table")
    inferred = sum(1 for a in ams if a.get("matched_via") == "heuristic")
    ungoverned = sum(1 for a in ams if a.get("matched_via") == "none")
    return {"actions": len(ams), "asserted": asserted,
            "inferred": inferred, "ungoverned": ungoverned,
            "nodes": len(onto.get("nodes", [])), "edges": len(onto.get("edges", []))}


def collect() -> list[dict]:
    manifest = _load(HERE / "manifest.json").get("entries", {})
    rows = []
    for d in sorted(SCANS.iterdir()):
        if not d.is_dir():
            continue
        profile = _load(d / "trust_profile.json")
        onto = _load(d / "ontology.json")
        receipt = _load(d / "receipt.json")
        if not profile or not onto:
            continue
        # precedence: curated manifest.json overrides the driver's per-scan _meta.json
        meta = manifest.get(d.name, {})
        sm = _load(d / "_meta.json")
        c = _counts(onto)
        tier = profile.get("tier", "UNGOVERNED")
        rows.append({
            "slug": d.name,
            "display": meta.get("display") or sm.get("display") or onto.get("source", d.name),
            "kind": meta.get("kind") or sm.get("kind") or "real",
            "repo_url": meta.get("repo_url") or sm.get("repo_url") or "",
            "commit": meta.get("commit") or sm.get("commit") or "",
            "note": meta.get("note") or sm.get("note") or "",
            "tier": tier,
            "score": int(profile.get("score", 0)),
            "frameworks": sorted(onto.get("frameworks", [])),
            "counts": c,
            "enterprise_safe": tier in SAFE_TIERS,
            "atom_id": receipt.get("atom_id", ""),
            "evidence_hash": receipt.get("evidence_hash", ""),
            "signed": bool(receipt.get("signed")),
            "alg": receipt.get("alg", "none"),
            "has_gms": (d / "graph_resolutions.json").exists(),
        })
    # rank: tier desc, then score desc, then asserted desc
    rows.sort(key=lambda r: (TIER_RANK.get(r["tier"], 0), r["score"],
                             r["counts"]["asserted"]), reverse=True)
    return rows


# ── HTML ----------------------------------------------------------------------
TIER_CLASS = {"SOVEREIGN": "t-sov", "HARDENED": "t-hard",
              "DEVELOPING": "t-dev", "UNGOVERNED": "t-ung"}


def _esc(s) -> str:
    return html.escape(str(s), quote=True)


def _row_html(r: dict) -> str:
    tcls = TIER_CLASS.get(r["tier"], "t-ung")
    c = r["counts"]
    safe = ('<span class="chip chip-safe">ENTERPRISE&#8209;SAFE</span>'
            if r["enterprise_safe"]
            else '<span class="chip chip-unsafe">NOT&nbsp;SAFE</span>')
    kind = ('<span class="kind kind-real">real&nbsp;third&#8209;party</span>'
            if r["kind"] == "real"
            else '<span class="kind kind-ref">CWN&nbsp;reference</span>')
    fw = ", ".join(_esc(f) for f in r["frameworks"]) or "<span class='muted'>none</span>"
    commit = f' <span class="muted">@{_esc(r["commit"])}</span>' if r["commit"] else ""
    repo = (f'<a href="{_esc(r["repo_url"])}" target="_blank" rel="noopener">{_esc(r["display"])}</a>'
            if r["repo_url"] else _esc(r["display"]))
    base = f"../scans/{_esc(r['slug'])}"
    links = " ".join([
        f'<a href="{base}/badge.svg" target="_blank" rel="noopener">badge</a>',
        f'<a href="{base}/trust_profile.json" target="_blank" rel="noopener">profile</a>',
        f'<a href="{base}/receipt.json" target="_blank" rel="noopener">receipt</a>',
        f'<a href="{base}/ontology.json" target="_blank" rel="noopener">ontology</a>',
    ] + ([f'<a href="{base}/graph_resolutions.json" target="_blank" rel="noopener">graph</a>']
         if r["has_gms"] else []))
    return f"""<tr class="{tcls}">
  <td class="c-proj"><div class="proj">{repo}{commit}</div><div class="note">{kind} &middot; {_esc(r['note'])}</div></td>
  <td class="c-tier"><span class="tier {tcls}">{_esc(r['tier'])}</span></td>
  <td class="c-score"><span class="score">{r['score']}</span><span class="muted">/100</span></td>
  <td class="c-cov"><b>{c['asserted']}</b><span class="muted">/{c['actions']}</span></td>
  <td class="c-fw">{fw}</td>
  <td class="c-safe">{safe}</td>
  <td class="c-links">{links}</td>
</tr>"""


def render(rows: list[dict]) -> str:
    real = [r for r in rows if r["kind"] == "real"]
    n_real = len(real)
    n_real_ung = sum(1 for r in real if r["tier"] == "UNGOVERNED")
    n_safe = sum(1 for r in rows if r["enterprise_safe"])
    total_actions = sum(r["counts"]["actions"] for r in real)
    total_asserted = sum(r["counts"]["asserted"] for r in real)
    body_rows = "\n".join(_row_html(r) for r in rows)

    ld = {
        "@context": "https://schema.org", "@type": "Dataset",
        "name": "OpenAgentOntology Agent Governance Registry",
        "description": ("A public registry of AI agents and MCP servers scanned with "
                        "OpenAgentOntology. Each entry lists the governance tier, score, "
                        "and framework coverage (NIST 800-53, EU AI Act, OWASP LLM Top 10, "
                        "MITRE ATT&CK), with a signed, reproducible receipt."),
        "url": "https://agent-ontology.cyberwarriornetwork.com/registry/",
        "creator": {"@type": "Organization", "name": "Cyber Warrior Network",
                    "url": "https://cyberwarriornetwork.com"},
        "isAccessibleForFree": True,
        "keywords": ["AI agent governance", "MITRE ATT&CK", "NIST 800-53",
                     "EU AI Act", "ENTERPRISE_SAFE", "agent security"],
    }

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Governance Registry — OpenAgentOntology (NIST · EU AI Act · MITRE ATT&CK)</title>
<meta name="description" content="A public registry of real AI agents and MCP servers scanned for governance coverage. {n_real_ung} of {n_real} real-world agents scored UNGOVERNED — zero side-effecting actions mapped to an asserted control. Signed, reproducible.">
<link rel="canonical" href="https://agent-ontology.cyberwarriornetwork.com/registry/">
<link rel="icon" type="image/svg+xml" href="../../favicon.svg">
<link rel="apple-touch-icon" sizes="180x180" href="../../apple-touch-icon.png">
<meta property="og:type" content="website">
<meta property="og:title" content="Agent Governance Registry — OpenAgentOntology">
<meta property="og:description" content="{n_real_ung} of {n_real} real-world agents scanned came back UNGOVERNED. See the signed receipts.">
<meta property="og:site_name" content="Cyber Warrior Network">
<meta name="twitter:card" content="summary_large_image">
<script type="application/ld+json">{json.dumps(ld, separators=(',', ':'))}</script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Archivo+Black&family=Bebas+Neue&family=DM+Sans:wght@400;600&family=JetBrains+Mono:wght@400;500&display=swap');
:root{{
  --bg:#0A0A0A; --orange:#FF4500; --cream:#EFEBE2;
  --dim:rgba(239,235,226,0.55); --dimLo:rgba(239,235,226,0.30); --dimXLo:rgba(239,235,226,0.12);
  --cardBg:rgba(239,235,226,0.04); --border:rgba(255,69,0,0.22); --line:rgba(239,235,226,0.10);
  --head:'Archivo Black',sans-serif; --label:'Bebas Neue',sans-serif;
  --mono:'JetBrains Mono',monospace; --body:'DM Sans',sans-serif;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{background:var(--bg);color:var(--cream);font-family:var(--body);font-size:16px;line-height:1.6}}
a{{color:var(--orange);text-decoration:none}} a:hover{{text-decoration:underline}}
.inner{{max-width:1180px;margin:0 auto;padding:0 20px}}
section{{padding:clamp(34px,5vw,56px) 0;border-top:1px solid var(--border)}}
.section-label{{font-family:var(--label);font-size:13px;letter-spacing:.2em;color:var(--orange);margin-bottom:14px}}
.h2{{font-family:var(--head);font-size:clamp(20px,3.5vw,32px);color:var(--cream);line-height:1.14;margin-bottom:14px}}
.body-text{{color:var(--dim);font-size:15px;line-height:1.66;max-width:820px}}
.muted{{color:var(--dim)}}
.mono{{font-family:var(--mono)}}
nav{{border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;background:rgba(10,10,10,.92);backdrop-filter:blur(8px);padding:14px 0}}
nav .inner{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}}
.wordmark{{font-family:var(--head);font-size:15px;color:var(--cream);letter-spacing:.02em}}
.wordmark span{{color:var(--orange)}}
.navlinks{{display:flex;gap:6px;flex-wrap:wrap}}
.navlinks a{{font-family:var(--mono);font-size:11px;color:var(--dim);padding:6px 12px;border:1px solid var(--border)}}
.navlinks a:hover{{border-color:var(--orange);color:var(--cream);text-decoration:none}}
.hero{{padding:clamp(40px,6vw,72px) 0 clamp(26px,4vw,44px)}}
.hero h1{{font-family:var(--head);font-size:clamp(28px,5.4vw,52px);color:var(--cream);line-height:1.04;margin-bottom:20px;max-width:940px}}
.hero h1 span{{color:var(--orange)}}
.lede{{color:var(--dim);font-size:clamp(15px,2vw,18px);max-width:760px;line-height:1.6}}
.lede b{{color:var(--cream)}}
.stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:1px;border:1.5px solid var(--border);margin-top:28px}}
.stat-cell{{background:var(--cardBg);padding:20px}}
.stat-num{{font-family:var(--head);font-size:clamp(26px,4vw,40px);line-height:1}}
.stat-cap{{font-size:12px;color:var(--dim);margin-top:8px;line-height:1.4}}
.n-red{{color:var(--orange)}} .n-orange{{color:var(--orange)}} .n-cream{{color:var(--cream)}} .n-green{{color:var(--cream)}} .n-dim{{color:var(--dim)}}
.tablewrap{{overflow-x:auto;border:1.5px solid var(--border)}}
table{{width:100%;border-collapse:collapse;min-width:860px}}
thead th{{font-family:var(--label);font-size:12px;letter-spacing:.14em;color:var(--orange);text-align:left;padding:14px 14px;border-bottom:1.5px solid var(--border);white-space:nowrap}}
tbody td{{padding:14px 14px;border-bottom:1px solid rgba(239,235,226,.08);vertical-align:top;font-size:13.5px}}
tbody tr:last-child td{{border-bottom:none}}
.proj{{font-family:var(--mono);font-size:14px;color:var(--cream)}}
.proj a{{color:var(--cream)}} .proj a:hover{{color:var(--orange)}}
.note{{font-size:11.5px;color:var(--dim);margin-top:5px;max-width:360px;line-height:1.4}}
.kind{{font-family:var(--mono);font-size:10px;letter-spacing:.05em;padding:1px 6px;border:1px solid var(--dimLo)}}
.kind-real{{color:var(--orange);border-color:var(--border)}}
.kind-ref{{color:var(--dim)}}
/* Tier = a FILL LADDER (governance coverage), one hue: solid -> filled -> outline -> ghost */
.tier{{font-family:var(--label);font-size:14px;letter-spacing:.1em;padding:3px 11px;display:inline-block;border:1.5px solid}}
.tier.t-sov{{color:var(--bg);background:var(--orange);border-color:var(--orange)}}
.tier.t-hard{{color:var(--orange);background:rgba(255,69,0,.14);border-color:var(--orange)}}
.tier.t-dev{{color:var(--cream);background:transparent;border-color:var(--dimLo)}}
.tier.t-ung{{color:var(--dim);background:transparent;border-color:var(--dimXLo);border-style:dashed}}
.score{{font-family:var(--head);font-size:20px;color:var(--cream)}}
.t-sov .score{{color:var(--orange)}} .t-ung .score{{color:var(--dim)}}
.c-cov b{{font-family:var(--head);font-size:16px;color:var(--cream)}}
.c-fw{{font-family:var(--mono);font-size:11.5px;color:var(--dim);max-width:220px}}
.chip{{font-family:var(--mono);font-size:10px;letter-spacing:.04em;padding:4px 8px;white-space:nowrap;display:inline-block}}
.chip-safe{{color:var(--bg);background:var(--orange);border:1px solid var(--orange)}}
.chip-unsafe{{color:var(--dim);background:transparent;border:1px dashed var(--dimLo)}}
.c-links{{font-family:var(--mono);font-size:11px;white-space:nowrap}}
.c-links a{{color:var(--dim);margin-right:9px}} .c-links a:hover{{color:var(--orange);text-decoration:none}}
.callout{{display:grid;grid-template-columns:1fr 1fr;gap:1px;border:1.5px solid var(--border);margin-top:22px}}
.callout > div{{background:var(--cardBg);padding:22px}}
.callout h3{{font-family:var(--head);font-size:15px;margin-bottom:8px}}
.callout .big{{font-family:var(--head);font-size:clamp(26px,4vw,40px);line-height:1}}
.callout p{{font-size:13px;color:var(--dim);margin-top:8px;line-height:1.5}}
.legend{{display:flex;flex-wrap:wrap;gap:14px;margin-top:18px;font-family:var(--mono);font-size:12px;color:var(--dim)}}
.legend span b{{color:var(--cream)}}
.repro{{font-family:var(--mono);font-size:12.5px;color:var(--dim);background:#070707;border:1px solid var(--border);padding:16px;overflow-x:auto;line-height:1.7;margin-top:14px}}
.repro .cmd{{color:var(--cream)}}
.note-box{{font-family:var(--mono);font-size:12px;color:var(--dim);border:1px solid var(--border);border-left:3px solid var(--orange);background:var(--cardBg);padding:12px 14px;margin-top:18px;line-height:1.6}}
.cta{{display:inline-block;font-family:var(--head);font-size:14px;color:var(--bg);background:var(--orange);padding:13px 24px;margin-top:8px}}
.cta:hover{{text-decoration:none;opacity:.92}}
.tier-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:1px;border:1.5px solid var(--border);margin-top:22px;background:var(--border)}}
.tier-card{{background:var(--bg);padding:20px 18px;text-align:center}}
.tier-card img{{width:100%;max-width:178px;height:auto;display:block;margin:0 auto 12px;border:1px solid var(--line)}}
.tier-card .tname{{font-family:var(--label);font-size:15px;letter-spacing:.12em;color:var(--cream);margin-bottom:6px}}
.tier-card figcaption{{font-size:12px;color:var(--dim);line-height:1.5}}
footer{{border-top:1px solid var(--border);padding:30px 0;color:var(--dim);font-family:var(--mono);font-size:12px}}
@media(max-width:640px){{
  .callout{{grid-template-columns:1fr}}
  .note{{max-width:none}}
}}
</style>
</head>
<body>
<nav><div class="inner">
  <div class="wordmark">Open<span>Agent</span>Ontology</div>
  <div class="navlinks">
    <a href="../../">Home</a>
    <a href="../../demo/">Demo</a>
    <a href="#registry">Registry</a>
    <a href="#method">Method</a>
    <a href="https://github.com/CWNApps/openagentontology" target="_blank" rel="noopener">GitHub</a>
  </div>
</div></nav>

<header class="hero"><div class="inner">
  <div class="section-label">THE AGENT GOVERNANCE REGISTRY</div>
  <h1>The agents people run in production answer to <span>no control at all.</span></h1>
  <p class="lede">We pointed OpenAgentOntology at {n_real} of the most-used autonomous agents and MCP servers on GitHub. <b>{n_real_ung} of {n_real} came back UNGOVERNED</b> — across {total_actions} side-effecting actions, <b>{total_asserted}</b> mapped to an asserted governance control. Every row below is a signed, reproducible scan. Verify any of them.</p>
  <div class="stat-grid">
    <div class="stat-cell"><div class="stat-num n-red">{n_real_ung}/{n_real}</div><div class="stat-cap">real-world agents scored UNGOVERNED</div></div>
    <div class="stat-cell"><div class="stat-num n-red">{total_asserted}/{total_actions}</div><div class="stat-cap">side-effecting actions with an asserted control</div></div>
    <div class="stat-cell"><div class="stat-num n-green">{n_safe}</div><div class="stat-cap">entries that earn ENTERPRISE&#8209;SAFE (HARDENED+)</div></div>
    <div class="stat-cell"><div class="stat-num n-cream">{len(rows)}</div><div class="stat-cap">total signed scans in this registry</div></div>
  </div>
</div></header>

<section id="tiers"><div class="inner">
  <div class="section-label">THE GOVERNANCE LADDER</div>
  <div class="h2">Four tiers. One question each scan answers: who answers for the action?</div>
  <p class="body-text">Tier is coverage made visible — how much of an agent's side-effecting surface maps to an asserted governance control. The badge fills as the governance does.</p>
  <div class="tier-grid">
    <figure class="tier-card"><img src="badges/sovereign.png" alt="SOVEREIGN tier badge"><div class="tname">SOVEREIGN</div><figcaption>Nearly every action maps to an asserted control. Earns ENTERPRISE&#8209;SAFE.</figcaption></figure>
    <figure class="tier-card"><img src="badges/hardened.png" alt="HARDENED tier badge"><div class="tname">HARDENED</div><figcaption>Strong coverage with asserted controls on the high-risk actions. Also ENTERPRISE&#8209;SAFE.</figcaption></figure>
    <figure class="tier-card"><img src="badges/developing.png" alt="DEVELOPING tier badge"><div class="tname">DEVELOPING</div><figcaption>Partial coverage — some actions mapped, the high-risk ones not yet.</figcaption></figure>
    <figure class="tier-card"><img src="badges/ungoverned.png" alt="UNGOVERNED tier badge"><div class="tname">UNGOVERNED</div><figcaption>No asserted control answers for the side-effecting actions. Where every scan below lands.</figcaption></figure>
  </div>
</div></section>

<section id="registry"><div class="inner">
  <div class="section-label">LEADERBOARD</div>
  <div class="h2">Every scan, ranked by governance coverage</div>
  <p class="body-text">Sorted by tier, then score. <b style="color:var(--cream)">ENTERPRISE&#8209;SAFE</b> = tier HARDENED or above — the same gate the CWN hosted notary uses to certify. Coverage is <b style="color:var(--cream)">asserted</b> controls (confirmed against published framework text) over total side-effecting actions; heuristic / inferred mappings are proposed, not asserted (pol.must_do.143).</p>
  <div class="legend">
    <span>tier fill = governance coverage: <b class="n-orange">SOVEREIGN</b> solid &rarr; HARDENED filled &rarr; DEVELOPING outline &rarr; <b class="n-dim">UNGOVERNED</b> ghost</span>
    <span><b class="n-orange">real third-party</b> = scanned from the public repo &middot; <b>CWN reference</b> = governed example</span>
  </div>
  <div class="tablewrap" style="margin-top:18px">
  <table>
    <thead><tr>
      <th>Target</th><th>Tier</th><th>Score</th><th>Asserted</th><th>Frameworks</th><th>Verdict</th><th>Evidence</th>
    </tr></thead>
    <tbody>
{body_rows}
    </tbody>
  </table>
  </div>
  <div class="note-box">Methodology: every real-world scan is pinned to the commit shown and reproduces from it (<span class="mono">python -m openagentontology &lt;repo&gt; --json</span>). Control mappings are evaluated against a static asserted-control table — they are <b style="color:var(--cream)">proposed, not asserted-for-audit</b>; confirm against published control text before relying on them. The CWN reference agents show the governed (SOVEREIGN) end of the scale and are labeled as references, not third-party results.</div>
</div></section>

<section id="contrast"><div class="inner">
  <div class="section-label">THE GAP</div>
  <div class="h2">Same scanner. Opposite verdicts.</div>
  <div class="callout">
    <div>
      <h3 class="n-orange">A governed agent</h3>
      <div class="big n-orange">SOVEREIGN</div>
      <p>The CWN reference agents map nearly every side-effecting action to an asserted NIST 800-53, EU AI Act, and OWASP LLM control. The receipt names the control for each one.</p>
    </div>
    <div>
      <h3 class="n-dim">An agent you can install today</h3>
      <div class="big n-dim">UNGOVERNED</div>
      <p><span class="mono">exec</span> — arbitrary code execution — maps to no control at all. There is no record of which control answers for it, because there is no control.</p>
    </div>
  </div>
</div></section>

<section id="method"><div class="inner">
  <div class="section-label">METHOD &amp; REPRODUCIBILITY</div>
  <div class="h2">Reproduce any row from its pinned commit</div>
  <p class="body-text">The scanner reads source as data (Python via <span class="mono">ast</span>, never executed), emits a deterministic typed ontology, scores it, and signs an Ed25519 cert-only receipt over the evidence hash. The same source always yields the same hash. Re-run any real-world row:</p>
  <div class="repro">
<span class="cmd">git clone https://github.com/OpenInterpreter/open-interpreter &amp;&amp; cd open-interpreter</span><br>
<span class="cmd">git checkout e00f08e</span><br>
<span class="cmd">pip install openagentontology</span><br>
<span class="cmd">python -m openagentontology . --json</span>  <span class="muted"># tier, score, signed receipt</span>
  </div>
  <p class="body-text" style="margin-top:18px">Honest method note: the open-source scanner uses a static, asserted control table plus heuristic verb mapping. The CWN hosted layer (OAO-GMS) additionally grounds each action through a live NIST&times;MITRE&times;CVE knowledge graph and mints a triple-signed resolution receipt — shown as the <span class="mono">graph</span> link where present. Graph-grounded mappings are <b style="color:var(--cream)">GRAPH_INFERRED</b>, never auto-asserted.</p>
  <a class="cta" href="https://github.com/CWNApps/openagentontology" target="_blank" rel="noopener">Scan your own agent &rarr;</a>
</div></section>

<footer><div class="inner">
  OpenAgentOntology &middot; by <a href="https://cyberwarriornetwork.com" target="_blank" rel="noopener">Cyber Warrior Network</a> &middot;
  Apache-2.0 &middot; every mapping is proposed, not asserted-for-audit — confirm against published control text.
</div></footer>
</body>
</html>
"""


def main() -> int:
    rows = collect()
    if not rows:
        print("no scans found under", SCANS)
        return 1
    (HERE / "index.html").write_text(render(rows), encoding="utf-8")
    (HERE / "data.json").write_text(
        json.dumps({"count": len(rows), "entries": rows}, indent=2), encoding="utf-8")
    safe = sum(1 for r in rows if r["enterprise_safe"])
    print(f"registry: {len(rows)} scans -> index.html  ({safe} ENTERPRISE_SAFE)")
    for r in rows:
        print(f"  {r['tier']:<11} {r['score']:>3}  {r['kind']:<9} {r['display']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
