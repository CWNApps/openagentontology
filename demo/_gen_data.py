"""_gen_data.py — build demo/data.js from REAL pipeline output for both demo agents.

Run from the repo root:  python demo/_gen_data.py
Emits demo/data.js with DATA_SAMPLE + DATA_HARDENED in the demo's node/edge/map shape.
Values are the actual crosswalk result — never hand-edited (pol.must_do.143).
"""
import json
from openagentontology.pipeline import run_pipeline


def shape(path):
    r = run_pipeline(path, make_receipt=False)
    o = r.ontology

    def node(n):
        d = n.to_dict()
        return {"id": d["id"], "type": d["type"], "name": d["name"], "props": d.get("props", {})}

    def mp(m):
        d = m.to_dict() if hasattr(m, "to_dict") else m
        return {"fw": d["fw"], "id": d["id"], "name": d["name"],
                "confidence": d["confidence"], "provenance": d["provenance"]}

    def amap(a):
        d = a.to_dict()
        return {"subject_id": d["subject_id"], "label": d["label"],
                "matched_via": d["matched_via"], "mappings": [mp(m) for m in d["mappings"]]}

    return {
        "nodes": [node(n) for n in o.nodes],
        "edges": [{"src": e.to_dict()["src"], "rel": e.to_dict()["rel"], "dst": e.to_dict()["dst"]}
                  for e in o.edges],
        "action_maps": [amap(a) for a in o.action_maps],
        "trust_profile": r.profile.to_dict(),
    }


def shape_from_scan(scan_dir):
    """Build a demo dataset from a committed real-world scan (docs/scans/<target>/), so the
    demo shows the EXACT signed result — not a re-run. Same shape as shape()."""
    o = json.load(open(scan_dir + "/ontology.json", encoding="ascii"))
    tp = json.load(open(scan_dir + "/trust_profile.json", encoding="ascii"))

    def mp(m):
        return {"fw": m["fw"], "id": m["id"], "name": m["name"],
                "confidence": m["confidence"], "provenance": m["provenance"]}

    return {
        "nodes": [{"id": n["id"], "type": n["type"], "name": n["name"], "props": n.get("props", {})}
                  for n in o["nodes"]],
        "edges": [{"src": e["src"], "rel": e["rel"], "dst": e["dst"]} for e in o["edges"]],
        "action_maps": [{"subject_id": a["subject_id"], "label": a["label"],
                         "matched_via": a["matched_via"], "mappings": [mp(m) for m in a["mappings"]]}
                        for a in o["action_maps"]],
        "trust_profile": tp,
    }


def emit(varname, d):
    L = [varname + "={nodes:["]
    L += [json.dumps(n, separators=(",", ":")) + "," for n in d["nodes"]]
    L[-1] = L[-1][:-1]
    L.append("],edges:[")
    L += [json.dumps(e, separators=(",", ":")) + "," for e in d["edges"]]
    L[-1] = L[-1][:-1]
    L.append("],action_maps:[")
    L += [json.dumps(a, separators=(",", ":")) + "," for a in d["action_maps"]]
    L[-1] = L[-1][:-1]
    L.append("],trust_profile:" + json.dumps(d["trust_profile"], separators=(",", ":")) + "};")
    return "\n".join(L)


def main():
    header = (
        "/* data.js -- REAL pipeline output for both demo agents. Regenerate with:\n"
        "     python demo/_gen_data.py\n"
        "   Values are the actual crosswalk result -- never hand-edited (pol.must_do.143). */\n"
    )
    s = shape("examples/sample_agent")
    h = shape("examples/hardened_agent")
    fde = shape("examples/agent_fde")                       # CWN's own agent — dogfood (SOVEREIGN)
    oi = shape_from_scan("docs/scans/open-interpreter")     # REAL signed scan, committed
    gpte = shape_from_scan("docs/scans/gpt-engineer")       # REAL signed scan, committed
    out = (header + "\n"
           + emit("var DATA_SAMPLE", s) + "\n\n"
           + emit("var DATA_HARDENED", h) + "\n\n"
           + emit("var DATA_FDE", fde) + "\n\n"
           + emit("var DATA_OI", oi) + "\n\n"
           + emit("var DATA_GPTE", gpte) + "\n")
    with open("demo/data.js", "w", encoding="ascii") as f:
        f.write(out)
    print("demo/data.js written:", len(out), "chars")
    for name, d in [("SAMPLE", s), ("HARDENED", h), ("AGENT_FDE", fde), ("OI(real)", oi), ("GPTE(real)", gpte)]:
        print(f"{name:11}", d["trust_profile"]["tier"], d["trust_profile"]["score"], "nodes", len(d["nodes"]))


if __name__ == "__main__":
    main()
