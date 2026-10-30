"""CVSS v3.1 Triage & Priority Scoring Engine (stage 6)."""
import json
import urllib.parse
from core.memory import scan_dir

CVSS_TABLE = {
    "sql": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "command": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "ssrf": (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"),
    "template": (8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"),
    "xss": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"),
    "lfi": (7.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "traversal": (7.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "403": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    "env": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "git": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
}


def triage_findings(target: str, findings: list) -> list[dict]:
    parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}")
    host_label = parsed.netloc or target
    triaged = []
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        low = (d.get("type") or "").lower()
        score, vec = 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
        for k, (sc, vc) in CVSS_TABLE.items():
            if k in low:
                score, vec = sc, vc
                break
        d["cvss_score"] = score
        d["cvss_vector"] = vec
        d["priority"] = "P1" if score >= 9.0 else ("P2" if score >= 7.5 else "P3")
        triaged.append(d)

    triaged.sort(key=lambda x: x["cvss_score"], reverse=True)
    sd = scan_dir(host_label)
    (sd / "triaged.json").write_text(json.dumps(triaged, indent=2))
    return triaged


run = triage_findings
