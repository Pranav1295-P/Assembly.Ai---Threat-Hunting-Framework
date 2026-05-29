"""Generate the final analysis PDF using ReportLab + matplotlib for the
process-tree diagram. Output: backend/reports_out/<analysis_id>.pdf"""
from __future__ import annotations

import io
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
from reportlab.lib            import colors
from reportlab.lib.pagesizes  import A4
from reportlab.lib.styles     import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units      import mm
from reportlab.platypus       import (
    Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

import config

NAVY    = colors.HexColor("#0B2545")
ACCENT  = colors.HexColor("#13315C")
SOFT    = colors.HexColor("#EEF2F7")
RED     = colors.HexColor("#B00020")
ORANGE  = colors.HexColor("#C77700")
GREEN   = colors.HexColor("#1B5E20")
BORDER  = colors.HexColor("#CFD8DC")


# ----------------------------- helpers -----------------------------

def _severity_color(sev: str):
    return {"critical": RED, "high": RED, "medium": ORANGE,
            "low": GREEN, "benign": GREEN}.get((sev or "").lower(), ACCENT)


def _verdict_color(v: str):
    return {"malicious": RED, "suspicious": ORANGE, "benign": GREEN
            }.get((v or "").lower(), ACCENT)


def _styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle("H0",  parent=s["Heading1"], fontSize=22, leading=26,
                         textColor=NAVY, spaceAfter=4))
    s.add(ParagraphStyle("Sub", parent=s["Normal"],   fontSize=11, leading=14,
                         textColor=ACCENT, spaceAfter=12))
    s.add(ParagraphStyle("H1",  parent=s["Heading2"], fontSize=14, leading=18,
                         textColor=NAVY, spaceBefore=14, spaceAfter=8))
    s.add(ParagraphStyle("H2",  parent=s["Heading3"], fontSize=11, leading=14,
                         textColor=ACCENT, spaceBefore=8, spaceAfter=4))
    s.add(ParagraphStyle("Body", parent=s["Normal"], fontSize=9.5, leading=13))
    s.add(ParagraphStyle("Small", parent=s["Normal"], fontSize=8, leading=10,
                         textColor=colors.grey))
    s.add(ParagraphStyle("Mono", parent=s["Code"], fontSize=8, leading=10))
    return s


def _process_tree_image(tree: List[Dict[str, str]]) -> bytes | None:
    if not tree:
        return None
    G = nx.DiGraph()
    for edge in tree:
        parent = edge.get("parent") or "?"
        child  = edge.get("child")  or "?"
        via    = edge.get("via", "")
        G.add_edge(parent, child, via=via)
    if G.number_of_edges() == 0:
        return None

    fig, ax = plt.subplots(figsize=(7.2, 4.0), dpi=150)
    try:
        pos = nx.nx_agraph.graphviz_layout(G, prog="dot")  # if pygraphviz
    except Exception:
        # Fall back to a top-down layered layout based on BFS depth.
        roots = [n for n, d in G.in_degree() if d == 0] or [next(iter(G.nodes))]
        depth = {}
        for r in roots:
            for n, d in nx.single_source_shortest_path_length(G, r).items():
                depth[n] = max(depth.get(n, 0), d)
        # group nodes by depth
        layers: Dict[int, List[str]] = {}
        for n, d in depth.items():
            layers.setdefault(d, []).append(n)
        pos = {}
        for d, nodes in layers.items():
            for i, n in enumerate(sorted(nodes)):
                pos[n] = (i - (len(nodes) - 1) / 2.0, -d)

    nx.draw_networkx_edges(G, pos, ax=ax, arrows=True,
                           edge_color="#13315C", width=1.4,
                           arrowsize=14, connectionstyle="arc3,rad=0.05")
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color="#EEF2F7",
                           edgecolors="#0B2545", linewidths=1.4,
                           node_size=2400)
    nx.draw_networkx_labels(G, pos, ax=ax, font_size=8, font_color="#0B2545")
    edge_labels = nx.get_edge_attributes(G, "via")
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, ax=ax,
                                 font_size=7, font_color="#5A6B7A")
    ax.set_axis_off()
    ax.set_title("Reconstructed Process Tree", fontsize=11, color="#0B2545")
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="PNG", bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def _kv_table(rows: List[tuple[str, str]], col1=45 * mm, col2=125 * mm) -> Table:
    t = Table(rows, colWidths=[col1, col2])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (0, -1), SOFT),
        ("TEXTCOLOR",    (0, 0), (0, -1), NAVY),
        ("FONTNAME",     (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("BOX",          (0, 0), (-1, -1), 0.4, BORDER),
        ("INNERGRID",    (0, 0), (-1, -1), 0.25, BORDER),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]))
    return t


def _on_page(canvas, doc):
    canvas.saveState()
    # Header
    canvas.setFillColor(NAVY)
    canvas.rect(0, A4[1] - 18 * mm, A4[0], 18 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 13)
    canvas.drawString(15 * mm, A4[1] - 10 * mm, "Assembly.AI")
    canvas.setFont("Helvetica", 9)
    canvas.drawString(15 * mm, A4[1] - 14 * mm, "AI-Sec-Ops • Malware Analysis Report")
    canvas.drawRightString(A4[0] - 15 * mm, A4[1] - 12 * mm,
                           datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    # Footer
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, A4[0], 12 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(15 * mm, 4.5 * mm,
                      "Proudly Designed And Developed At B.M.S. College Of Engineering, Bengaluru, India")
    canvas.drawRightString(A4[0] - 15 * mm, 4.5 * mm,
                           f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


# ----------------------------- main entry -----------------------------

def generate(analysis: Dict[str, Any]) -> Path:
    aid = analysis["analysis_id"]
    out_path = Path(config.REPORT_DIR) / f"{aid}.pdf"

    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        leftMargin=15 * mm, rightMargin=15 * mm,
        topMargin=24 * mm,  bottomMargin=18 * mm,
        title=f"Assembly.AI Report {aid}",
    )
    s = _styles()
    story: list = []

    static = analysis["static"]
    ml     = analysis["ml"]
    iocs   = analysis["iocs"]
    ai     = analysis["ai"]
    mitre  = analysis["mitre"]

    verdict  = (ai.get("verdict")  or "unknown").upper()
    severity = (ai.get("severity") or "unknown").upper()

    # ---------- Title block ----------
    story += [
        Paragraph("Malware Analysis Report", s["H0"]),
        Paragraph(f"Analysis ID: <b>{aid}</b>", s["Sub"]),
    ]

    verdict_table = Table(
        [[
            Paragraph(f"<b>Verdict</b><br/><font color='{_verdict_color(ai.get('verdict')).hexval()}' size='13'><b>{verdict}</b></font>", s["Body"]),
            Paragraph(f"<b>Severity</b><br/><font color='{_severity_color(ai.get('severity')).hexval()}' size='13'><b>{severity}</b></font>", s["Body"]),
            Paragraph(f"<b>Confidence</b><br/><font size='13'><b>{ai.get('confidence', 0):.0%}</b></font>", s["Body"]),
            Paragraph(f"<b>Static Risk</b><br/><font size='13'><b>{static.get('static_risk_score', 0)}/100</b></font>", s["Body"]),
            Paragraph(f"<b>ML Probability</b><br/><font size='13'><b>"
                      f"{(ml.get('malicious_probability') if ml.get('malicious_probability') is not None else 0):.0%}"
                      f"</b></font>", s["Body"]),
        ]],
        colWidths=[36*mm]*5,
    )
    verdict_table.setStyle(TableStyle([
        ("BOX",       (0, 0), (-1, -1), 0.5, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, BORDER),
        ("BACKGROUND",(0, 0), (-1, -1), SOFT),
        ("VALIGN",    (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",     (0, 0), (-1, -1), "CENTER"),
        ("LEFTPADDING",(0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
    ]))
    story += [verdict_table, Spacer(1, 6 * mm)]

    # ---------- Executive Summary ----------
    story += [
        Paragraph("Executive Summary", s["H1"]),
        Paragraph(ai.get("executive_summary",
                  "No summary available."), s["Body"]),
    ]
    if ai.get("malware_family"):
        story += [Spacer(1, 2*mm),
                  Paragraph(f"<b>Suspected family:</b> {ai['malware_family']}",
                            s["Body"])]

    # ---------- File Information ----------
    story += [Paragraph("File Information", s["H1"])]
    h = static.get("hashes", {})
    rows = [
        ("Filename",   static.get("filename", "")),
        ("Type",       static.get("filetype", "")),
        ("Size",       f"{static.get('size_bytes', 0):,} bytes"),
        ("Entropy",    f"{static.get('entropy', 0)} (max 8.0)"),
        ("MD5",        h.get("md5", "")),
        ("SHA-1",      h.get("sha1", "")),
        ("SHA-256",    h.get("sha256", "")),
    ]
    story += [_kv_table(rows)]

    # ---------- PE Header ----------
    pe = static.get("pe") or {}
    if pe.get("is_pe"):
        story += [Paragraph("PE Header Details", s["H1"])]
        story += [_kv_table([
            ("Architecture",  str(pe.get("arch"))),
            ("Type",          ", ".join(filter(None, [
                                "DLL"    if pe.get("is_dll")    else None,
                                "EXE"    if pe.get("is_exe")    else None,
                                "Driver" if pe.get("is_driver") else None,
                              ])) or "-"),
            ("Image Base",    str(pe.get("image_base", ""))),
            ("Entry Point",   str(pe.get("entry_point", ""))),
            ("Sections",      str(pe.get("section_count", 0))),
            ("Import DLLs",   str(pe.get("import_dll_count", 0))),
            ("Import Funcs",  str(pe.get("import_func_count", 0))),
        ])]

        # sections table
        sec_rows = [["Name", "Virt Size", "Raw Size", "Entropy", "Char."]]
        for sec in pe.get("sections", [])[:14]:
            sec_rows.append([sec["name"], f"{sec['virtual_size']:,}",
                             f"{sec['raw_size']:,}", f"{sec['entropy']}",
                             sec["characteristics"]])
        sec_t = Table(sec_rows, colWidths=[28*mm, 28*mm, 28*mm, 22*mm, 28*mm])
        sec_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 8.5),
            ("BOX",        (0, 0), (-1, -1), 0.4, BORDER),
            ("INNERGRID",  (0, 0), (-1, -1), 0.25, BORDER),
            ("ALIGN",      (1, 1), (-1, -1), "RIGHT"),
        ]))
        story += [Spacer(1, 2*mm), sec_t]

    # ---------- Suspicious APIs ----------
    apis = static.get("suspicious_apis", [])
    if apis:
        story += [Paragraph("Suspicious API Calls", s["H1"])]
        rows = [["API", "Reason"]]
        for a in apis[:30]:
            rows.append([a["api"], a["reason"]])
        t = Table(rows, colWidths=[45*mm, 125*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME",  (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",  (0, 0), (-1, -1), 8.5),
            ("BOX",       (0, 0), (-1, -1), 0.4, BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
            ("VALIGN",    (0, 0), (-1, -1), "TOP"),
        ]))
        story += [t]

    if static.get("packer_hints"):
        story += [Paragraph("Packer / Obfuscation Hints", s["H2"])]
        for hint in static["packer_hints"]:
            story += [Paragraph(f"• {hint}", s["Body"])]

    story += [PageBreak()]

    # ---------- Attack Chain ----------
    story += [Paragraph("AI Investigation — Attack Chain", s["H1"])]
    chain = ai.get("attack_chain", [])
    if chain:
        rows = [["#", "Stage", "Action", "Evidence"]]
        for step in chain:
            rows.append([
                str(step.get("step", "")),
                step.get("stage", ""),
                step.get("action", ""),
                Paragraph(step.get("evidence", ""), s["Body"]),
            ])
        t = Table(rows, colWidths=[10*mm, 32*mm, 50*mm, 78*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME",  (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",  (0, 0), (-1, -1), 8.5),
            ("VALIGN",    (0, 0), (-1, -1), "TOP"),
            ("BOX",       (0, 0), (-1, -1), 0.4, BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
        ]))
        story += [t]
    else:
        story += [Paragraph("No attack chain reconstructed.", s["Body"])]

    # ---------- Process Tree ----------
    img_bytes = _process_tree_image(ai.get("process_tree", []))
    if img_bytes:
        story += [Paragraph("Process Tree", s["H1"]),
                  Image(io.BytesIO(img_bytes), width=170*mm, height=95*mm)]

    # ---------- MITRE ATT&CK ----------
    if mitre:
        story += [Paragraph("MITRE ATT&amp;CK Coverage", s["H1"])]
        rows = [["Tactic", "Technique", "Name", "Evidence"]]
        for m in mitre:
            rows.append([
                m.get("tactic", ""),
                m.get("id", ""),
                m.get("name", ""),
                Paragraph(m.get("evidence", ""), s["Body"]),
            ])
        t = Table(rows, colWidths=[36*mm, 22*mm, 44*mm, 68*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME",  (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",  (0, 0), (-1, -1), 8),
            ("VALIGN",    (0, 0), (-1, -1), "TOP"),
            ("BOX",       (0, 0), (-1, -1), 0.4, BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
        ]))
        story += [t]

    story += [PageBreak()]

    # ---------- IOCs ----------
    story += [Paragraph("Indicators of Compromise", s["H1"])]
    any_ioc = False
    for label, key in [
        ("URLs", "urls"), ("Domains", "domains"), ("IPv4 Addresses", "ipv4"),
        ("Email Addresses", "emails"), ("Bitcoin Addresses", "btc"),
        ("Ethereum Addresses", "eth"), ("Registry Keys", "registry"),
        ("File Paths", "filepaths"), ("Mutexes", "mutexes"),
    ]:
        items = iocs.get(key) or []
        if not items:
            continue
        any_ioc = True
        story += [Paragraph(f"{label}  ({len(items)})", s["H2"])]
        rows = [[textwrap.shorten(x, 95)] for x in items[:25]]
        t = Table(rows, colWidths=[170 * mm])
        t.setStyle(TableStyle([
            ("FONTNAME",  (0, 0), (-1, -1), "Courier"),
            ("FONTSIZE",  (0, 0), (-1, -1), 8),
            ("BOX",       (0, 0), (-1, -1), 0.3, BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.2, BORDER),
        ]))
        story += [t, Spacer(1, 2 * mm)]

    if not any_ioc:
        story += [Paragraph("No IOCs extracted from the sample.", s["Body"])]

    # ---------- Recommendations ----------
    story += [Paragraph("Recommendations", s["H1"])]
    for rec in (ai.get("recommendations") or []):
        story += [Paragraph(f"• {rec}", s["Body"])]

    # ---------- Footer / provenance ----------
    story += [Spacer(1, 6 * mm),
              Paragraph(f"Analysis engine: Assembly.AI · LLM provider: "
                        f"<b>{ai.get('_provider', 'n/a')}</b> · "
                        f"ML model: {ml.get('model_version', 'n/a')}",
                        s["Small"])]

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return out_path
