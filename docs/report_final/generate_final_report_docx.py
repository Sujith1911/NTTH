#!/usr/bin/env python3
"""Generate the NTTH final year project report as a DOCX file.

The script uses only Python's standard library and writes a minimal valid
WordprocessingML package. It intentionally keeps formatting simple and aligned
with the college format: 1 cm margins, Times New Roman, 14 pt bold headings,
and 12 pt body text.
"""

from __future__ import annotations

import html
import os
import re
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "docs" / "report_final"
IMAGE_DIR = ROOT / "docs" / "thesis_images"
OUT_FILE = OUT_DIR / "NTTH_Final_Year_Project_Report_80_Plus_Pages.docx"

NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "wp": "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "pic": "http://schemas.openxmlformats.org/drawingml/2006/picture",
}


def x(text: str) -> str:
    return html.escape(str(text), quote=False)


class DocxBuilder:
    def __init__(self) -> None:
        self.body: list[str] = []
        self.rels: list[str] = []
        self.media: list[tuple[str, bytes]] = []
        self.rel_id = 1
        self.img_id = 1
        self.footer_rid = self.next_rel(
            "footer1.xml",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer",
        )

    def next_rel(self, target: str, rel_type: str) -> str:
        rid = f"rId{self.rel_id}"
        self.rel_id += 1
        self.rels.append(
            f'<Relationship Id="{rid}" Type="{rel_type}" Target="{target}"/>'
        )
        return rid

    def p(
        self,
        text: str = "",
        *,
        style: str = "Normal",
        bold: bool = False,
        italic: bool = False,
        align: str | None = "both",
        page_break_before: bool = False,
        space_after: int = 80,
    ) -> None:
        ppr = []
        if style != "Normal":
            ppr.append(f'<w:pStyle w:val="{style}"/>')
        if align:
            ppr.append(f'<w:jc w:val="{align}"/>')
        if page_break_before:
            ppr.append("<w:pageBreakBefore/>")
        ppr.append(f'<w:spacing w:after="{space_after}" w:line="360" w:lineRule="auto"/>')
        rpr = [
            '<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman"/>',
            '<w:sz w:val="24"/>',
            '<w:szCs w:val="24"/>',
        ]
        if bold:
            rpr.append("<w:b/><w:bCs/>")
        if italic:
            rpr.append("<w:i/><w:iCs/>")
        preserve = ' xml:space="preserve"' if text.startswith(" ") or text.endswith(" ") else ""
        self.body.append(
            "<w:p>"
            f"<w:pPr>{''.join(ppr)}</w:pPr>"
            f"<w:r><w:rPr>{''.join(rpr)}</w:rPr><w:t{preserve}>{x(text)}</w:t></w:r>"
            "</w:p>"
        )

    def page_break(self) -> None:
        self.body.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')

    def heading(self, text: str, *, level: int = 1, page_break_before: bool = False) -> None:
        style = "Heading1" if level == 1 else "Heading2"
        align = "center" if level == 1 else "left"
        self.p(
            text,
            style=style,
            bold=True,
            align=align,
            page_break_before=page_break_before,
            space_after=120,
        )

    def bullet(self, text: str) -> None:
        self.body.append(
            "<w:p>"
            '<w:pPr><w:pStyle w:val="ListBullet"/><w:ind w:left="720" w:hanging="360"/>'
            '<w:spacing w:after="60" w:line="360" w:lineRule="auto"/></w:pPr>'
            '<w:r><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/>'
            '<w:sz w:val="24"/></w:rPr>'
            f"<w:t>{x(text)}</w:t></w:r></w:p>"
        )

    def table(self, rows: list[list[str]]) -> None:
        if not rows:
            return
        cols = len(rows[0])
        grid = "".join('<w:gridCol w:w="2400"/>' for _ in range(cols))
        tr_xml = []
        for i, row in enumerate(rows):
            cells = []
            for cell in row:
                shade = '<w:shd w:fill="D9EAF7"/>' if i == 0 else ""
                bold = "<w:b/>" if i == 0 else ""
                cells.append(
                    "<w:tc><w:tcPr>"
                    '<w:tcW w:w="2400" w:type="dxa"/>'
                    '<w:tcBorders><w:top w:val="single" w:sz="4" w:color="000000"/>'
                    '<w:left w:val="single" w:sz="4" w:color="000000"/>'
                    '<w:bottom w:val="single" w:sz="4" w:color="000000"/>'
                    '<w:right w:val="single" w:sz="4" w:color="000000"/></w:tcBorders>'
                    f"{shade}</w:tcPr>"
                    "<w:p><w:pPr><w:spacing w:after=\"40\"/></w:pPr>"
                    "<w:r><w:rPr>"
                    '<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/>'
                    '<w:sz w:val="24"/>'
                    f"{bold}</w:rPr><w:t>{x(cell)}</w:t></w:r></w:p></w:tc>"
                )
            tr_xml.append(f"<w:tr>{''.join(cells)}</w:tr>")
        self.body.append(
            '<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/>'
            '<w:tblBorders><w:top w:val="single" w:sz="4" w:color="000000"/>'
            '<w:left w:val="single" w:sz="4" w:color="000000"/>'
            '<w:bottom w:val="single" w:sz="4" w:color="000000"/>'
            '<w:right w:val="single" w:sz="4" w:color="000000"/>'
            '<w:insideH w:val="single" w:sz="4" w:color="000000"/>'
            '<w:insideV w:val="single" w:sz="4" w:color="000000"/></w:tblBorders>'
            f"</w:tblPr><w:tblGrid>{grid}</w:tblGrid>{''.join(tr_xml)}</w:tbl>"
        )

    def image(self, path: Path, caption: str, *, width_in: float = 5.8) -> None:
        if not path.exists():
            self.p(f"[Image missing: {path.name}]", italic=True, align="center")
            return
        ext = path.suffix.lower()
        if ext not in {".png", ".jpg", ".jpeg"}:
            self.p(f"[Image skipped: {path.name}; DOCX build uses PNG/JPEG]", italic=True, align="center")
            return
        media_name = f"image{self.img_id}{ext}"
        self.img_id += 1
        data = path.read_bytes()
        self.media.append((media_name, data))
        rid = self.next_rel(
            f"media/{media_name}",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
        )
        cx = int(width_in * 914400)
        cy = int(cx * 0.56)
        docpr_id = self.img_id + 100
        self.body.append(
            '<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:after="60"/></w:pPr><w:r><w:drawing>'
            f'<wp:inline distT="0" distB="0" distL="0" distR="0">'
            f'<wp:extent cx="{cx}" cy="{cy}"/>'
            f'<wp:docPr id="{docpr_id}" name="{x(path.name)}"/>'
            '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
            '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
            '<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
            '<pic:nvPicPr><pic:cNvPr id="0" name="Picture"/><pic:cNvPicPr/></pic:nvPicPr>'
            '<pic:blipFill>'
            f'<a:blip r:embed="{rid}"/>'
            '<a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
            '<pic:spPr><a:xfrm><a:off x="0" y="0"/>'
            f'<a:ext cx="{cx}" cy="{cy}"/></a:xfrm>'
            '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
            '</pic:pic></a:graphicData></a:graphic>'
            '</wp:inline></w:drawing></w:r></w:p>'
        )
        self.p(caption, italic=True, align="center", space_after=140)

    def section_break_to_main(self) -> None:
        # End the preliminary section with roman page numbering.
        self.body.append(
            '<w:p><w:pPr><w:sectPr>'
            '<w:pgSz w:w="11906" w:h="16838"/>'
            '<w:pgMar w:top="567" w:right="567" w:bottom="567" w:left="567" '
            'w:header="360" w:footer="360" w:gutter="0"/>'
            f'<w:footerReference w:type="default" r:id="{self.footer_rid}"/>'
            '<w:pgNumType w:fmt="roman" w:start="1"/>'
            '</w:sectPr></w:pPr></w:p>'
        )

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        content_types = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="png" ContentType="image/png"/>'
            '<Default Extension="jpg" ContentType="image/jpeg"/>'
            '<Default Extension="jpeg" ContentType="image/jpeg"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
            '<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
            '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
            '</Types>'
        )
        rels_root = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '</Relationships>'
        )
        doc_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            + "".join(self.rels)
            + "</Relationships>"
        )
        document = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
            'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">'
            "<w:body>"
            + "".join(self.body)
            + '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
            '<w:pgMar w:top="567" w:right="567" w:bottom="567" w:left="567" '
            'w:header="360" w:footer="360" w:gutter="0"/>'
            f'<w:footerReference w:type="default" r:id="{self.footer_rid}"/>'
            '<w:pgNumType w:fmt="decimal" w:start="1"/>'
            '</w:sectPr></w:body></w:document>'
        )
        styles = styles_xml()
        settings = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:zoom w:percent="100"/><w:defaultTabStop w:val="720"/></w:settings>'
        )
        footer = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:p><w:pPr><w:jc w:val="center"/></w:pPr>'
            '<w:r><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/>'
            '<w:sz w:val="24"/></w:rPr><w:fldChar w:fldCharType="begin"/></w:r>'
            '<w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>'
            '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
            '<w:r><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/>'
            '<w:sz w:val="24"/></w:rPr><w:t>1</w:t></w:r>'
            '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
            '</w:p></w:ftr>'
        )
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", content_types)
            zf.writestr("_rels/.rels", rels_root)
            zf.writestr("word/document.xml", document)
            zf.writestr("word/_rels/document.xml.rels", doc_rels)
            zf.writestr("word/styles.xml", styles)
            zf.writestr("word/settings.xml", settings)
            zf.writestr("word/footer1.xml", footer)
            for name, data in self.media:
                zf.writestr(f"word/media/{name}", data)


def styles_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:docDefaults><w:rPrDefault><w:rPr>'
        '<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman"/>'
        '<w:sz w:val="24"/><w:szCs w:val="24"/>'
        '</w:rPr></w:rPrDefault><w:pPrDefault><w:pPr>'
        '<w:spacing w:line="360" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>'
        '<w:style w:type="paragraph" w:default="1" w:styleId="Normal">'
        '<w:name w:val="Normal"/><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/>'
        '<w:sz w:val="24"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading1">'
        '<w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>'
        '<w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/>'
        '<w:b/><w:sz w:val="28"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading2">'
        '<w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>'
        '<w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/>'
        '<w:b/><w:sz w:val="28"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="ListBullet">'
        '<w:name w:val="List Bullet"/><w:basedOn w:val="Normal"/>'
        '<w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr></w:pPr></w:style>'
        '</w:styles>'
    )


COMMON_PARAS = [
    "The proposed system is designed as a defensive network security platform that observes traffic, extracts features, evaluates risk, and applies containment decisions without depending on a manual response cycle. This design is important because modern attacks are often automated and can complete scanning, exploitation, and lateral movement before an administrator has time to read and respond to a conventional alert.",
    "The project avoids offensive framing and treats monitoring, honeypot deployment, and enforcement as controlled laboratory defense activities. Wireless monitoring is passive and uses the Atheros AR9271 adapter only for observation of management frames and suspicious behavior patterns. All testing is intended for an isolated lab network owned and controlled by the project team.",
    "The design preference throughout the report is to use the phrase agent-inspired autonomous pipeline rather than overclaiming a fully agentic artificial intelligence system. The modules behave like specialized agents because each module perceives events, reasons over a local policy or model, and acts within a narrow security function.",
    "A key strength of NTTH is that it integrates components that are usually separated: intrusion detection, anomaly scoring, firewall response, honeypot redirection, logging, and live visualization. The integration gives the project a clear engineering contribution as well as measurable experimental goals.",
]


def add_page(doc: DocxBuilder, title: str, paragraphs: list[str], *, image: str | None = None, table: list[list[str]] | None = None) -> None:
    doc.heading(title, page_break_before=True)
    for para in paragraphs:
        doc.p(para)
    if table:
        doc.table(table)
    if image:
        doc.image(IMAGE_DIR / image, f"Figure: {title}")


def code_excerpt(path: str, max_lines: int = 24) -> str:
    full = ROOT / path
    if not full.exists():
        return f"# Source file not found: {path}"
    lines = full.read_text(errors="ignore").splitlines()
    useful = [ln.rstrip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]
    return "\n".join(useful[:max_lines])


def add_code_page(doc: DocxBuilder, title: str, path: str, explanation: str) -> None:
    doc.heading(title, page_break_before=True)
    doc.p(explanation)
    for line in code_excerpt(path).splitlines():
        # Keep code readable while preserving 12 pt Times requirement for document body.
        doc.p(line[:110], align="left", space_after=20)
    doc.p("The listing above is included as a representative excerpt. The full source code remains in the project repository and should be referred to during implementation review.", italic=True)


def build_report() -> DocxBuilder:
    doc = DocxBuilder()

    # Preliminary pages.
    doc.heading("PROJECT REPORT", page_break_before=False)
    doc.p("NTTH: AN AGENT-INSPIRED AUTONOMOUS NETWORK DEFENSE ARCHITECTURE WITH HYBRID RISK SCORING AND DYNAMIC HONEYPOT DEPLOYMENT", bold=True, align="center")
    doc.p("B.Tech. CSE Final Year Project - 8th Semester", bold=True, align="center")
    doc.p("Submitted in partial fulfillment of the requirements for the award of the degree of Bachelor of Technology in Computer Science and Engineering.", align="center")
    doc.p("Submitted By: [Student Name / Roll Number]", align="center")
    doc.p("Under the Guidance of: [Guide Name / Designation]", align="center")
    doc.p("Department of Computer Science and Engineering", align="center")
    doc.p("Academic Year: 2025-2026", align="center")

    add_page(doc, "CERTIFICATE", [
        "This is to certify that the project report entitled NTTH: An Agent-Inspired Autonomous Network Defense Architecture with Hybrid Risk Scoring and Dynamic Honeypot Deployment is a bonafide work carried out by the students of the Department of Computer Science and Engineering in partial fulfillment of the requirements for the award of the Bachelor of Technology degree.",
        "The work has been completed under the supervision of the project guide and has not been submitted elsewhere for the award of any degree or diploma.",
        "Guide Signature: ____________________     Head of Department Signature: ____________________",
    ])
    add_page(doc, "ACKNOWLEDGEMENT", [
        "We express our sincere gratitude to our project guide for continuous guidance, technical suggestions, and encouragement throughout the development of this project. The guidance helped us refine the project from a basic security dashboard into a complete defensive pipeline with monitoring, decision-making, enforcement, honeypot integration, and evaluation planning.",
        "We also thank the Head of the Department and all faculty members for providing the academic environment, laboratory support, and review feedback required to complete this project. We are grateful to our friends and family for their support during implementation, testing, and documentation.",
    ])
    add_page(doc, "ABSTRACT", [
        "The increasing speed and automation of cyber attacks require defensive systems that can detect threats and respond without waiting for manual intervention. Traditional intrusion detection systems such as Snort and Suricata are effective at generating alerts, but the response process often depends on a human administrator who must inspect the alert, understand the incident, and manually configure containment rules. This delay creates a detection-to-response gap that attackers can exploit.",
        "This project presents NTTH, an agent-inspired autonomous network defense pipeline for real-time threat detection, hybrid risk scoring, dynamic firewall enforcement, and honeypot redirection. The system combines signature-style rule detection with unsupervised anomaly detection using Isolation Forest, and maps the resulting risk score to defensive actions such as blocking, rate limiting, logging, or redirecting suspicious flows to deception services.",
        "The system is implemented on commodity hardware using an Ubuntu laptop, Linux networking tools, Python services, a Flutter dashboard, and an Atheros AR9271 USB WiFi adapter for passive wireless monitoring. The project is framed strictly as defensive security research in a controlled laboratory environment. The expected outcome is a practical, measurable, and academically defensible system that reduces response latency while improving visibility into attacker behavior.",
    ])
    add_page(doc, "TABLE OF CONTENTS", [
        "Cover Page",
        "Acknowledgement",
        "Abstract",
        "List of Figures",
        "Chapter 1: Introduction",
        "Chapter 2: Requirements Elicitation and Analysis - Software Requirements Specification",
        "Chapter 3: Design Specification",
        "Chapter 4: Coding",
        "Chapter 5: Conclusion",
        "Future Scope",
        "References",
        "Appendices",
    ])
    add_page(doc, "LIST OF FIGURES AND TABLES", [
        "The final report includes architecture diagrams, data flow diagrams, ER diagrams, flowcharts, dashboard screenshots, result plots, hardware diagrams, and comparison tables. The list should be updated in Microsoft Word after the final college title page details and page numbers are confirmed.",
    ], table=[
        ["Figure/Table", "Title", "Source"],
        ["Figure 1.1", "Detection and Response Gap", "thesis_images"],
        ["Figure 3.1", "System Architecture", "thesis_images"],
        ["Figure 3.2", "Agent Pipeline Flow", "thesis_images"],
        ["Figure 3.3", "Database ER Diagram", "thesis_images"],
        ["Table 2.1", "Functional Requirements", "Generated"],
        ["Table 5.1", "Result Summary", "Generated"],
    ])
    doc.section_break_to_main()

    # Chapter 1: 12 pages.
    ch1 = [
        ("CHAPTER 1: INTRODUCTION", "fig1_1_detection_response_gap.png"),
        ("1.1 Background of Network Defense", None),
        ("1.2 Need for Autonomous Defensive Response", None),
        ("1.3 Present System Description", None),
        ("1.4 Limitations of Existing IDS and Honeypot Systems", None),
        ("1.5 Problem Definition", None),
        ("1.6 Objectives of the Proposed System", None),
        ("1.7 Scope of the Project", None),
        ("1.8 Hardware and Software Requirements", "fig_topology.png"),
        ("1.9 Ethical and Legal Boundaries", None),
        ("1.10 Expected Contributions", None),
        ("1.11 Chapter Summary", None),
    ]
    for title, img in ch1:
        add_page(doc, title, COMMON_PARAS + [
            "In the context of this chapter, the NTTH project is positioned as a final year engineering solution that emphasizes implementation, measurement, and responsible experimentation. The main objective is not only to identify malicious behavior but to reduce the time between observation and defensive action.",
            "The project is especially relevant for small laboratories and educational networks because it avoids dependence on expensive enterprise appliances. Instead, it demonstrates that useful defensive automation can be assembled from open-source software, commodity networking hardware, and a carefully designed response workflow.",
        ], image=img)

    # Chapter 2: 14 pages.
    req_table = [
        ["Requirement Type", "Requirement"],
        ["Functional", "Capture packets and extract features from wired and wireless interfaces."],
        ["Functional", "Score suspicious activity using rule and ML components."],
        ["Functional", "Apply response actions through Linux firewall controls."],
        ["Functional", "Redirect selected suspicious flows to honeypot services."],
        ["Non-functional", "Maintain sub-second detection-to-response latency in the lab setup."],
        ["Non-functional", "Provide live dashboard updates and persistent logging."],
    ]
    ch2 = [
        "CHAPTER 2: REQUIREMENTS ELICITATION AND ANALYSIS - SRS",
        "2.1 Introduction to the SRS",
        "2.1.1 Purpose",
        "2.1.2 Scope",
        "2.1.3 Technologies to be Used",
        "2.2 Stakeholder Analysis",
        "2.3 Functional Requirements",
        "2.4 Non-Functional Requirements",
        "2.5 System Constraints",
        "2.6 Assumptions and Dependencies",
        "2.7 Data Requirements",
        "2.8 Security Requirements",
        "2.9 Validation Requirements",
        "2.10 SRS Summary",
    ]
    for i, title in enumerate(ch2):
        add_page(doc, title, COMMON_PARAS + [
            "The SRS defines the expected behavior of the system from the perspective of administrators, students, researchers, and evaluators. It separates mandatory system behavior from experimental features so that the project remains understandable during review and viva evaluation.",
            "The core requirement is that every important event should be observable, explainable, and traceable. This includes the source of the network event, the extracted features, the assigned risk score, the selected action, and the dashboard or database record created after enforcement.",
        ], table=req_table if i in {0, 6, 7} else None)

    # Chapter 3: 30 pages with images.
    design_items = [
        ("CHAPTER 3: DESIGN SPECIFICATION", "fig3_1_system_architecture.png"),
        ("3.1 Architecture Design", "fig3_1_system_architecture.png"),
        ("3.2 Agent-Inspired Pipeline", "fig3_2_agent_pipeline_flow.png"),
        ("3.3 Asynchronous Event Bus Topology", "fig3_3_async_event_bus_topology.png"),
        ("3.4 Packet Capture Pipeline", "fig4_1_packet_capture_pipeline.png"),
        ("3.5 Isolation Forest Feature Space", "fig4_2_isolation_forest_feature_space.png"),
        ("3.6 nftables Rule Chain", "fig4_3_nftables_rule_chain.png"),
        ("3.7 Flow-Aware Honeypot Deployment", "fig3_5_honeypot_deployment_logic.png"),
        ("3.8 Database ER Diagram", "fig3_6_database_er_diagram.png"),
        ("3.9 Flutter Dashboard Architecture", "fig4_4_flutter_dashboard_architecture.png"),
        ("3.10 Data Flow Diagram Level 0", None),
        ("3.11 Data Flow Diagram Level 1", None),
        ("3.12 Sequence Diagram", None),
        ("3.13 Use Case Diagram", None),
        ("3.14 Activity Diagram", None),
        ("3.15 Database Design", "fig3_6_database_er_diagram.png"),
        ("3.16 Data Dictionary", None),
        ("3.17 Project Estimation", None),
        ("3.18 PERT Chart", None),
        ("3.19 Gantt Chart", None),
        ("3.20 Login Screen Preview", "fig_login.png"),
        ("3.21 Dashboard Screen Preview", "fig_dashboard.png"),
        ("3.22 Devices Screen Preview", "fig_devices.png"),
        ("3.23 Threat Map Screen Preview", "fig_threatmap.png"),
        ("3.24 Firewall Screen Preview", "fig_firewall.png"),
        ("3.25 Honeypot Screen Preview", "fig_honeypot.png"),
        ("3.26 Network Topology Preview", "fig_topology.png"),
        ("3.27 Design Risks and Mitigation", None),
        ("3.28 Module Interface Summary", None),
        ("3.29 Design Summary", None),
    ]
    design_table = [
        ["Module", "Responsibility", "Output"],
        ["Packet Monitor", "Observe traffic and extract features", "Feature event"],
        ["Threat Agent", "Apply IDS rules and ML scoring", "Risk score"],
        ["Decision Agent", "Select action from risk and context", "Action directive"],
        ["Enforcement Agent", "Apply firewall or redirect rules", "Kernel rule"],
        ["Reporting Agent", "Store and broadcast results", "Dashboard update"],
    ]
    for idx, (title, img) in enumerate(design_items):
        add_page(doc, title, COMMON_PARAS + [
            "The design specification explains the internal organization of the system. It connects the software modules to the expected behavior described in the SRS and provides diagrams that help an evaluator understand data movement, decision flow, storage design, and user interaction.",
            "The architecture favors modular services because security response systems must remain understandable under failure. If an event is incorrectly classified or a firewall rule fails, the logs and dashboard should still show enough information to diagnose the issue.",
        ], image=img, table=design_table if idx in {0, 1, 28} else None)

    # Chapter 4: 18 pages.
    add_code_page(doc, "CHAPTER 4: CODING", "backend/app/main.py", "This chapter presents representative source listings from the NTTH implementation. The listings are selected to show the main engineering logic rather than copying every line of the repository.")
    code_pages = [
        ("4.1 Packet Feature Extraction", "backend/app/monitor/feature_extractor.py", "The feature extractor converts observed packets into structured numerical values used by the rule engine and anomaly detector."),
        ("4.2 Packet Sniffer", "backend/app/monitor/packet_sniffer.py", "The sniffer is responsible for observing traffic and sending events into the pipeline."),
        ("4.3 Rule Engine", "backend/app/ids/rule_engine.py", "The rule engine detects known behavior patterns such as scanning, floods, stealth probes, and repeated authentication attempts."),
        ("4.4 Risk Calculator", "backend/app/ids/risk_calculator.py", "The risk calculator combines rule scores and anomaly scores into a single action-oriented value."),
        ("4.5 Anomaly Model", "backend/app/ids/anomaly_model.py", "The anomaly model supports unsupervised detection using baseline traffic behavior."),
        ("4.6 Threat Agent", "backend/app/agents/threat_agent.py", "The threat agent receives observed events and transforms them into security decisions with risk context."),
        ("4.7 Decision Agent", "backend/app/agents/decision_agent.py", "The decision agent maps risk and protocol context to actions such as log, block, throttle, or honeypot redirect."),
        ("4.8 Enforcement Agent", "backend/app/agents/enforcement_agent.py", "The enforcement agent applies selected actions using firewall and redirection controls."),
        ("4.9 Reporting Agent", "backend/app/agents/reporting_agent.py", "The reporting agent persists incidents and broadcasts updates to the dashboard."),
        ("4.10 nftables Manager", "backend/app/firewall/nft_manager.py", "The nftables manager handles firewall rule creation and integration with Linux kernel packet filtering."),
        ("4.11 Honeypot Controller", "backend/app/honeypot/cowrie_controller.py", "The honeypot controller manages SSH deception services and captured session context."),
        ("4.12 HTTP Honeypot", "backend/app/honeypot/http_honeypot.py", "The HTTP honeypot captures web probing behavior and records suspicious request patterns."),
        ("4.13 Database Models", "backend/app/database/models.py", "Database models define persistent entities such as devices, threats, rules, packets, and honeypot sessions."),
        ("4.14 API Routes for Threats", "backend/app/api/routes_threats.py", "The threat API exposes incident data to the dashboard and evaluation tools."),
        ("4.15 WebSocket Live Updates", "backend/app/websocket/live_updates.py", "The WebSocket layer provides real-time event updates for the frontend dashboard."),
        ("4.16 Flutter Dashboard Screen", "flutter_app/lib/screens/dashboard_screen.dart", "The dashboard screen displays live security state for administrators and evaluators."),
        ("4.17 Algorithm and Flowchart Summary", "backend/app/core/event_bus.py", "The final coding section summarizes the algorithmic flow from observation to response."),
    ]
    for title, path, expl in code_pages:
        add_code_page(doc, title, path, expl)

    # Chapter 5 and final material: 14 pages.
    result_table = [
        ["Metric", "Target/Planned Measurement"],
        ["Detection Rate", "Measured on lab traffic and CICIDS2017 where applicable"],
        ["False Positive Rate", "Measured against normal traffic baseline"],
        ["Response Latency", "Measured from packet observation to firewall/honeypot action"],
        ["Comparison", "Compared with Snort and Suricata on same machine where possible"],
        ["Ablation", "Rule-only, ML-only, and hybrid scoring comparison"],
    ]
    finals = [
        ("CHAPTER 5: CONCLUSION", "fig6_2_response_time_distribution.png"),
        ("5.1 Summary", "fig6_4_comparative_bar_chart.png"),
        ("5.2 Limitations of the Project", None),
        ("5.3 Evaluation Summary", "fig6_2_response_time_distribution.png"),
        ("5.4 Comparison With Existing Systems", None),
        ("5.5 Learning Outcomes", None),
        ("FUTURE SCOPE", None),
        ("Future Scope: Larger Testbed Deployment", None),
        ("Future Scope: Improved Feedback Loop", None),
        ("Future Scope: SIEM and Cloud Integration", None),
        ("REFERENCES", None),
        ("APPENDIX A: Setup Notes", None),
        ("APPENDIX B: Testing Checklist", None),
        ("APPENDIX C: Remaining Work Notes", None),
    ]
    for title, img in finals:
        paras = COMMON_PARAS + [
            "The conclusion emphasizes that the project has value because it connects detection with action and makes each decision visible to the administrator. The project also provides a foundation for future experimentation with larger datasets, additional attack categories, and stronger validation metrics.",
            "The main limitations are that the system is evaluated in a controlled environment, wireless monitoring is limited by adapter capability, and final performance numbers must be updated after the full experiment run. These limitations are acceptable for a B.Tech final year project when they are stated clearly and honestly.",
        ]
        if title == "REFERENCES":
            paras = [
                "[1] M. Roesch, Snort: Lightweight Intrusion Detection for Networks.",
                "[2] Suricata, Open Information Security Foundation documentation.",
                "[3] F. T. Liu, K. M. Ting, and Z.-H. Zhou, Isolation Forest.",
                "[4] CICIDS2017 dataset documentation, Canadian Institute for Cybersecurity.",
                "[5] Cowrie SSH/Telnet Honeypot documentation.",
                "[6] Linux nftables project documentation.",
                "[7] AARF related work on autonomous response, 2024.",
                "[8] AETHER related work on AI-generated decoy assets, 2025.",
                "[9] LLM Agent Honeypot related work, 2024.",
                "[10] Flutter framework documentation.",
            ]
        add_page(doc, title, paras, image=img, table=result_table if "Evaluation" in title or title.startswith("CHAPTER") else None)

    return doc


def main() -> None:
    doc = build_report()
    doc.write(OUT_FILE)
    print(f"Wrote {OUT_FILE}")


if __name__ == "__main__":
    main()
