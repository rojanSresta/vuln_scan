"""PDF report generation."""

from __future__ import annotations

import tempfile
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import HRFlowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

DARK_BG = colors.HexColor("#0f1117")
ACCENT = colors.HexColor("#00d4aa")
HIGH_CLR = colors.HexColor("#ef4444")
MED_CLR = colors.HexColor("#f59e0b")
LOW_CLR = colors.HexColor("#3b82f6")
INFO_CLR = colors.HexColor("#6b7280")
TEXT_CLR = colors.HexColor("#1f2937")
LIGHT_BG = colors.HexColor("#f8fafc")
BORDER = colors.HexColor("#e2e8f0")

RISK_COLOURS = {
    "High": HIGH_CLR,
    "Medium": MED_CLR,
    "Low": LOW_CLR,
    "Informational": INFO_CLR,
}


def generate_pdf_report(scan_id: str, target_url: str, results: list[dict[str, Any]]) -> str:
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf", prefix=f"vulnscan_{scan_id[:8]}_")
    path = tmp.name
    tmp.close()

    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )
    styles = _build_styles()
    story = _build_story(styles, scan_id, target_url, results)
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return path


def _risk_colour(risk: str) -> colors.Color:
    return RISK_COLOURS.get(risk, INFO_CLR)


def _build_styles() -> dict[str, ParagraphStyle]:
    getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "cover_title",
            fontSize=28,
            textColor=TEXT_CLR,
            spaceAfter=6,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub",
            fontSize=13,
            textColor=colors.HexColor("#475569"),
            spaceAfter=4,
            fontName="Helvetica",
            alignment=TA_CENTER,
        ),
        "section_title": ParagraphStyle(
            "section_title",
            fontSize=14,
            textColor=TEXT_CLR,
            spaceBefore=16,
            spaceAfter=6,
            fontName="Helvetica-Bold",
            borderPad=4,
        ),
        "body": ParagraphStyle(
            "body",
            fontSize=10,
            textColor=TEXT_CLR,
            spaceAfter=4,
            fontName="Helvetica",
            leading=14,
        ),
        "label": ParagraphStyle(
            "label",
            fontSize=9,
            textColor=colors.HexColor("#64748b"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        ),
        "vuln_name": ParagraphStyle(
            "vuln_name",
            fontSize=11,
            textColor=TEXT_CLR,
            fontName="Helvetica-Bold",
            spaceAfter=3,
        ),
        "small": ParagraphStyle(
            "small",
            fontSize=9,
            textColor=colors.HexColor("#475569"),
            fontName="Helvetica",
            leading=12,
        ),
    }


def _build_story(styles: dict[str, ParagraphStyle], scan_id: str, target_url: str, results: list[dict[str, Any]]) -> list[Any]:
    story: list[Any] = []
    now = datetime.now().strftime("%B %d, %Y  %H:%M UTC")

    story.append(Spacer(1, 1.5 * cm))
    story.append(Paragraph("Vulnerability Scan Report", styles["cover_title"]))
    story.append(Spacer(1, 0.4 * cm))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
    story.append(Spacer(1, 0.6 * cm))

    meta = [
        ["Target URL", target_url],
        ["Scan Date", now],
        ["Scan ID", scan_id],
        ["Total Findings", str(len(results))],
    ]
    meta_table = Table(meta, colWidths=[4 * cm, 13 * cm])
    meta_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#64748b")),
                ("TEXTCOLOR", (1, 0), (1, -1), TEXT_CLR),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [LIGHT_BG, colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 0.8 * cm))

    story.append(Paragraph("Summary by Risk Level", styles["section_title"]))
    risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for result in results:
        risk = result.get("risk", "Informational")
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    summary_data = [["Risk Level", "Count"]]
    for level in ["High", "Medium", "Low", "Informational"]:
        summary_data.append([level, str(risk_counts[level])])

    summary_table = Table(summary_data, colWidths=[8 * cm, 9 * cm])
    summary_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LIGHT_BG, colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("PADDING", (0, 0), (-1, -1), 8),
                ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 1 * cm))

    if not results:
        story.append(Paragraph("Detailed Findings", styles["section_title"]))
        story.append(
            Paragraph(
                "No vulnerabilities were detected for the selected scan categories.",
                styles["body"],
            )
        )
        return story

    story.append(Paragraph("Detailed Findings", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER))
    story.append(Spacer(1, 0.3 * cm))

    for index, vuln in enumerate(results, start=1):
        risk = vuln.get("risk", "Informational")
        risk_clr = _risk_colour(risk)
        block: list[Any] = []

        title_data = [[
            Paragraph(f"{index}. {vuln.get('name', 'Unknown')}", styles["vuln_name"]),
            Paragraph(
                f'<font color="{risk_clr.hexval()}" size="10"><b> {risk} </b></font>',
                ParagraphStyle("badge", alignment=TA_CENTER, fontSize=10),
            ),
        ]]
        title_table = Table(title_data, colWidths=[13 * cm, 4 * cm])
        title_table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("PADDING", (0, 0), (-1, -1), 4),
                    ("BACKGROUND", (1, 0), (1, 0), colors.Color(risk_clr.red, risk_clr.green, risk_clr.blue, alpha=0.12)),
                    ("BOX", (1, 0), (1, 0), 1, risk_clr),
                ]
            )
        )
        block.append(title_table)
        block.append(Spacer(1, 0.2 * cm))

        if vuln.get("url"):
            block.append(Paragraph("URL", styles["label"]))
            block.append(Paragraph(f'<font size="9" color="#1d4ed8">{vuln["url"]}</font>', styles["small"]))
            block.append(Spacer(1, 0.2 * cm))

        block.append(Paragraph("What this means", styles["label"]))
        block.append(Paragraph(vuln.get("explanation", ""), styles["body"]))
        block.append(Spacer(1, 0.2 * cm))

        if vuln.get("solution"):
            block.append(Paragraph("Recommended Fix", styles["label"]))
            solution = vuln["solution"][:400] + ("…" if len(vuln["solution"]) > 400 else "")
            block.append(Paragraph(solution, styles["small"]))
            block.append(Spacer(1, 0.2 * cm))

        meta_parts: list[str] = []
        if vuln.get("cwe_id"):
            meta_parts.append(f"CWE-{vuln['cwe_id']}")
        if vuln.get("wasc_id"):
            meta_parts.append(f"WASC-{vuln['wasc_id']}")
        if meta_parts:
            block.append(Paragraph(" · ".join(meta_parts), styles["small"]))

        card = Table([[block]], colWidths=[17 * cm])
        card.setStyle(
            TableStyle(
                [
                    ("BOX", (0, 0), (-1, -1), 1, BORDER),
                    ("PADDING", (0, 0), (-1, -1), 10),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ]
            )
        )
        story.append(KeepTogether(card))
        story.append(Spacer(1, 0.5 * cm))

    return story


def _header_footer(canvas, doc) -> None:
    width, height = A4
    canvas.saveState()
    canvas.setFillColor(DARK_BG)
    canvas.rect(0, height - 1.2 * cm, width, 1.2 * cm, fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(2 * cm, height - 0.75 * cm, "VulnScan  ·  Security Report")
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(width - 2 * cm, height - 0.75 * cm, datetime.now().strftime("%Y-%m-%d"))
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(2 * cm, 1.4 * cm, width - 2 * cm, 1.4 * cm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(INFO_CLR)
    canvas.drawString(2 * cm, 0.9 * cm, "Confidential · For authorised use only")
    canvas.drawRightString(width - 2 * cm, 0.9 * cm, f"Page {doc.page}")
    canvas.restoreState()
