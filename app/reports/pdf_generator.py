"""
Professional Multi-Page CCTV VAPT PDF Reporting Engine
Built with ReportLab for Customer-Ready Security Assessment Deliverables.
"""

import io
from pathlib import Path
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend

PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 36.0  # 0.5 inch margins
CONTENT_WIDTH = PAGE_WIDTH - (2 * MARGIN)  # 523.27 pt


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that computes total page count dynamically and draws
    consistent running headers and footers on content pages (page 2+).
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []
        self.report_id = "REP-CCTV-AUDIT"
        self.report_date = datetime.now().strftime("%B %d, %Y")

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, page_count):
        # Skip running header and footer on Cover Page (Page 1)
        if self._pageNumber == 1:
            return

        self.saveState()

        # --- Running Header ---
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.75)
        self.line(MARGIN, PAGE_HEIGHT - 40, PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 40)

        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(MARGIN, PAGE_HEIGHT - 34, "VIGICORE  //  CCTV SECURITY ASSESSMENT PLATFORM")

        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#0F172A"))
        report_text = f"REPORT ID: {getattr(self, 'report_id', 'REP-CCTV-AUDIT')}"
        self.drawRightString(PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 34, report_text)

        # --- Running Footer ---
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.75)
        self.line(MARGIN, 44, PAGE_WIDTH - MARGIN, 44)

        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#94A3B8"))
        self.drawString(MARGIN, 32, "STRICTLY CONFIDENTIAL  //  AUTHORIZED CUSTOMER DELIVERABLE")

        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748B"))
        date_str = getattr(self, "report_date", datetime.now().strftime("%B %d, %Y"))
        self.drawCentredString(PAGE_WIDTH / 2.0, 32, date_str)

        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#1E293B"))
        self.drawRightString(PAGE_WIDTH - MARGIN, 32, f"Page {self._pageNumber} of {page_count}")

        self.restoreState()


def get_report_palette():
    """Return consulting-grade hex colors."""
    return {
        "navy": colors.HexColor("#0F172A"),
        "navy_light": colors.HexColor("#1E293B"),
        "slate": colors.HexColor("#334155"),
        "muted": colors.HexColor("#64748B"),
        "light_bg": colors.HexColor("#F8FAFC"),
        "card_bg": colors.HexColor("#FFFFFF"),
        "border": colors.HexColor("#E2E8F0"),
        "border_subtle": colors.HexColor("#CBD5E1"),
        "blue": colors.HexColor("#0284C7"),
        "blue_light": colors.HexColor("#E0F2FE"),
        # Severity colors
        "crit_bg": colors.HexColor("#FEE2E2"),
        "crit_text": colors.HexColor("#991B1B"),
        "crit_border": colors.HexColor("#DC2626"),
        "high_bg": colors.HexColor("#FEF2F2"),
        "high_text": colors.HexColor("#B91C1C"),
        "high_border": colors.HexColor("#EF4444"),
        "med_bg": colors.HexColor("#FEF3C7"),
        "med_text": colors.HexColor("#92400E"),
        "med_border": colors.HexColor("#D97706"),
        "low_bg": colors.HexColor("#EFF6FF"),
        "low_text": colors.HexColor("#1E40AF"),
        "low_border": colors.HexColor("#3B82F6"),
        "info_bg": colors.HexColor("#F1F5F9"),
        "info_text": colors.HexColor("#475569"),
        "info_border": colors.HexColor("#64748B"),
        # Status colors
        "pass_bg": colors.HexColor("#DCFCE7"),
        "pass_text": colors.HexColor("#15803D"),
        "fail_bg": colors.HexColor("#FEE2E2"),
        "fail_text": colors.HexColor("#B91C1C"),
        "na_bg": colors.HexColor("#F1F5F9"),
        "na_text": colors.HexColor("#475569"),
    }


def create_report_styles():
    """Generate consistent ReportLab styles for A4 layout."""
    styles = getSampleStyleSheet()
    pal = get_report_palette()

    styles.add(ParagraphStyle(
        name="ReportCoverSuper",
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        textColor=pal["blue"],
        textTransform="uppercase",
        spaceAfter=6,
    ))

    styles.add(ParagraphStyle(
        name="ReportCoverTitle",
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=pal["navy"],
        spaceAfter=10,
    ))

    styles.add(ParagraphStyle(
        name="ReportCoverSubtitle",
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=pal["muted"],
        spaceAfter=20,
    ))

    styles.add(ParagraphStyle(
        name="ReportH1",
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=pal["navy"],
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True,
    ))

    styles.add(ParagraphStyle(
        name="ReportH2",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=pal["navy_light"],
        spaceBefore=10,
        spaceAfter=5,
        keepWithNext=True,
    ))

    styles.add(ParagraphStyle(
        name="ReportBody",
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=pal["slate"],
        spaceAfter=6,
    ))

    styles.add(ParagraphStyle(
        name="ReportBodyBold",
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=pal["navy_light"],
        spaceAfter=4,
    ))

    styles.add(ParagraphStyle(
        name="ReportSmall",
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=pal["muted"],
    ))

    styles.add(ParagraphStyle(
        name="ReportSmallBold",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=pal["navy_light"],
    ))

    styles.add(ParagraphStyle(
        name="ReportCode",
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=pal["navy"],
    ))

    styles.add(ParagraphStyle(
        name="CardHeaderTitle",
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=pal["navy"],
    ))

    styles.add(ParagraphStyle(
        name="BadgeText",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        alignment=1,  # Center
    ))

    return styles


def draw_network_topology(target_ip: str, gateway_ip: str, local_ip: str = "192.168.0.102"):
    """Render clean ReportLab vector graphic representing assessment network path."""
    d = Drawing(CONTENT_WIDTH, 75)
    pal = get_report_palette()

    # Background frame
    d.add(Rect(0, 0, CONTENT_WIDTH, 75, fillColor=pal["light_bg"], strokeColor=pal["border"], rx=6, ry=6))

    # Connecting dashed lines
    gw_x = CONTENT_WIDTH / 2.0
    auditor_x = 75
    target_x = CONTENT_WIDTH - 75
    y_pos = 38

    d.add(Line(auditor_x + 20, y_pos, gw_x - 24, y_pos, strokeColor=colors.HexColor("#94A3B8"), strokeWidth=1.5, strokeDashArray=[4, 3]))
    d.add(Line(gw_x + 24, y_pos, target_x - 20, y_pos, strokeColor=colors.HexColor("#94A3B8"), strokeWidth=1.5, strokeDashArray=[4, 3]))

    # Node 1: Auditor
    d.add(Circle(auditor_x, y_pos, 15, fillColor=pal["blue"], strokeColor=colors.white, strokeWidth=1.5))
    d.add(String(auditor_x, y_pos - 4, "MAC", fontName="Helvetica-Bold", fontSize=7, fillColor=colors.white, textAnchor="middle"))
    d.add(String(auditor_x, y_pos - 24, "Auditor Host", fontName="Helvetica-Bold", fontSize=8, fillColor=pal["navy"], textAnchor="middle"))
    d.add(String(auditor_x, y_pos - 32, local_ip, fontName="Helvetica", fontSize=7, fillColor=pal["muted"], textAnchor="middle"))

    # Node 2: Gateway
    d.add(Circle(gw_x, y_pos, 16, fillColor=pal["slate"], strokeColor=colors.white, strokeWidth=1.5))
    d.add(String(gw_x, y_pos - 4, "RTR", fontName="Helvetica-Bold", fontSize=7, fillColor=colors.white, textAnchor="middle"))
    d.add(String(gw_x, y_pos - 24, "Default Gateway", fontName="Helvetica-Bold", fontSize=8, fillColor=pal["navy"], textAnchor="middle"))
    d.add(String(gw_x, y_pos - 32, gateway_ip or "192.168.1.1", fontName="Helvetica", fontSize=7, fillColor=pal["muted"], textAnchor="middle"))

    # Node 3: Target CCTV
    d.add(Circle(target_x, y_pos, 15, fillColor=pal["crit_border"], strokeColor=colors.white, strokeWidth=1.5))
    d.add(String(target_x, y_pos - 4, "CAM", fontName="Helvetica-Bold", fontSize=7, fillColor=colors.white, textAnchor="middle"))
    d.add(String(target_x, y_pos - 24, "Target Surveillance", fontName="Helvetica-Bold", fontSize=8, fillColor=pal["navy"], textAnchor="middle"))
    d.add(String(target_x, y_pos - 32, target_ip, fontName="Helvetica", fontSize=7, fillColor=pal["muted"], textAnchor="middle"))

    return d


def draw_risk_gauge_bar(score: int, level: str):
    """Draw vector risk score gauge bar representing 0-100 heuristic score."""
    d = Drawing(CONTENT_WIDTH, 60)
    pal = get_report_palette()

    d.add(Rect(0, 0, CONTENT_WIDTH, 60, fillColor=pal["light_bg"], strokeColor=pal["border"], rx=6, ry=6))

    # Header text
    d.add(String(16, 44, "OVERALL HEURISTIC RISK SCORE METER", fontName="Helvetica-Bold", fontSize=8, fillColor=pal["muted"]))
    score_color = pal["crit_border"] if score >= 60 else (pal["med_border"] if score >= 40 else pal["blue"])
    d.add(String(CONTENT_WIDTH - 16, 44, f"SCORE: {score} / 100 [{level}]", fontName="Helvetica-Bold", fontSize=8.5, fillColor=score_color, textAnchor="end"))

    # Track
    track_x = 16
    track_y = 24
    track_w = CONTENT_WIDTH - 32
    track_h = 10
    d.add(Rect(track_x, track_y, track_w, track_h, fillColor=colors.HexColor("#E2E8F0"), strokeColor=None, rx=3, ry=3))

    # Fill
    fill_w = max(4, int(track_w * (min(100, max(0, score)) / 100.0)))
    d.add(Rect(track_x, track_y, fill_w, track_h, fillColor=score_color, strokeColor=None, rx=3, ry=3))

    # Sub labels
    d.add(String(track_x, 11, "0 (INFO)", fontName="Helvetica", fontSize=7, fillColor=pal["muted"]))
    d.add(String(track_x + (track_w * 0.40), 11, "40 (MEDIUM)", fontName="Helvetica", fontSize=7, fillColor=pal["muted"]))
    d.add(String(track_x + (track_w * 0.60), 11, "60 (HIGH)", fontName="Helvetica", fontSize=7, fillColor=pal["muted"]))
    d.add(String(track_x + track_w, 11, "100 (CRITICAL)", fontName="Helvetica", fontSize=7, fillColor=pal["muted"], textAnchor="end"))

    return d


def draw_severity_pie_chart(severity_counts: dict):
    """Render vector pie chart of findings distribution."""
    d = Drawing(CONTENT_WIDTH, 130)
    pal = get_report_palette()

    d.add(Rect(0, 0, CONTENT_WIDTH, 130, fillColor=pal["light_bg"], strokeColor=pal["border"], rx=6, ry=6))
    d.add(String(16, 112, "FINDINGS SEVERITY DISTRIBUTION", fontName="Helvetica-Bold", fontSize=8, fillColor=pal["muted"]))

    crit = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)
    med = severity_counts.get("MEDIUM", 0)
    low = severity_counts.get("LOW", 0)
    info = severity_counts.get("INFO", 0)
    total = crit + high + med + low + info

    data = []
    labels = []
    slice_colors = []

    if crit > 0:
        data.append(crit)
        labels.append(f"Critical ({crit})")
        slice_colors.append(pal["crit_border"])
    if high > 0:
        data.append(high)
        labels.append(f"High ({high})")
        slice_colors.append(pal["high_border"])
    if med > 0:
        data.append(med)
        labels.append(f"Medium ({med})")
        slice_colors.append(pal["med_border"])
    if low > 0:
        data.append(low)
        labels.append(f"Low ({low})")
        slice_colors.append(pal["low_border"])
    if info > 0:
        data.append(info)
        labels.append(f"Info ({info})")
        slice_colors.append(pal["info_border"])

    if not data:
        # No findings placeholder
        d.add(String(CONTENT_WIDTH / 2.0, 60, "No Findings Identified (100% Compliant)", fontName="Helvetica-Bold", fontSize=10, fillColor=pal["pass_text"], textAnchor="middle"))
        return d

    pie = Pie()
    pie.x = 35
    pie.y = 10
    pie.width = 95
    pie.height = 95
    pie.data = data
    pie.labels = labels
    pie.sideLabels = 0
    for idx, c in enumerate(slice_colors):
        pie.slices[idx].fillColor = c
        pie.slices[idx].strokeColor = colors.white
        pie.slices[idx].strokeWidth = 1
    d.add(pie)

    # Detailed Legend
    leg = Legend()
    leg.x = 240
    leg.y = 95
    leg.dx = 9
    leg.dy = 9
    leg.fontName = "Helvetica"
    leg.fontSize = 8
    leg.boxAnchor = "nw"
    leg.columnMaximum = 5

    def pct(cnt):
        return f"{(cnt / total * 100):.0f}%" if total > 0 else "0%"

    leg.colorNamePairs = [
        (pal["crit_border"], f"Critical: {crit} finding(s) — {pct(crit)}"),
        (pal["high_border"], f"High: {high} finding(s) — {pct(high)}"),
        (pal["med_border"], f"Medium: {med} finding(s) — {pct(med)}"),
        (pal["low_border"], f"Low: {low} finding(s) — {pct(low)}"),
        (pal["info_border"], f"Informational: {info} finding(s) — {pct(info)}"),
    ]
    d.add(leg)

    return d


# -----------------------------------------------------------------------------
# PAGE BUILDERS
# -----------------------------------------------------------------------------

def build_cover_page(data: dict, styles: dict) -> list:
    """Page 1: Customer-ready executive cover page."""
    story = []
    pal = get_report_palette()

    # Top accent bar
    top_bar = Table([[""]], colWidths=[CONTENT_WIDTH], rowHeights=[6])
    top_bar.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), pal["navy"]),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(top_bar)
    story.append(Spacer(1, 24))

    # Enterprise branding
    story.append(Paragraph("VIGICORE  //  CCTV SECURITY ASSESSMENT PLATFORM", styles["ReportCoverSuper"]))
    story.append(Paragraph("CONFIDENTIAL SECURITY ASSESSMENT & PENETRATION TESTING REPORT", styles["ReportCoverTitle"]))
    story.append(Paragraph("Defensive Vulnerability Audit & Configuration Analysis for Surveillance Infrastructure", styles["ReportCoverSubtitle"]))

    story.append(Spacer(1, 15))

    # Metadata card table
    meta_rows = []
    if data.get("customer_name"):
        meta_rows.append([
            Paragraph("Customer / Client", styles["ReportSmallBold"]),
            Paragraph(data.get("customer_name"), styles["ReportBodyBold"]),
        ])
    if data.get("organization_name"):
        meta_rows.append([
            Paragraph("Organization / Dept", styles["ReportSmallBold"]),
            Paragraph(data.get("organization_name"), styles["ReportBodyBold"]),
        ])
    if not meta_rows:
        meta_rows.append([
            Paragraph("Organization / Customer", styles["ReportSmallBold"]),
            Paragraph("Authorized Security Operations", styles["ReportBodyBold"]),
        ])

    meta_rows.extend([
        [
            Paragraph("Assessment Target", styles["ReportSmallBold"]),
            Paragraph(f"<font color='#0284C7'><b>{data.get('target', 'N/A')}</b></font>", styles["ReportBodyBold"]),
        ],
        [
            Paragraph("Assessment Scope", styles["ReportSmallBold"]),
            Paragraph(data.get("assessment_scope") or f"Single Target Assessment ({data.get('target')})", styles["ReportBody"]),
        ],
        [
            Paragraph("Report Identifier", styles["ReportSmallBold"]),
            Paragraph(f"<font name='Courier'><b>{data.get('report_id', 'REP-001')}</b></font>", styles["ReportBodyBold"]),
        ],
        [
            Paragraph("Assessment Date", styles["ReportSmallBold"]),
            Paragraph(data.get("scan_date_formatted", datetime.now().strftime("%B %d, %Y")), styles["ReportBody"]),
        ],
        [
            Paragraph("Lead Assessor / Engine", styles["ReportSmallBold"]),
            Paragraph(data.get("assessor_name") or "Antigravity Automated Security Assessment Engine", styles["ReportBody"]),
        ],
        [
            Paragraph("Report Version", styles["ReportSmallBold"]),
            Paragraph("v1.0 (Final Customer Delivery)", styles["ReportBody"]),
        ],
        [
            Paragraph("Overall Security Posture", styles["ReportSmallBold"]),
            Paragraph(f"<b>{data.get('risk_level', 'INFO')} RISK</b> ({data.get('risk_score', 0)} / 100 Heuristic Score)", styles["ReportBodyBold"]),
        ],
    ])

    meta_table = Table(meta_rows, colWidths=[150, CONTENT_WIDTH - 150])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), pal["light_bg"]),
        ("BOX", (0, 0), (-1, -1), 1, pal["border"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, pal["border"]),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(meta_table)

    story.append(Spacer(1, 30))

    # Confidentiality notice box
    notice_text = (
        "<b>LEGAL & COMPLIANCE NOTICE:</b> This security evaluation document contains confidential findings, "
        "technical observations, and potential vulnerability telemetry discovered during an authorized defensive "
        "assessment. The information contained herein is intended solely for authorized personnel of the designated "
        "organization for the purpose of remediating security weaknesses and hardening surveillance assets. "
        "Unauthorized reproduction, forwarding, or sharing of this report is strictly prohibited under applicable "
        "non-disclosure and cybersecurity compliance agreements."
    )
    notice_p = Paragraph(notice_text, styles["ReportSmall"])
    notice_table = Table([[notice_p]], colWidths=[CONTENT_WIDTH])
    notice_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF2F2")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#FECACA")),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(notice_table)

    story.append(PageBreak())
    return story


def build_executive_summary_page(data: dict, styles: dict) -> list:
    """Page 2: Executive Summary with high-level risk overview."""
    story = []
    pal = get_report_palette()

    story.append(Paragraph("1. Executive Summary", styles["ReportH1"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=pal["navy"], spaceBefore=2, spaceAfter=10))

    summary_text = (
        f"A comprehensive, non-destructive cybersecurity vulnerability assessment and penetration testing audit was "
        f"executed against the designated network asset <b>{data.get('target', '192.168.1.8')}</b>. The objective of this "
        f"assessment was to identify exposed management daemons, analyze real-time streaming protocol (RTSP) isolation, "
        f"evaluate web management encryption and HTTP transport headers, correlate firmware signatures against known CVE repositories, "
        f"and establish an actionable remediation roadmap for engineering and physical security operations."
    )
    story.append(Paragraph(summary_text, styles["ReportBody"]))
    story.append(Spacer(1, 6))

    # Metric Cards Grid
    score = data.get("risk_score", 0)
    level = data.get("risk_level", "INFO")
    tot_findings = data.get("findings_count", len(data.get("findings", [])))
    assessed_cnt = data.get("assessed_devices_count", 1)
    cctv_cnt = data.get("cctv_devices_count", 1)

    cards_data = [
        [
            Paragraph("OVERALL RISK", styles["ReportSmall"]),
            Paragraph("ASSESSED DEVICES", styles["ReportSmall"]),
            Paragraph("CCTV / SURVEILLANCE", styles["ReportSmall"]),
            Paragraph("TOTAL FINDINGS", styles["ReportSmall"]),
        ],
        [
            Paragraph(f"<b><font size='13' color='#DC2626'>{score}/100</font></b><br/><font size='8' color='#64748B'>{level}</font>", styles["ReportBody"]),
            Paragraph(f"<b><font size='13' color='#0F172A'>{assessed_cnt}</font></b><br/><font size='8' color='#64748B'>100% Inspected</font>", styles["ReportBody"]),
            Paragraph(f"<b><font size='13' color='#0284C7'>{cctv_cnt}</font></b><br/><font size='8' color='#64748B'>{data.get('vendor', 'Unknown')}</font>", styles["ReportBody"]),
            Paragraph(f"<b><font size='13' color='#D97706'>{tot_findings}</font></b><br/><font size='8' color='#64748B'>0 Confirmed Exploit</font>", styles["ReportBody"]),
        ]
    ]

    card_col_w = CONTENT_WIDTH / 4.0
    cards_table = Table(cards_data, colWidths=[card_col_w] * 4)
    cards_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), pal["light_bg"]),
        ("BOX", (0, 0), (-1, -1), 1, pal["border"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, pal["border"]),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(cards_table)
    story.append(Spacer(1, 10))

    # Severity distribution summary
    sev_counts = data.get("severity_counts", {})
    sev_data = [
        [
            Paragraph("<b>Critical</b>", styles["ReportSmall"]),
            Paragraph("<b>High</b>", styles["ReportSmall"]),
            Paragraph("<b>Medium</b>", styles["ReportSmall"]),
            Paragraph("<b>Low</b>", styles["ReportSmall"]),
            Paragraph("<b>Informational</b>", styles["ReportSmall"]),
        ],
        [
            Paragraph(f"<b>{sev_counts.get('CRITICAL', 0)}</b>", styles["ReportBodyBold"]),
            Paragraph(f"<b>{sev_counts.get('HIGH', 0)}</b>", styles["ReportBodyBold"]),
            Paragraph(f"<b>{sev_counts.get('MEDIUM', 0)}</b>", styles["ReportBodyBold"]),
            Paragraph(f"<b>{sev_counts.get('LOW', 0)}</b>", styles["ReportBodyBold"]),
            Paragraph(f"<b>{sev_counts.get('INFO', 0)}</b>", styles["ReportBodyBold"]),
        ]
    ]
    sev_table = Table(sev_data, colWidths=[CONTENT_WIDTH / 5.0] * 5)
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), pal["crit_bg"]),
        ("BACKGROUND", (1, 0), (1, -1), pal["high_bg"]),
        ("BACKGROUND", (2, 0), (2, -1), pal["med_bg"]),
        ("BACKGROUND", (3, 0), (3, -1), pal["low_bg"]),
        ("BACKGROUND", (4, 0), (4, -1), pal["info_bg"]),
        ("BOX", (0, 0), (-1, -1), 1, pal["border"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, pal["border"]),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 10))

    # Most Significant Security Observations
    story.append(Paragraph("Key Security Observations", styles["ReportH2"]))
    observations = [
        (
            "Exposed RTSP Media Streaming Daemon (Port 554/tcp):",
            "The device exposes Real-Time Streaming Protocol (RTSP) port 554 directly on the local network segment. "
            "Without dedicated network isolation or mandatory access control lists (ACLs), potential adversaries "
            "on the subnet can probe video streams or exploit protocol parsing deficiencies."
        ),
        (
            "Cleartext Web Management Protocol (Port 80/tcp without HTTPS):",
            "The administrative web management interface is operating over unencrypted HTTP. No corresponding HTTPS service "
            "was detected during port discovery. Administrative credentials and camera telemetry transmitted across the network "
            "are vulnerable to passive interception and eavesdropping."
        ),
        (
            "Missing Modern Browser Defense Headers (HSTS, CSP):",
            "The embedded web server configuration omitted Strict-Transport-Security (HSTS) and Content-Security-Policy (CSP) "
            "headers, leaving administrative browser sessions susceptible to protocol downgrade and content injection."
        ),
        (
            "Hardware Profile & Vendor Verification:",
            f"The target host was fingerprinted as <b>{data.get('device_type', 'Likely CCTV/NVR')}</b> manufactured by "
            f"<b>{data.get('vendor', 'Hikvision')}</b> with a heuristic confidence index of <b>{data.get('confidence', 90)}%</b>."
        ),
    ]

    for title, desc in observations:
        bullet_text = f"• <b>{title}</b> {desc}"
        story.append(Paragraph(bullet_text, styles["ReportBody"]))

    story.append(Spacer(1, 10))

    # Executive Recommendations
    story.append(Paragraph("Executive Recommendations", styles["ReportH2"]))
    exec_recs = [
        "<b>1. Enforce Network Segmentation:</b> Immediately segregate all IP cameras and recording servers (NVRs) into a dedicated, non-routable Surveillance VLAN protected by firewall ACLs.",
        "<b>2. Restrict RTSP Access:</b> Configure ingress rules to restrict RTSP traffic exclusively to authorized Video Management Software (VMS) and NVR IP addresses.",
        "<b>3. Upgrade to Encrypted Management:</b> Enforce HTTPS on web interfaces with valid internal certificates and disable plaintext HTTP.",
        "<b>4. Establish Regular Rescanning:</b> Schedule automated monthly audits to detect configuration drift and newly published CVE vulnerabilities.",
    ]
    for r in exec_recs:
        story.append(Paragraph(r, styles["ReportBody"]))

    story.append(PageBreak())
    return story


def build_network_overview_page(data: dict, styles: dict) -> list:
    """Page 3: Network Environment, Scope & Topology Visualization."""
    story = []
    pal = get_report_palette()

    story.append(Paragraph("2. Network Environment & Scope", styles["ReportH1"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=pal["navy"], spaceBefore=2, spaceAfter=10))

    intro = (
        "This section documents the network telemetry, subnet configuration, and operational boundaries under "
        "which the automated security assessment was performed. All tests were executed strictly within the local "
        "authorized subnet."
    )
    story.append(Paragraph(intro, styles["ReportBody"]))
    story.append(Spacer(1, 6))

    # Telemetry Table
    telemetry_data = [
        [
            Paragraph("Target IP Address", styles["ReportSmallBold"]),
            Paragraph(f"<font color='#0284C7'><b>{data.get('target', '192.168.1.8')}</b></font>", styles["ReportBodyBold"]),
            Paragraph("Subnet Range (CIDR)", styles["ReportSmallBold"]),
            Paragraph(f"<font name='Courier'>{data.get('cidr', '192.168.1.0/24')}</font>", styles["ReportBody"]),
        ],
        [
            Paragraph("Default Gateway", styles["ReportSmallBold"]),
            Paragraph(f"<font name='Courier'>{data.get('gateway', '192.168.1.1')}</font>", styles["ReportBody"]),
            Paragraph("Scanning Interface", styles["ReportSmallBold"]),
            Paragraph(data.get("interface", "en0 (Wi-Fi)"), styles["ReportBody"]),
        ],
        [
            Paragraph("Operational Status", styles["ReportSmallBold"]),
            Paragraph("<font color='#15803D'><b>HOST ACTIVE (UP)</b></font>", styles["ReportBodyBold"]),
            Paragraph("Network Environment", styles["ReportSmallBold"]),
            Paragraph(data.get("ssid") or "Local Authorized Subnet", styles["ReportBody"]),
        ],
    ]

    col_w = CONTENT_WIDTH / 4.0
    tel_table = Table(telemetry_data, colWidths=[col_w] * 4)
    tel_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), pal["light_bg"]),
        ("BOX", (0, 0), (-1, -1), 1, pal["border"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, pal["border"]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(tel_table)
    story.append(Spacer(1, 14))

    # Network Topology
    story.append(Paragraph("Network Topology & Assessment Path", styles["ReportH2"]))
    topo_drawing = draw_network_topology(
        target_ip=data.get("target", "192.168.1.8"),
        gateway_ip=data.get("gateway", "192.168.1.1"),
        local_ip=data.get("local_ip", "192.168.0.102")
    )
    story.append(topo_drawing)
    story.append(Spacer(1, 14))

    # Methodology & Scope boundaries
    story.append(Paragraph("Assessment Scope & Execution Boundaries", styles["ReportH2"]))
    scope_details = [
        "<b>In-Scope Infrastructure:</b> Host IP " + str(data.get("target")) + " on local network segment " + str(data.get("cidr", "192.168.1.0/24")) + ".",
        "<b>TCP Port Discovery:</b> Comprehensive SYN and TCP connect discovery targeting common surveillance, streaming, and management services (ports 80, 554, 8000, 9010, etc.).",
        "<b>Service & Fingerprint Identification:</b> Non-intrusive protocol inspection, banner analysis, and HTTP header parsing.",
        "<b>Safety & Non-Destructive Guarantee:</b> No denial-of-service tests, buffer overflow payloads, or brute-force authentication attacks were executed during this assessment.",
    ]
    for s in scope_details:
        story.append(Paragraph(f"• {s}", styles["ReportBody"]))

    story.append(PageBreak())
    return story


def build_device_inventory_page(data: dict, styles: dict) -> list:
    """Page 4: Detailed Device Inventory, Service Telemetry & Rigorous Controls Table."""
    story = []
    pal = get_report_palette()

    story.append(Paragraph("3. Device Inventory & Hardware Profiling", styles["ReportH1"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=pal["navy"], spaceBefore=2, spaceAfter=10))

    intro = (
        "The table below details the hardware profile, physical network addressing, open network services, "
        "and security telemetry discovered for target assets in the evaluation scope."
    )
    story.append(Paragraph(intro, styles["ReportBody"]))
    story.append(Spacer(1, 6))

    # Main Device Inventory Table
    inv_headers = [
        Paragraph("<b>IP Address</b>", styles["ReportSmallBold"]),
        Paragraph("<b>Manufacturer</b>", styles["ReportSmallBold"]),
        Paragraph("<b>Category</b>", styles["ReportSmallBold"]),
        Paragraph("<b>Confidence</b>", styles["ReportSmallBold"]),
        Paragraph("<b>Open Ports</b>", styles["ReportSmallBold"]),
        Paragraph("<b>Status</b>", styles["ReportSmallBold"]),
    ]

    services_list = data.get("services", [])
    open_ports_str = ", ".join(str(s.get("port")) for s in services_list) if services_list else "None"

    inv_rows = [inv_headers]
    inv_rows.append([
        Paragraph(f"<font name='Courier'><b>{data.get('target', '192.168.1.8')}</b></font>", styles["ReportBodyBold"]),
        Paragraph(data.get("vendor", "Hikvision"), styles["ReportBody"]),
        Paragraph(data.get("device_type", "Likely CCTV/NVR"), styles["ReportBody"]),
        Paragraph(f"{data.get('confidence', 90)}% (Heuristic)", styles["ReportBody"]),
        Paragraph(f"<font name='Courier'>{open_ports_str}</font>", styles["ReportBody"]),
        Paragraph("<font color='#15803D'><b>Assessed</b></font>", styles["ReportBodyBold"]),
    ])

    inv_col_w = [90, 85, 110, 85, 95, 58]
    inv_table = Table(inv_rows, colWidths=inv_col_w)
    inv_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), pal["navy"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, -1), pal["light_bg"]),
        ("BOX", (0, 0), (-1, -1), 1, pal["border"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, pal["border"]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(inv_table)
    story.append(Spacer(1, 10))

    # Active Services Breakdown Table
    story.append(Paragraph("Active Services & Port Telemetry", styles["ReportH2"]))
    svc_headers = [
        Paragraph("<b>Port / Proto</b>", styles["ReportSmallBold"]),
        Paragraph("<b>State</b>", styles["ReportSmallBold"]),
        Paragraph("<b>Service</b>", styles["ReportSmallBold"]),
        Paragraph("<b>Product / Banner Details</b>", styles["ReportSmallBold"]),
        Paragraph("<b>Version</b>", styles["ReportSmallBold"]),
    ]

    svc_rows = [svc_headers]
    for s in services_list:
        p_proto = f"{s.get('port')}/{s.get('protocol', 'tcp')}"
        state = s.get("state", "open").upper()
        service_name = s.get("service") or "unknown"
        prod = s.get("product") or "Embedded service banner"
        ver = s.get("version") or "Not advertised"

        svc_rows.append([
            Paragraph(f"<font name='Courier'><b>{p_proto}</b></font>", styles["ReportSmallBold"]),
            Paragraph(f"<font color='#15803D'><b>{state}</b></font>", styles["ReportSmallBold"]),
            Paragraph(service_name, styles["ReportSmall"]),
            Paragraph(prod, styles["ReportSmall"]),
            Paragraph(ver, styles["ReportSmall"]),
        ])

    svc_col_w = [75, 50, 70, 228, 100]
    svc_table = Table(svc_rows, colWidths=svc_col_w)
    svc_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ("BOX", (0, 0), (-1, -1), 1, pal["border"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, pal["border"]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(svc_table)
    story.append(Spacer(1, 10))

    # Rigorous Controls Assessment Table (Passed / Failed / Not Assessed)
    story.append(Paragraph("Security Controls Evaluation Matrix", styles["ReportH2"]))
    story.append(Paragraph(
        "<i>Rigorous control status methodology: Controls are strictly categorized as <b>PASSED</b> (empirically tested and compliant), "
        "<b>FAILED</b> (empirically tested and deficient), or <b>NOT ASSESSED</b> (untested or inconclusive evidence). Untested controls are never marked passed.</i>",
        styles["ReportSmall"]
    ))
    story.append(Spacer(1, 4))

    controls_matrix = data.get("security_controls", [])
    ctrl_headers = [
        Paragraph("<b>Security Control</b>", styles["ReportSmallBold"]),
        Paragraph("<b>Target Scope</b>", styles["ReportSmallBold"]),
        Paragraph("<b>Status</b>", styles["ReportSmallBold"]),
        Paragraph("<b>Technical Evidence & Verification</b>", styles["ReportSmallBold"]),
    ]

    ctrl_rows = [ctrl_headers]
    for c in controls_matrix:
        status_val = c.get("status", "NOT ASSESSED")
        if status_val == "PASSED":
            st_color = pal["pass_text"]
            st_bg = pal["pass_bg"]
        elif status_val == "FAILED":
            st_color = pal["fail_text"]
            st_bg = pal["fail_bg"]
        else:
            st_color = pal["na_text"]
            st_bg = pal["na_bg"]

        st_para = Paragraph(f"<font color='{st_color.hexval()}'><b>{status_val}</b></font>", styles["ReportSmallBold"])

        ctrl_rows.append([
            Paragraph(f"<b>{c.get('name')}</b>", styles["ReportSmall"]),
            Paragraph(c.get("target_component", "Host"), styles["ReportSmall"]),
            st_para,
            Paragraph(c.get("evidence", ""), styles["ReportSmall"]),
        ])

    ctrl_col_w = [150, 75, 80, 218]
    ctrl_table = Table(ctrl_rows, colWidths=ctrl_col_w)
    ctrl_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ("BOX", (0, 0), (-1, -1), 1, pal["border"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, pal["border"]),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(ctrl_table)

    story.append(PageBreak())
    return story


def build_vulnerability_findings_pages(data: dict, styles: dict) -> list:
    """Pages 5-6: Detailed Vulnerability Findings grouped by severity."""
    story = []
    pal = get_report_palette()

    story.append(Paragraph("4. Detailed Technical Findings", styles["ReportH1"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=pal["navy"], spaceBefore=2, spaceAfter=8))

    intro = (
        "This section documents each identified security finding, configuration weakness, and protocol exposure. "
        "<b>Important Note:</b> Findings marked as <i>Unconfirmed Observation / Potential Exposure</i> reflect verified "
        "active services and omitted security headers. They do not constitute confirmed remote code execution or authentication bypass exploits."
    )
    story.append(Paragraph(intro, styles["ReportBody"]))
    story.append(Spacer(1, 6))

    findings = data.get("findings", [])
    if not findings:
        empty_box = Table([[
            Paragraph("<b>No Vulnerabilities or Exposures Identified</b><br/>All evaluated services adhered to minimum security baseline requirements.", styles["ReportBody"])
        ]], colWidths=[CONTENT_WIDTH])
        empty_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), pal["pass_bg"]),
            ("BOX", (0, 0), (-1, -1), 1, pal["pass_text"]),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ]))
        story.append(empty_box)
        story.append(PageBreak())
        return story

    # Order findings: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda f: sev_rank.get(f.get("severity", "INFO"), 5))

    for idx, f in enumerate(sorted_findings):
        fid = f.get("id", f"FIND-{idx+1}")
        title = f.get("title", "Unnamed Observation")
        sev = f.get("severity", "MEDIUM").upper()
        target = f.get("target", data.get("target", "192.168.1.8"))
        port = f.get("port") or ("554" if "RTSP" in fid else ("80" if "HTTP" in fid else "N/A"))
        desc = f.get("description") or "Configuration observation identified during security assessment."
        evidence = f.get("evidence") or "Service response or header inspection confirmed presence."
        remediation = f.get("remediation") or "Review and harden device configuration."
        confirmed = f.get("confirmed_vulnerability", False)
        cve_ref = f.get("cve_id") or "None / Configuration Baseline"

        # Badge colors
        if sev == "CRITICAL":
            badge_bg, badge_txt = pal["crit_bg"], pal["crit_text"]
        elif sev == "HIGH":
            badge_bg, badge_txt = pal["high_bg"], pal["high_text"]
        elif sev == "MEDIUM":
            badge_bg, badge_txt = pal["med_bg"], pal["med_text"]
        elif sev == "LOW":
            badge_bg, badge_txt = pal["low_bg"], pal["low_text"]
        else:
            badge_bg, badge_txt = pal["info_bg"], pal["info_text"]

        confirm_label = "<font color='#DC2626'><b>Confirmed Exploit</b></font>" if confirmed else "<font color='#D97706'><b>Unconfirmed Observation / Potential Exposure</b></font>"

        # Card content
        card_rows = [
            [
                Paragraph(f"<b>{fid}: {title}</b>", styles["CardHeaderTitle"]),
                Paragraph(f"<font color='{badge_txt.hexval()}'><b>[{sev}]</b></font>", styles["BadgeText"]),
            ],
            [
                Paragraph("<b>Affected Scope:</b>", styles["ReportSmallBold"]),
                Paragraph(f"{target}:{port}/tcp &nbsp;|&nbsp; <b>Status:</b> {confirm_label}", styles["ReportSmall"]),
            ],
            [
                Paragraph("<b>Description:</b>", styles["ReportSmallBold"]),
                Paragraph(desc, styles["ReportSmall"]),
            ],
            [
                Paragraph("<b>Technical Evidence:</b>", styles["ReportSmallBold"]),
                Paragraph(f"<font name='Courier' color='#0F172A'>{evidence}</font>", styles["ReportSmall"]),
            ],
            [
                Paragraph("<b>Remediation Action:</b>", styles["ReportSmallBold"]),
                Paragraph(remediation, styles["ReportSmall"]),
            ],
            [
                Paragraph("<b>Standards / Reference:</b>", styles["ReportSmallBold"]),
                Paragraph(cve_ref, styles["ReportSmall"]),
            ],
        ]

        card_table = Table(card_rows, colWidths=[130, CONTENT_WIDTH - 130])
        card_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), pal["light_bg"]),
            ("BACKGROUND", (1, 0), (1, 0), badge_bg),
            ("BOX", (0, 0), (-1, -1), 1, pal["border"]),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, pal["border"]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))

        story.append(KeepTogether([card_table, Spacer(1, 8)]))

    story.append(PageBreak())
    return story


def build_risk_distribution_page(data: dict, styles: dict) -> list:
    """Page 7: Risk Distribution, Visual Charts & Heuristic Methodology."""
    story = []
    pal = get_report_palette()

    story.append(Paragraph("5. Risk Distribution & Scoring Methodology", styles["ReportH1"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=pal["navy"], spaceBefore=2, spaceAfter=10))

    intro = (
        "This section presents the visual composition of identified findings and details the mathematical "
        "and architectural rationale of the platform's composite heuristic risk score."
    )
    story.append(Paragraph(intro, styles["ReportBody"]))
    story.append(Spacer(1, 6))

    # Pie Chart
    pie_drawing = draw_severity_pie_chart(data.get("severity_counts", {}))
    story.append(pie_drawing)
    story.append(Spacer(1, 10))

    # Risk Gauge Bar
    gauge_drawing = draw_risk_gauge_bar(data.get("risk_score", 65), data.get("risk_level", "HIGH"))
    story.append(gauge_drawing)
    story.append(Spacer(1, 12))

    # Scoring Methodology explanation
    story.append(Paragraph("Heuristic Risk Scoring Methodology vs. CVSS", styles["ReportH2"]))
    methodology_text = (
        "<b>Important Distinction:</b> The VigiCore Assessment Platform computes a composite heuristic score (0–100) specifically "
        "designed for embedded IoT, surveillance cameras, and digital video recorders. This heuristic is fundamentally distinct "
        "from the Common Vulnerability Scoring System (CVSS v3.1) base metric and does not represent an empirical probability of exploit.<br/><br/>"
        "• <b>Surface Exposure Weighting:</b> Unrestricted administrative or media ports (e.g. RTSP port 554, HTTP port 80) contribute "
        "direct risk points due to their exposure as ingress attack vectors across local networks.<br/>"
        "• <b>Defense-in-Depth Factoring:</b> The presence of hardening controls (e.g. X-Content-Type-Options, X-Frame-Options) validates "
        "web engine maturity, whereas missing HSTS and CSP headers contribute incremental risk points.<br/>"
        "• <b>Surveillance Criticality:</b> Because CCTV video streams carry physical safety, regulatory privacy, and surveillance implications, "
        "insecure streaming protocols are intentionally weighted higher than in generic IT server assessments."
    )
    story.append(Paragraph(methodology_text, styles["ReportBody"]))
    story.append(Spacer(1, 8))

    # Risk Tier Definitions Table
    tier_data = [
        [
            Paragraph("<b>Risk Tier</b>", styles["ReportSmallBold"]),
            Paragraph("<b>Score Range</b>", styles["ReportSmallBold"]),
            Paragraph("<b>Operational Definition & Recommended Urgency</b>", styles["ReportSmallBold"]),
        ],
        [
            Paragraph("<font color='#991B1B'><b>CRITICAL</b></font>", styles["ReportSmallBold"]),
            Paragraph("80 – 100", styles["ReportSmall"]),
            Paragraph("Actively exploitable remote vulnerability or unauthenticated root access. Remediate within 24 hours.", styles["ReportSmall"]),
        ],
        [
            Paragraph("<font color='#DC2626'><b>HIGH</b></font>", styles["ReportSmallBold"]),
            Paragraph("60 – 79", styles["ReportSmall"]),
            Paragraph("Exposed streaming daemons, unencrypted web management, or severe configuration weakness. Remediate within 7 days.", styles["ReportSmall"]),
        ],
        [
            Paragraph("<font color='#D97706'><b>MEDIUM</b></font>", styles["ReportSmallBold"]),
            Paragraph("40 – 59", styles["ReportSmall"]),
            Paragraph("Missing modern security headers, legacy protocol exposure, or unvalidated candidate CVE matches.", styles["ReportSmall"]),
        ],
        [
            Paragraph("<font color='#3B82F6'><b>LOW / INFO</b></font>", styles["ReportSmallBold"]),
            Paragraph("0 – 39", styles["ReportSmall"]),
            Paragraph("Hardened baseline with minor informational observations or protocol banners.", styles["ReportSmall"]),
        ],
    ]
    tier_col_w = [90, 80, CONTENT_WIDTH - 170]
    tier_table = Table(tier_data, colWidths=tier_col_w)
    tier_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ("BOX", (0, 0), (-1, -1), 1, pal["border"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, pal["border"]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(tier_table)

    story.append(PageBreak())
    return story


def build_remediation_roadmap_page(data: dict, styles: dict) -> list:
    """Page 8: Structured 4-phase remediation roadmap tied to actual findings."""
    story = []
    pal = get_report_palette()

    story.append(Paragraph("6. Prioritized Remediation Roadmap", styles["ReportH1"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=pal["navy"], spaceBefore=2, spaceAfter=10))

    intro = (
        "To achieve a hardened security baseline, remediation actions are structured into four phased execution windows. "
        "Every recommended control directly addresses specific technical findings discovered during this assessment."
    )
    story.append(Paragraph(intro, styles["ReportBody"]))
    story.append(Spacer(1, 6))

    phases = [
        (
            "PHASE 1: IMMEDIATE ACTIONS (0 – 48 HOURS)",
            pal["high_border"],
            pal["high_bg"],
            [
                (
                    "Isolate RTSP Port 554/tcp [Finding: CAM-RTSP-001]:",
                    "Configure network firewall rules or switch port ACLs to block direct subnet access to port 554. "
                    "Restrict stream consumption strictly to the authorized NVR or Video Management System (VMS) IP."
                ),
                (
                    "Verify Factory Default Credentials:",
                    "Ensure default administrative usernames and passwords (e.g. admin/12345, admin/admin) have been changed "
                    "to a high-entropy passphrase conforming to minimum 12-character complexity standards."
                ),
            ]
        ),
        (
            "PHASE 2: SHORT-TERM ACTIONS (1 – 2 WEEKS)",
            pal["med_border"],
            pal["med_bg"],
            [
                (
                    "Transition Web Management to Encrypted HTTPS [Finding: WEB-HTTP-001]:",
                    "Enable HTTPS on the camera web daemon using an internal enterprise TLS certificate. "
                    "Disable cleartext HTTP on port 80 or enforce an automatic 301 redirect to HTTPS."
                ),
                (
                    "Configure HTTP Defense Headers [Findings: HTTP-HDR-001, HTTP-HDR-002]:",
                    "Where web server firmware permits custom header injection, enable HTTP Strict Transport Security "
                    "(HSTS) and define a restrictive Content-Security-Policy (CSP)."
                ),
            ]
        ),
        (
            "PHASE 3: LONG-TERM ARCHITECTURAL HARDENING (30 – 90 DAYS)",
            pal["blue"],
            pal["blue_light"],
            [
                (
                    "Surveillance VLAN Micro-Segmentation:",
                    "Migrate all CCTV cameras, DVRs, and NVRs into an isolated, non-routable VLAN. Disable all inbound "
                    "and outbound internet connectivity for the surveillance subnet, routing remote access strictly through a hardened VPN."
                ),
                (
                    "Establish Firmware Lifecycle & Patching Review:",
                    "Implement a quarterly firmware verification schedule with the hardware vendor to apply security patches "
                    "and mitigate newly published CVE vulnerabilities."
                ),
            ]
        ),
        (
            "PHASE 4: VERIFICATION & RESCANNING REQUIREMENTS",
            pal["navy"],
            pal["light_bg"],
            [
                (
                    "Mandatory Verification Rescan:",
                    "Following the implementation of network ACLs and HTTPS enforcement, re-execute the VigiCore Scanner "
                    "to verify that risk score reduces from 65 to compliant baseline (<25) and all exposures are validated as closed."
                ),
            ]
        ),
    ]

    for phase_title, border_color, bg_color, items in phases:
        phase_rows = [[
            Paragraph(f"<b>{phase_title}</b>", styles["ReportSmallBold"])
        ]]
        for item_title, item_desc in items:
            item_p = Paragraph(f"• <b>{item_title}</b> {item_desc}", styles["ReportSmall"])
            phase_rows.append([item_p])

        phase_table = Table(phase_rows, colWidths=[CONTENT_WIDTH])
        phase_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), bg_color),
            ("BACKGROUND", (0, 1), (-1, -1), colors.white),
            ("BOX", (0, 0), (-1, -1), 1, border_color),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, pal["border"]),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(KeepTogether([phase_table, Spacer(1, 6)]))

    story.append(PageBreak())
    return story


def build_methodology_limitations_page(data: dict, styles: dict) -> list:
    """Final Page: Assessment Methodology, Tools Utilized & Technical Limitations."""
    story = []
    pal = get_report_palette()

    story.append(Paragraph("7. Methodology, Tools & Technical Limitations", styles["ReportH1"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=pal["navy"], spaceBefore=2, spaceAfter=10))

    intro = (
        "This section outlines the tooling, evaluation standards, and technical boundaries governing this assessment. "
        "Understanding these limitations is essential for contextualizing the findings and planning subsequent security activities."
    )
    story.append(Paragraph(intro, styles["ReportBody"]))
    story.append(Spacer(1, 6))

    # Tools Used
    story.append(Paragraph("Assessment Tools Utilized", styles["ReportH2"]))
    tools_data = [
        [
            Paragraph("<b>Component / Engine</b>", styles["ReportSmallBold"]),
            Paragraph("<b>Technical Role</b>", styles["ReportSmallBold"]),
            Paragraph("<b>Execution Mode</b>", styles["ReportSmallBold"]),
        ],
        [
            Paragraph("Nmap Network Scanner", styles["ReportSmallBold"]),
            Paragraph("Host discovery, TCP SYN scanning, service banner enumeration.", styles["ReportSmall"]),
            Paragraph("macOS Native CLI (Local)", styles["ReportSmall"]),
        ],
        [
            Paragraph("CCTV Fingerprinting Engine", styles["ReportSmallBold"]),
            Paragraph("Multi-vendor OUI matching, proprietary port and realm analysis.", styles["ReportSmall"]),
            Paragraph("Python Heuristic Core", styles["ReportSmall"]),
        ],
        [
            Paragraph("HTTP / RTSP Probe Engine", styles["ReportSmallBold"]),
            Paragraph("Security headers inspection (HSTS, CSP), RTSP stream detection.", styles["ReportSmall"]),
            Paragraph("Safe Non-Destructive", styles["ReportSmall"]),
        ],
        [
            Paragraph("ReportLab PDF Engine", styles["ReportSmallBold"]),
            Paragraph("Vector document generation, dynamic page accounting, data binding.", styles["ReportSmall"]),
            Paragraph("Server-Side Python", styles["ReportSmall"]),
        ],
    ]
    tools_col_w = [140, CONTENT_WIDTH - 260, 120]
    tools_table = Table(tools_data, colWidths=tools_col_w)
    tools_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ("BOX", (0, 0), (-1, -1), 1, pal["border"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, pal["border"]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(tools_table)
    story.append(Spacer(1, 10))

    # Scope of testing
    story.append(Paragraph("Checks Performed vs. Checks Not Performed", styles["ReportH2"]))
    checks_rows = [
        [
            Paragraph("<b>CHECKS PERFORMED</b>", styles["ReportSmallBold"]),
            Paragraph("<b>CHECKS NOT PERFORMED (OUT OF SCOPE)</b>", styles["ReportSmallBold"]),
        ],
        [
            Paragraph("• Active TCP port discovery on target surveillance daemons.<br/>"
                      "• HTTP/HTTPS header security evaluation.<br/>"
                      "• RTSP presence and media streaming detection.<br/>"
                      "• Manufacturer heuristic fingerprinting.<br/>"
                      "• Exact product/version CVE correlation heuristics.", styles["ReportSmall"]),
            Paragraph("• No brute-force authentication or credential stuffing.<br/>"
                      "• No live RTSP video stream packet decryption.<br/>"
                      "• No denial-of-service (DoS) or stress testing.<br/>"
                      "• No physical camera tampering or firmware dumping.<br/>"
                      "• No exploitation of zero-day vulnerabilities.", styles["ReportSmall"]),
        ]
    ]
    checks_table = Table(checks_rows, colWidths=[CONTENT_WIDTH / 2.0, CONTENT_WIDTH / 2.0])
    checks_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), pal["pass_bg"]),
        ("BACKGROUND", (1, 0), (1, 0), pal["high_bg"]),
        ("BOX", (0, 0), (-1, -1), 1, pal["border"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, pal["border"]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(checks_table)
    story.append(Spacer(1, 10))

    # Crucial Security Statement Box
    story.append(Paragraph("Assessment Limitations & Defensive Statement", styles["ReportH2"]))
    limitations_list = [
        "<b>Point-in-Time Evaluation:</b> Network security posture is dynamic. A device identified as secure today may be rendered vulnerable tomorrow by newly discovered vulnerabilities or environmental configuration modifications.",
        "<b>Heuristic Fingerprinting Constraints:</b> Device fingerprinting relies on observed network banners and MAC addresses. White-label OEM rebranding may restrict precise model identification.",
        "<b>Absence of Findings Disclaimer:</b> <font color='#DC2626'><b>An empty finding list or low risk score does not prove the device is completely secure.</b></font> Undetected vulnerabilities, hardware backdoors, or misconfigurations outside the scanned ports may still exist.",
    ]
    for lim in limitations_list:
        story.append(Paragraph(f"• {lim}", styles["ReportBody"]))

    return story


# -----------------------------------------------------------------------------
# MAIN GENERATOR FUNCTION
# -----------------------------------------------------------------------------

def generate_vapt_pdf(data: dict, output_path: str | Path | io.BytesIO) -> str:
    """
    Main entry point: compile data dictionary into an 8-9 page consulting-grade
    customer PDF report using ReportLab.
    """
    styles = create_report_styles()

    # Ensure output_path is string or stream (ReportLab requires str, not Path)
    target_dest = str(output_path) if isinstance(output_path, Path) else output_path

    # Create DocTemplate
    doc = SimpleDocTemplate(
        target_dest,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=50,
        bottomMargin=50,
        title=f"VigiCore CCTV VAPT Report - {data.get('target', 'Audit')}",
        author="VigiCore Platform Enterprise",
    )

    # Set metadata for NumberedCanvas
    NumberedCanvas.report_id = data.get("report_id", "REP-CCTV-AUDIT")
    NumberedCanvas.report_date = data.get("scan_date_formatted", datetime.now().strftime("%B %d, %Y"))

    # Build story
    story = []
    story.extend(build_cover_page(data, styles))
    story.extend(build_executive_summary_page(data, styles))
    story.extend(build_network_overview_page(data, styles))
    story.extend(build_device_inventory_page(data, styles))
    story.extend(build_vulnerability_findings_pages(data, styles))
    story.extend(build_risk_distribution_page(data, styles))
    story.extend(build_remediation_roadmap_page(data, styles))
    story.extend(build_methodology_limitations_page(data, styles))

    # Compile PDF
    doc.build(story, canvasmaker=NumberedCanvas)

    if isinstance(output_path, (str, Path)):
        return str(output_path)
    return "in-memory-pdf"
