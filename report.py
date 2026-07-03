from datetime import datetime
from io import BytesIO
import textwrap

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    ListFlowable,
    ListItem,
    Preformatted,
)
from reportlab.lib.enums import TA_CENTER


def safe_text(value):
    if value is None:
        return "N/A"
    return str(value)


def bullet_list(items, styles):
    return ListFlowable(
        [
            ListItem(
                Paragraph(safe_text(item), styles["Normal"]),
                bulletColor="black"
            )
            for item in items
        ],
        bulletType="bullet"
    )


def generate_incident_pdf(alert, triage):
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=18,
        spaceAfter=16,
    )

    heading_style = ParagraphStyle(
        "CustomHeading",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=12,
        spaceAfter=8,
    )

    normal = styles["Normal"]

    story = []

    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    story.append(Paragraph("AI-Powered SOC Dashboard", title_style))
    story.append(Paragraph("Incident Triage Report", title_style))
    story.append(Paragraph(f"<b>Generated At:</b> {report_time}", normal))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("1. Alert Overview", heading_style))
    story.append(Paragraph(f"<b>Timestamp:</b> {safe_text(alert.get('timestamp', 'N/A'))}", normal))
    story.append(Paragraph(f"<b>Agent:</b> {safe_text(alert.get('agent', 'N/A'))}", normal))
    story.append(Paragraph(f"<b>Rule ID:</b> {safe_text(alert.get('rule_id', 'N/A'))}", normal))
    story.append(Paragraph(f"<b>Severity Level:</b> {safe_text(alert.get('level', 'N/A'))}", normal))
    story.append(Paragraph(f"<b>Triage Severity:</b> {safe_text(triage.get('severity', 'N/A'))}", normal))
    story.append(Paragraph(f"<b>Alert Description:</b> {safe_text(alert.get('description', 'N/A'))}", normal))
    story.append(Paragraph(f"<b>Rule Groups:</b> {safe_text(alert.get('groups', 'N/A'))}", normal))
    story.append(Paragraph(f"<b>Log Location:</b> {safe_text(alert.get('location', 'N/A'))}", normal))

    story.append(Paragraph("2. AI Analyst Summary", heading_style))
    story.append(Paragraph(f"<b>Attack Type:</b> {safe_text(triage.get('attack_type', 'N/A'))}", normal))
    story.append(Paragraph(f"<b>Summary:</b> {safe_text(triage.get('summary', 'N/A'))}", normal))
    story.append(Paragraph(f"<b>Severity Reason:</b> {safe_text(triage.get('severity_reason', 'N/A'))}", normal))

    story.append(Paragraph("3. MITRE ATT&amp;CK Mapping", heading_style))
    story.append(Paragraph(f"<b>MITRE Tactic:</b> {safe_text(triage.get('mitre_tactic', 'N/A'))}", normal))
    story.append(Paragraph(f"<b>MITRE Technique:</b> {safe_text(triage.get('mitre_technique', 'N/A'))}", normal))

    story.append(Paragraph("4. Investigation Steps", heading_style))
    story.append(bullet_list(triage.get("investigation_steps", []), styles))

    story.append(Paragraph("5. Recommended Response Actions", heading_style))
    story.append(bullet_list(triage.get("response_actions", []), styles))

    story.append(Paragraph("6. False Positive Note", heading_style))
    story.append(Paragraph(safe_text(triage.get("false_positive_note", "N/A")), normal))

    story.append(Paragraph("7. Raw Log Evidence", heading_style))

    raw_log = safe_text(alert.get("full_log", "N/A"))
    wrapped_log = textwrap.fill(raw_log, width=90)
    story.append(Preformatted(wrapped_log, styles["Code"]))

    story.append(Paragraph("8. Analyst Notes", heading_style))
    story.append(Paragraph("Add manual investigation notes here.", normal))

    doc.build(story)

    pdf = buffer.getvalue()
    buffer.close()

    return pdf