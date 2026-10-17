"""
Report generator for SecureWatch SIEM Dashboard.

Generates Daily/Weekly/Monthly security reports in CSV and PDF formats.
"""

import csv
import io
import os
from datetime import datetime, timedelta
from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from models import db, Event, Alert, Incident
from sqlalchemy import func


def _range(period):
    """Get date range for the specified period."""
    now = datetime.utcnow()
    if period == "daily":
        start = now - timedelta(days=1)
    elif period == "weekly":
        start = now - timedelta(weeks=1)
    else:  # monthly
        start = now - timedelta(days=30)
    return start, now


def stats(period):
    """Generate statistics for the specified period."""
    start, end = _range(period)
    evs = db.session.query(Event).filter(Event.timestamp >= start).all()
    
    sev = {}
    for e in evs:
        sev[e.severity] = sev.get(e.severity, 0) + 1
    
    types = {}
    for e in evs:
        types[e.event_type] = types.get(e.event_type, 0) + 1
    
    ip_counts = {}
    for e in evs:
        if e.source_ip not in ("-", "localhost"):
            ip_counts[e.source_ip] = ip_counts.get(e.source_ip, 0) + 1
    
    alerts = Alert.query.filter(Alert.created_at >= start).all()
    incs = Incident.query.all()
    failed = sum(1 for e in evs if "Failed" in e.event_type)
    
    return dict(
        start=start,
        end=end,
        total=len(evs),
        severity=sev,
        types=types,
        top_ips=dict(sorted(ip_counts.items(), key=lambda x: -x[1])[:10]),
        alerts=len(alerts),
        critical_alerts=sum(1 for a in alerts if a.severity == "Critical"),
        incidents=len(incs),
        open_incidents=sum(1 for i in incs if i.status in ("Open", "Investigating")),
        failed_logins=failed,
    )


def to_csv(period):
    """Generate CSV report for the specified period."""
    s = stats(period)
    buf = io.StringIO()
    wr = csv.writer(buf)
    
    wr.writerow(["SecureWatch SIEM Report"])
    wr.writerow(["Period", period])
    wr.writerow(["Range", f"{s['start']:%Y-%m-%d %H:%M} -> {s['end']:%Y-%m-%d %H:%M}"])
    wr.writerow([])
    
    wr.writerow(["Metric", "Value"])
    for k in ("total", "alerts", "critical_alerts", "incidents", "open_incidents", "failed_logins"):
        wr.writerow([k, s[k]])
    
    wr.writerow([])
    wr.writerow(["Severity", "Count"])
    for k, v in sorted(s["severity"].items()):
        wr.writerow([k, v])
    
    wr.writerow([])
    wr.writerow(["Top Source IP", "Events"])
    for k, v in list(s["top_ips"].items())[:10]:
        wr.writerow([k, v])
    
    return buf.getvalue()


def to_pdf_bytes(period):
    """Generate PDF report for the specified period using reportlab."""
    s = stats(period)
    
    # Create PDF buffer
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                           topMargin=0.75*inch, bottomMargin=0.75*inch,
                           leftMargin=0.75*inch, rightMargin=0.75*inch)
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#0d6efd'),
        spaceAfter=12,
        alignment=TA_CENTER
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#0d6efd'),
        spaceAfter=10,
        spaceBefore=15
    )
    
    normal_style = styles['Normal']
    
    # Build PDF content
    story = []
    
    # Title
    story.append(Paragraph("SecureWatch SIEM Dashboard", title_style))
    story.append(Paragraph("Security Report", title_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Report info
    story.append(Paragraph(f"<b>Generated:</b> {datetime.utcnow():%Y-%m-%d %H:%M UTC}", normal_style))
    story.append(Paragraph(f"<b>Period:</b> {period.title()}", normal_style))
    story.append(Paragraph(f"<b>Range:</b> {s['start']:%Y-%m-%d} to {s['end']:%Y-%m-%d}", normal_style))
    story.append(Spacer(1, 0.3*inch))
    
    # Summary section
    story.append(Paragraph("Summary", heading_style))
    
    summary_data = [
        ["Metric", "Value"],
        ["Total Events", str(s['total'])],
        ["Total Alerts", f"{s['alerts']} (Critical: {s['critical_alerts']})"],
        ["Incidents", f"{s['incidents']} (Open: {s['open_incidents']})"],
        ["Failed Logins", str(s['failed_logins'])],
    ]
    
    summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d6efd')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('TOPPADDING', (0, 1), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Events by severity
    story.append(Paragraph("Events by Severity", heading_style))
    
    sev_data = [["Severity", "Count"]]
    for sev in ["Information", "Warning", "Medium", "High", "Critical"]:
        count = s['severity'].get(sev, 0)
        sev_data.append([sev, str(count)])
    
    sev_table = Table(sev_data, colWidths=[3*inch, 3*inch])
    sev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d6efd')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('TOPPADDING', (0, 1), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Top source IPs
    if s['top_ips']:
        story.append(Paragraph("Top Source IPs", heading_style))
        
        ip_data = [["Source IP", "Event Count"]]
        for ip, count in list(s['top_ips'].items())[:10]:
            ip_data.append([ip, str(count)])
        
        ip_table = Table(ip_data, colWidths=[3*inch, 3*inch])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d6efd')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('TOPPADDING', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ]))
        story.append(ip_table)
        story.append(Spacer(1, 0.3*inch))
    
    # Event types
    if s['types']:
        story.append(Paragraph("Event Types", heading_style))
        
        type_data = [["Event Type", "Count"]]
        for etype, count in sorted(s['types'].items(), key=lambda x: -x[1])[:12]:
            type_data.append([etype, str(count)])
        
        type_table = Table(type_data, colWidths=[3*inch, 3*inch])
        type_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d6efd')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('TOPPADDING', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ]))
        story.append(type_table)
    
    # Build PDF
    doc.build(story)
    pdf = buffer.getvalue()
    buffer.close()
    
    return pdf


def save_report(period, fmt="pdf"):
    """Save report to file."""
    os.makedirs(os.path.dirname(__file__) + "/reports", exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    
    if fmt == "csv":
        path = f"reports/report_{period}_{stamp}.csv"
        with open(path, "w", encoding="utf-8") as f:
            f.write(to_csv(period))
    else:
        path = f"reports/report_{period}_{stamp}.pdf"
        with open(path, "wb") as f:
            f.write(to_pdf_bytes(period))
    
    return path