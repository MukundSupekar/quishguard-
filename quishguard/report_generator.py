import json
import io
from datetime import datetime
from typing import Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

class ReportGenerator:
    """
    Generates downloadable forensic security reports in PDF and JSON formats.
    """
    def __init__(self):
        pass

    def generate_json_report(self, scan_data: Dict[str, Any]) -> str:
        return json.dumps(scan_data, indent=2)

    def generate_pdf_report(self, scan_data: Dict[str, Any]) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom cybersecurity styles
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=colors.HexColor('#0f172a'),
            fontName='Helvetica-Bold',
            spaceAfter=4
        )
        
        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#64748b'),
            spaceAfter=14
        )
        
        heading2_style = ParagraphStyle(
            'Heading2Style',
            parent=styles['Heading2'],
            fontSize=12,
            textColor=colors.HexColor('#1e293b'),
            fontName='Helvetica-Bold',
            spaceBefore=10,
            spaceAfter=6
        )
        
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#334155'),
            leading=12
        )

        score = scan_data.get("risk_score", 0)
        classification = scan_data.get("classification", "UNKNOWN")

        # Color based on score
        if score <= 20:
            badge_color = colors.HexColor('#10b981')  # Green
        elif score <= 40:
            badge_color = colors.HexColor('#f59e0b')  # Amber
        elif score <= 60:
            badge_color = colors.HexColor('#f97316')  # Orange
        else:
            badge_color = colors.HexColor('#ef4444')  # Red

        elements = []

        # 1. Header Banner
        elements.append(Paragraph("🛡️ QUISHGUARD FORENSIC SECURITY REPORT", title_style))
        elements.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Reference ID: {scan_data.get('id', 'N/A')}",
            subtitle_style
        ))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#cbd5e1"), spaceAfter=12))

        # 2. Executive Threat Summary Card (Table)
        summary_table_data = [
            [
                Paragraph("<b>Risk Score</b>", body_style),
                Paragraph(f"<b><font size='16' color='{badge_color.hexval()}'>{score} / 100</font></b>", body_style),
                Paragraph("<b>Classification</b>", body_style),
                Paragraph(f"<b><font color='{badge_color.hexval()}'>{classification}</font></b>", body_style),
            ],
            [
                Paragraph("<b>Recommended Action</b>", body_style),
                Paragraph(f"<b>{scan_data.get('recommendation', 'ALLOW')}</b>", body_style),
                Paragraph("<b>Scan Method</b>", body_style),
                Paragraph(scan_data.get("source_type", "Image").upper(), body_style),
            ]
        ]
        summary_table = Table(summary_table_data, colWidths=[120, 150, 120, 150])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 14))

        # 3. Target URL & Domain Breakdown
        elements.append(Paragraph("TARGET METADATA & RECONNAISSANCE", heading2_style))
        url_table_data = [
            [Paragraph("<b>Extracted Payload</b>", body_style), Paragraph(scan_data.get("raw_payload", "N/A")[:90], body_style)],
            [Paragraph("<b>Normalized URL</b>", body_style), Paragraph(scan_data.get("normalized_url", "N/A")[:90], body_style)],
            [Paragraph("<b>Registered Domain</b>", body_style), Paragraph(scan_data.get("domain", "N/A"), body_style)],
            [Paragraph("<b>Protocol / Scheme</b>", body_style), Paragraph(scan_data.get("protocol", "N/A").upper(), body_style)],
            [Paragraph("<b>Identified Threat Types</b>", body_style), Paragraph(", ".join(scan_data.get("threat_types", [])) or "None Detected", body_style)]
        ]
        url_table = Table(url_table_data, colWidths=[140, 400])
        url_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(url_table)
        elements.append(Spacer(1, 14))

        # 4. Forensic Evidence & Risk Indicators
        elements.append(Paragraph("DETECTED THREAT INDICATORS & EVIDENCE", heading2_style))
        indicators = scan_data.get("indicators", [])
        if indicators:
            ind_table_data = [["Category", "Severity", "Impact", "Forensic Explanation"]]
            for ind in indicators[:10]:
                ind_table_data.append([
                    Paragraph(ind.get("category", "General"), body_style),
                    Paragraph(f"<b>{ind.get('severity', 'INFO')}</b>", body_style),
                    Paragraph(f"+{ind.get('points', 0)} pts", body_style),
                    Paragraph(ind.get("message", ""), body_style)
                ])
            ind_table = Table(ind_table_data, colWidths=[100, 70, 60, 310])
            ind_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 5),
            ]))
            elements.append(ind_table)
        else:
            elements.append(Paragraph("No anomalous risk indicators were detected for this destination.", body_style))
        elements.append(Spacer(1, 14))

        # 5. Redirect Trace Section
        redirect_chain = scan_data.get("redirect_chain", [])
        if len(redirect_chain) > 1:
            elements.append(Paragraph("REDIRECT TRACE EVIDENCE", heading2_style))
            red_table_data = [["Hop", "Status", "Domain", "Hop Target URL"]]
            for hop in redirect_chain:
                red_table_data.append([
                    str(hop.get("hop", 1)),
                    str(hop.get("status_code", "200")),
                    hop.get("domain", "") or "N/A",
                    Paragraph(hop.get("url", "")[:70], body_style)
                ])
            red_table = Table(red_table_data, colWidths=[40, 50, 120, 330])
            red_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#334155')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(red_table)
            elements.append(Spacer(1, 14))

        # 6. SOC Sign-off / Confidentiality Footer
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=8))
        elements.append(Paragraph(
            "Confidentiality: QuishGuard Automated Cybersecurity Defense System. For authorized institutional and incident response use.",
            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=7.5, textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER)
        ))

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()

report_generator = ReportGenerator()
