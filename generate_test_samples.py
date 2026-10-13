"""
Generate test QR code images and a PDF containing embedded QR codes
for testing the QuishGuard detection pipeline across all threat tiers.
"""

import os
from pathlib import Path
import qrcode
from PIL import Image, ImageOps
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

OUT_DIR = Path(__file__).resolve().parent / "test_samples"
OUT_DIR.mkdir(parents=True, exist_ok=True)

TEST_CASES = [
    {
        "filename": "01_safe_university.png",
        "url": "https://www.ox.ac.uk/research",
        "title": "Safe University Documentation",
        "inverted": False
    },
    {
        "filename": "02_url_shortener.png",
        "url": "https://tinyurl.com/quish-test-doc",
        "title": "URL Shortener Redirect Hop",
        "inverted": False
    },
    {
        "filename": "03_paypal_phishing.png",
        "url": "https://paypa1-security-check.xyz/login/verify?account=urgent",
        "title": "PayPal Brand Impersonation Phishing",
        "inverted": False
    },
    {
        "filename": "04_malware_dropper.png",
        "url": "http://evil-payload-dist.org/downloads/setup_invoice.pdf.exe",
        "title": "Malware Executable Dropper",
        "inverted": False
    },
    {
        "filename": "05_eicar_test.png",
        "url": "https://www.eicar.org/download-anti-malware-testfile/",
        "title": "EICAR Standard Security Test Site",
        "inverted": False
    },
    {
        "filename": "06_fancy_inverted.png",
        "url": "https://paypa1-security-check.xyz/verify",
        "title": "Stylized Inverted Dark Mode QR",
        "inverted": True
    }
]

def generate_qr_images():
    print(f"[*] Generating test QR code images in {OUT_DIR}...")
    for tc in TEST_CASES:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(tc["url"])
        qr.make(fit=True)

        if tc["inverted"]:
            # White on black (inverted)
            img = qr.make_image(fill_color="white", back_color="black").convert('RGB')
        else:
            img = qr.make_image(fill_color="black", back_color="white").convert('RGB')

        target_path = OUT_DIR / tc["filename"]
        img.save(str(target_path))
        print(f"  [+] Created {tc['filename']} ({tc['title']})")

def generate_test_pdf():
    pdf_path = OUT_DIR / "07_embedded_invoice_qr.pdf"
    print(f"[*] Generating sample PDF document with embedded QR at {pdf_path}...")
    
    # Use the PayPal phishing QR sample to embed in the PDF
    qr_img_path = OUT_DIR / "03_paypal_phishing.png"

    doc = SimpleDocTemplate(str(pdf_path), pagesize=letter, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
    styles = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=12
    )
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#334155')
    )

    elements.append(Paragraph("<b>GLOBAL LOGISTICS - EXPEDITED SHIPMENT NOTICE</b>", title_style))
    elements.append(Paragraph("Tracking Ref: <b>#GL-9948201-US</b> | Date: September 20, 2026", body_style))
    elements.append(Spacer(1, 15))
    elements.append(Paragraph(
        "Important Security Notice: An expedited parcel delivery requires identity verification. "
        "Please scan the QR code below using your mobile device camera to confirm your billing details and release the package.",
        body_style
    ))
    elements.append(Spacer(1, 20))

    # Embed QR image
    elements.append(RLImage(str(qr_img_path), width=180, height=180))
    elements.append(Spacer(1, 15))
    elements.append(Paragraph("<i>Scan the QR code to verify account and avoid dispatch cancellation.</i>", body_style))

    doc.build(elements)
    print(f"  [+] Created {pdf_path.name}")

if __name__ == "__main__":
    generate_qr_images()
    generate_test_pdf()
    print("\n[+] All test assets generated successfully.")
