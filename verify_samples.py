"""
Verification runner: Evaluates all generated sample QR assets
through the QuishGuard detection pipeline.
"""

from pathlib import Path
from quishguard.qr_engine import qr_engine
from quishguard.pdf_extractor import pdf_extractor
from quishguard.pipeline import process_security_pipeline

def run_verification():
    samples_dir = Path(__file__).resolve().parent / "test_samples"
    print("=" * 85)
    print("QUISHGUARD DEFENSE PIPELINE - END-TO-END ASSET VERIFICATION")
    print("=" * 85)

    print("\n--- 1. Testing Standalone QR Images & Evasive Inverted Styles ---")
    for img_path in sorted(samples_dir.glob("*.png")):
        qr_res = qr_engine.decode_image(img_path)
        if qr_res.detected:
            scan = process_security_pipeline(
                raw_payload=qr_res.payload,
                source_type="image",
                filename=img_path.name,
                qr_metadata=qr_res.to_dict()
            )
            print(f"  [+] {img_path.name:<25} -> Engine: {qr_res.engine:<9} | Strategy: {qr_res.strategy:<16} | Score: {scan['risk_score']:>3}/100 | Class: {scan['classification']:<22} | Action: {scan['recommendation']}")
        else:
            print(f"  [-] {img_path.name:<25} -> FAILED TO DECODE")

    print("\n--- 2. Testing Covert QR Codes Embedded Inside Multi-page PDFs ---")
    for pdf_path in sorted(samples_dir.glob("*.pdf")):
        pdf_res = pdf_extractor.scan_pdf(pdf_path)
        if pdf_res["qr_detected"]:
            scan = process_security_pipeline(
                raw_payload=pdf_res["primary_payload"],
                source_type="pdf",
                filename=pdf_path.name,
                qr_metadata={"total_pages": pdf_res["total_pages"]}
            )
            print(f"  [+] {pdf_path.name:<25} -> Pages: {pdf_res['total_pages']} | QRs Found: {pdf_res['total_qrs_found']} | Score: {scan['risk_score']:>3}/100 | Class: {scan['classification']:<22} | Action: {scan['recommendation']}")
        else:
            print(f"  [-] {pdf_path.name:<25} -> NO QR FOUND")

    print("\n" + "=" * 85)
    print("[+] Full End-to-End Asset Verification Complete.")
    print("=" * 85)

if __name__ == "__main__":
    run_verification()
