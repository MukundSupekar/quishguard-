import os
import io
import base64
import uuid
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, render_template, redirect, url_for, send_file, Response
from werkzeug.utils import secure_filename

from quishguard.config import SECRET_KEY, UPLOADS_DIR, REPORTS_DIR, MAX_CONTENT_LENGTH
from quishguard.qr_engine import qr_engine
from quishguard.pdf_extractor import pdf_extractor
from quishguard.pipeline import process_security_pipeline
from quishguard.database import (
    get_scan, get_history, get_dashboard_metrics,
    get_blocklist, add_to_blocklist
)
from quishguard.report_generator import report_generator
from quishguard.siem import siem_service
from quishguard.playbooks import playbook_manager

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "bmp", "webp", "gif"}
ALLOWED_DOC_EXTENSIONS = {"pdf"}

def allowed_file(filename: str, allowed_set: set) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_set

# --- Page Routes ---

@app.route("/")
def index():
    metrics = get_dashboard_metrics()
    return render_template("index.html", metrics=metrics)

@app.route("/scan/<scan_id>")
def scan_result_page(scan_id):
    scan_data = get_scan(scan_id)
    if not scan_data:
        return render_template("404.html", message=f"Scan #{scan_id} not found"), 404
    return render_template("result.html", scan=scan_data)

@app.route("/interstitial/<scan_id>")
def interstitial_warning_page(scan_id):
    scan_data = get_scan(scan_id)
    if not scan_data:
        return redirect(url_for("index"))
    return render_template("interstitial.html", scan=scan_data)

@app.route("/history")
def history_page():
    classification = request.args.get("classification", "ALL")
    search = request.args.get("search", "")
    history = get_history(limit=150, classification=classification, search=search)
    return render_template("history.html", history=history, current_filter=classification, search=search)

@app.route("/soc")
def soc_dashboard_page():
    metrics = get_dashboard_metrics()
    blocklist = get_blocklist()
    siem_events = siem_service.get_recent_events(limit=30)
    return render_template("soc_dashboard.html", metrics=metrics, blocklist=blocklist, siem_events=siem_events)

# --- REST API Endpoints ---

@app.route("/api/scan/image", methods=["POST"])
def api_scan_image():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected"}), 400

    if not allowed_file(file.filename, ALLOWED_IMAGE_EXTENSIONS):
        return jsonify({"success": False, "error": f"Invalid image format. Allowed: {', '.join(ALLOWED_IMAGE_EXTENSIONS)}"}), 400

    filename = secure_filename(file.filename)
    file_bytes = file.read()
    
    # Run multi-strategy QR engine
    qr_res = qr_engine.decode_image(file_bytes)
    
    if not qr_res.detected:
        return jsonify({
            "success": False,
            "qr_detected": False,
            "error": "No QR code could be decoded from this image despite multi-strategy filtering.",
            "strategies_attempted": qr_res.strategy
        }), 422

    client_ip = request.remote_addr or "127.0.0.1"
    scan_result = process_security_pipeline(
        raw_payload=qr_res.payload,
        source_type="image",
        filename=filename,
        qr_detected=True,
        client_ip=client_ip,
        qr_metadata=qr_res.to_dict()
    )

    return jsonify({
        "success": True,
        "scan_id": scan_result["id"],
        "result": scan_result,
        "redirect_url": url_for("scan_result_page", scan_id=scan_result["id"])
    })

@app.route("/api/scan/camera", methods=["POST"])
def api_scan_camera():
    data = request.get_json() or {}
    payload = data.get("payload", "").strip()
    image_base64 = data.get("image_base64", "").strip()
    client_ip = request.remote_addr or "127.0.0.1"

    qr_metadata = {}
    if not payload and image_base64:
        try:
            if "," in image_base64:
                image_base64 = image_base64.split(",", 1)[1]
            frame_bytes = base64.b64decode(image_base64)
            qr_res = qr_engine.decode_image(frame_bytes)
            if qr_res.detected:
                payload = qr_res.payload
                qr_metadata = qr_res.to_dict()
            else:
                return jsonify({"success": False, "qr_detected": False, "error": "No QR detected in video frame"}), 422
        except Exception as e:
            return jsonify({"success": False, "error": f"Camera frame processing failed: {str(e)}"}), 400

    if not payload:
        return jsonify({"success": False, "error": "No payload or frame provided"}), 400

    scan_result = process_security_pipeline(
        raw_payload=payload,
        source_type="camera",
        filename="live_camera_capture.png",
        qr_detected=True,
        client_ip=client_ip,
        qr_metadata=qr_metadata
    )

    return jsonify({
        "success": True,
        "scan_id": scan_result["id"],
        "result": scan_result,
        "redirect_url": url_for("scan_result_page", scan_id=scan_result["id"])
    })

@app.route("/api/scan/pdf", methods=["POST"])
def api_scan_pdf():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected"}), 400

    if not allowed_file(file.filename, ALLOWED_DOC_EXTENSIONS):
        return jsonify({"success": False, "error": "Invalid format. Expected PDF document."}), 400

    filename = secure_filename(file.filename)
    pdf_bytes = file.read()
    
    pdf_res = pdf_extractor.scan_pdf(pdf_bytes)
    if not pdf_res["qr_detected"]:
        return jsonify({
            "success": False,
            "qr_detected": False,
            "total_pages": pdf_res["total_pages"],
            "error": "No QR codes found inside this PDF document."
        }), 422

    client_ip = request.remote_addr or "127.0.0.1"
    scan_result = process_security_pipeline(
        raw_payload=pdf_res["primary_payload"],
        source_type="pdf",
        filename=filename,
        qr_detected=True,
        client_ip=client_ip,
        qr_metadata={"pdf_findings": pdf_res["qr_findings"], "total_pages": pdf_res["total_pages"]}
    )

    return jsonify({
        "success": True,
        "scan_id": scan_result["id"],
        "total_qrs_found": pdf_res["total_qrs_found"],
        "pdf_findings": pdf_res["qr_findings"],
        "result": scan_result,
        "redirect_url": url_for("scan_result_page", scan_id=scan_result["id"])
    })

@app.route("/api/scan/url", methods=["POST"])
def api_scan_url():
    data = request.get_json() or {}
    target_url = data.get("url", "").strip()
    if not target_url:
        return jsonify({"success": False, "error": "No URL provided"}), 400

    client_ip = request.remote_addr or "127.0.0.1"
    scan_result = process_security_pipeline(
        raw_payload=target_url,
        source_type="url",
        filename="direct_url_input",
        qr_detected=True,
        client_ip=client_ip
    )

    return jsonify({
        "success": True,
        "scan_id": scan_result["id"],
        "result": scan_result,
        "redirect_url": url_for("scan_result_page", scan_id=scan_result["id"])
    })

@app.route("/api/scan/<scan_id>")
def api_get_scan(scan_id):
    scan_data = get_scan(scan_id)
    if not scan_data:
        return jsonify({"success": False, "error": "Scan not found"}), 404
    return jsonify({"success": True, "scan": scan_data})

@app.route("/api/history")
def api_get_history():
    classification = request.args.get("classification")
    search = request.args.get("search")
    history = get_history(limit=100, classification=classification, search=search)
    return jsonify({"success": True, "count": len(history), "history": history})

@app.route("/api/report/<scan_id>")
def api_download_report(scan_id):
    scan_data = get_scan(scan_id)
    if not scan_data:
        return jsonify({"error": "Scan not found"}), 404

    fmt = request.args.get("format", "pdf").lower()
    
    if fmt == "json":
        json_content = report_generator.generate_json_report(scan_data)
        return Response(
            json_content,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment;filename=QuishGuard_Report_{scan_id}.json"}
        )
    else:
        pdf_bytes = report_generator.generate_pdf_report(scan_data)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"QuishGuard_Report_{scan_id}.pdf"
        )

@app.route("/api/dashboard")
def api_dashboard_metrics():
    metrics = get_dashboard_metrics()
    return jsonify({"success": True, "metrics": metrics})

@app.route("/api/siem/events")
def api_siem_events():
    events = siem_service.get_recent_events(limit=50)
    fmt = request.args.get("format", "json").lower()
    
    if fmt == "cef":
        cef_lines = [siem_service.format_cef(e["details"]) for e in events if "details" in e]
        return Response("\n".join(cef_lines), mimetype="text/plain")
        
    return jsonify({"success": True, "count": len(events), "events": events})

@app.route("/api/playbook/action", methods=["POST"])
def api_playbook_action():
    data = request.get_json() or {}
    action = data.get("action")
    
    if action == "BLOCK_DOMAIN":
        domain = data.get("domain", "").strip()
        reason = data.get("reason", "Manual SOC block via QuishGuard dashboard")
        res = playbook_manager.execute_block_domain(domain, reason)
        return jsonify(res)
        
    elif action == "CREATE_INCIDENT":
        scan_id = data.get("scan_id", "").strip()
        res = playbook_manager.execute_create_incident(scan_id)
        return jsonify(res)
        
    elif action == "GET_FIREWALL_RULES":
        domain = data.get("domain", "").strip()
        rules = playbook_manager.generate_firewall_rules(domain)
        return jsonify({"success": True, "rules": rules})
        
    return jsonify({"success": False, "error": f"Unknown action '{action}'"}), 400

@app.route("/api/test-samples")
def api_test_samples():
    """Returns safe demonstration test URLs representing different threat tiers."""
    return jsonify({
        "success": True,
        "samples": [
            {
                "label": "Safe University Documentation",
                "category": "SAFE",
                "url": "https://www.ox.ac.uk/research",
                "expected_tier": "Safe (0-20)"
            },
            {
                "label": "URL Shortener Redirect Chain",
                "category": "SUSPICIOUS",
                "url": "https://tinyurl.com/quish-test-doc",
                "expected_tier": "Suspicious / Low Risk (25-45)"
            },
            {
                "label": "PayPal Brand Impersonation Phishing",
                "category": "PHISHING",
                "url": "https://paypa1-security-check.xyz/login/verify?account=urgent",
                "expected_tier": "High Risk - Phishing (65-85)"
            },
            {
                "label": "Malicious Executable Dropper Link",
                "category": "MALWARE",
                "url": "http://evil-payload-dist.org/downloads/setup_invoice.pdf.exe",
                "expected_tier": "High Risk - Malware (75-95)"
            },
            {
                "label": "EICAR Standard Security Test Site",
                "category": "MALWARE",
                "url": "https://www.eicar.org/download-anti-malware-testfile/",
                "expected_tier": "High Risk / Critical (80-100)"
            }
        ]
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
