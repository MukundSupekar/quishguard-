import unittest
import json
from app import app

class TestQuishGuardAPI(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_index_page(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"QR SECURITY SCANNER", resp.data)

    def test_history_page(self):
        resp = self.client.get("/history")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Scan History", resp.data)

    def test_soc_dashboard_page(self):
        resp = self.client.get("/soc")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"SOC Operations", resp.data)

    def test_api_scan_url_safe(self):
        payload = {"url": "https://www.ox.ac.uk/research"}
        resp = self.client.post("/api/scan/url", data=json.dumps(payload), content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["result"]["classification"], "SAFE")
        self.assertLessEqual(data["result"]["risk_score"], 20)

    def test_api_scan_url_phishing(self):
        payload = {"url": "https://paypa1-security-check.xyz/login/verify?account=urgent"}
        resp = self.client.post("/api/scan/url", data=json.dumps(payload), content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("PHISHING", data["result"]["classification"])
        self.assertGreaterEqual(data["result"]["risk_score"], 60)
        self.assertEqual(data["result"]["recommendation"], "BLOCK")

    def test_api_scan_camera_payload(self):
        payload = {"payload": "https://www.ox.ac.uk"}
        resp = self.client.post("/api/scan/camera", data=json.dumps(payload), content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["result"]["source_type"], "camera")

    def test_api_dashboard_metrics(self):
        resp = self.client.get("/api/dashboard")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("total_scans", data["metrics"])

    def test_api_siem_events_json(self):
        resp = self.client.get("/api/siem/events")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("events", data)

    def test_api_playbook_block(self):
        payload = {
            "action": "BLOCK_DOMAIN",
            "domain": "test-block-target.xyz",
            "reason": "Automated unit test block"
        }
        resp = self.client.post("/api/playbook/action", data=json.dumps(payload), content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["target"], "test-block-target.xyz")

    def test_upload_image_and_render_result(self):
        import io
        from pathlib import Path
        img_path = Path("test_samples/01_safe_university.png")
        if img_path.exists():
            with open(img_path, "rb") as f:
                img_data = f.read()
            data = {"file": (io.BytesIO(img_data), "sample.png")}
            resp = self.client.post("/api/scan/image", data=data, content_type="multipart/form-data")
            self.assertEqual(resp.status_code, 200)
            res_json = resp.get_json()
            self.assertTrue(res_json["success"])
            scan_id = res_json["scan_id"]
            
            # Now verify GET /scan/<scan_id> renders without Jinja2 UndefinedError
            view_resp = self.client.get(f"/scan/{scan_id}")
            self.assertEqual(view_resp.status_code, 200)
            self.assertIn(b"QuishGuard", view_resp.data)

    def test_upload_pdf_and_render_result(self):
        import io
        from pathlib import Path
        pdf_path = Path("test_samples/07_embedded_invoice_qr.pdf")
        if pdf_path.exists():
            with open(pdf_path, "rb") as f:
                pdf_data = f.read()
            data = {"file": (io.BytesIO(pdf_data), "invoice.pdf")}
            resp = self.client.post("/api/scan/pdf", data=data, content_type="multipart/form-data")
            self.assertEqual(resp.status_code, 200)
            res_json = resp.get_json()
            self.assertTrue(res_json["success"])
            scan_id = res_json["scan_id"]

            # Verify GET /scan/<scan_id> renders without errors
            view_resp = self.client.get(f"/scan/{scan_id}")
            self.assertEqual(view_resp.status_code, 200)

if __name__ == "__main__":
    unittest.main()
