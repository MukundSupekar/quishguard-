import io
from pathlib import Path
from typing import List, Dict, Any, Union
from pypdf import PdfReader
from PIL import Image
from quishguard.qr_engine import qr_engine, QRDetectionResult

class PDFQRExtractor:
    """
    Extracts embedded QR codes from PDF documents.
    Extracts raster image objects from each page and scans them.
    """
    def __init__(self):
        self.engine = qr_engine

    def scan_pdf(self, pdf_input: Union[str, Path, bytes]) -> Dict[str, Any]:
        """
        Scans a PDF file or bytes for embedded QR codes across all pages.
        """
        if isinstance(pdf_input, (str, Path)):
            reader = PdfReader(str(pdf_input))
        else:
            reader = PdfReader(io.BytesIO(pdf_input))

        total_pages = len(reader.pages)
        detected_qrs: List[Dict[str, Any]] = []

        for page_idx, page in enumerate(reader.pages):
            page_num = page_idx + 1
            image_count = 0
            
            try:
                # Extract image objects
                for img_obj in page.images:
                    image_count += 1
                    try:
                        img_bytes = img_obj.data
                        img_pil = Image.open(io.BytesIO(img_bytes))
                        
                        # Run QR engine
                        res: QRDetectionResult = self.engine.decode_image(img_pil)
                        if res.detected:
                            detected_qrs.append({
                                "page": page_num,
                                "image_name": img_obj.name,
                                "image_index": image_count,
                                "payload": res.payload,
                                "all_payloads": res.all_payloads,
                                "engine": res.engine,
                                "strategy": res.strategy,
                                "confidence": res.confidence
                            })
                    except Exception:
                        continue
            except Exception:
                continue

        primary_payload = detected_qrs[0]["payload"] if detected_qrs else ""
        return {
            "success": True,
            "total_pages": total_pages,
            "qr_detected": len(detected_qrs) > 0,
            "total_qrs_found": len(detected_qrs),
            "primary_payload": primary_payload,
            "qr_findings": detected_qrs
        }

pdf_extractor = PDFQRExtractor()
