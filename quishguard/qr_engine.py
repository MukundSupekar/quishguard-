import cv2
import numpy as np
from PIL import Image
from typing import List, Dict, Any, Optional, Union
from pathlib import Path

# Optional zxingcpp import
try:
    import zxingcpp
    HAS_ZXING = True
except ImportError:
    HAS_ZXING = False

class QRDetectionResult:
    def __init__(
        self,
        detected: bool,
        payload: str = "",
        all_payloads: Optional[List[str]] = None,
        engine: str = "None",
        strategy: str = "None",
        format_name: str = "QR_CODE",
        bbox: Optional[List[List[float]]] = None,
        confidence: float = 0.0
    ):
        self.detected = detected
        self.payload = payload.strip()
        self.all_payloads = [p.strip() for p in (all_payloads or []) if p.strip()]
        if self.payload and self.payload not in self.all_payloads:
            self.all_payloads.insert(0, self.payload)
        self.engine = engine
        self.strategy = strategy
        self.format_name = format_name
        self.bbox = bbox
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "payload": self.payload,
            "all_payloads": self.all_payloads,
            "engine": self.engine,
            "strategy": self.strategy,
            "format": self.format_name,
            "bbox": self.bbox,
            "confidence": self.confidence
        }

class MultiStrategyQREngine:
    """
    Robust QR Code detection engine combining ZXing-CPP and OpenCV
    with an adaptive multi-stage image preprocessing pipeline.
    """
    def __init__(self):
        self.cv_detector = cv2.QRCodeDetector()
        # OpenCV multi detector if available
        self.cv_multi_detector = cv2.QRCodeDetector()

    def _generate_preprocessed_variants(self, img_bgr: np.ndarray):
        """Yield (strategy_name, image_to_test) pairs."""
        # 1. Original BGR
        yield "Original", img_bgr
        
        # 2. Grayscale
        gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY) if len(img_bgr.shape) == 3 else img_bgr
        yield "Grayscale", gray
        
        # 3. Inverted (detects inverted / dark-mode / fancy QR codes)
        inverted = cv2.bitwise_not(gray)
        yield "Inverted", inverted
        
        # 4. Contrast Limited Adaptive Histogram Equalization (CLAHE)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        clahe_img = clahe.apply(gray)
        yield "CLAHE-Contrast", clahe_img
        
        # 5. Otsu Thresholding
        _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        yield "Otsu-Threshold", otsu
        
        # 6. Inverted Otsu
        yield "Inverted-Otsu", cv2.bitwise_not(otsu)
        
        # 7. Adaptive Gaussian Thresholding
        adaptive = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 21, 5
        )
        yield "Adaptive-Threshold", adaptive
        
        # 8. Sharpening filter (for blurry scans)
        sharpen_kernel = np.array([[-1, -1, -1], [-1, 9, -1], [-1, -1, -1]])
        sharpened = cv2.filter2D(gray, -1, sharpen_kernel)
        yield "Sharpened", sharpened
        
        # 9. Scaled up 2x (for small or low-res embedded QRs)
        h, w = gray.shape[:2]
        if max(h, w) < 600:
            upscaled = cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
            yield "Upscaled-2x", upscaled

    def _decode_zxing(self, img: np.ndarray, strategy: str) -> Optional[QRDetectionResult]:
        if not HAS_ZXING:
            return None
        try:
            results = zxingcpp.read_barcodes(img)
            if results:
                payloads = [r.text for r in results if r.text]
                if payloads:
                    primary = payloads[0]
                    # Get position if available
                    bbox = None
                    try:
                        pos = results[0].position
                        bbox = [[float(pos.top_left.x), float(pos.top_left.y)],
                                [float(pos.top_right.x), float(pos.top_right.y)],
                                [float(pos.bottom_right.x), float(pos.bottom_right.y)],
                                [float(pos.bottom_left.x), float(pos.bottom_left.y)]]
                    except Exception:
                        pass
                    return QRDetectionResult(
                        detected=True,
                        payload=primary,
                        all_payloads=payloads,
                        engine="ZXing-CPP",
                        strategy=strategy,
                        format_name=str(results[0].format).replace("BarcodeFormat.", ""),
                        bbox=bbox,
                        confidence=0.95
                    )
        except Exception:
            pass
        return None

    def _decode_opencv(self, img: np.ndarray, strategy: str) -> Optional[QRDetectionResult]:
        try:
            # Try multi first
            retval, decoded_info, points, _ = self.cv_detector.detectAndDecodeMulti(img)
            if retval and decoded_info:
                valid_payloads = [info for info in decoded_info if info.strip()]
                if valid_payloads:
                    pts_list = points[0].tolist() if points is not None and len(points) > 0 else None
                    return QRDetectionResult(
                        detected=True,
                        payload=valid_payloads[0],
                        all_payloads=valid_payloads,
                        engine="OpenCV",
                        strategy=strategy,
                        format_name="QR_CODE",
                        bbox=pts_list,
                        confidence=0.88
                    )
            
            # Try single detector
            data, bbox, _ = self.cv_detector.detectAndDecode(img)
            if data and data.strip():
                pts_list = bbox[0].tolist() if bbox is not None and len(bbox) > 0 else None
                return QRDetectionResult(
                    detected=True,
                    payload=data.strip(),
                    all_payloads=[data.strip()],
                    engine="OpenCV",
                    strategy=strategy,
                    format_name="QR_CODE",
                    bbox=pts_list,
                    confidence=0.85
                )
        except Exception:
            pass
        return None

    def decode_image(self, image_input: Union[str, Path, bytes, np.ndarray, Image.Image]) -> QRDetectionResult:
        """
        Decodes a QR code from a file path, bytes, NumPy array, or PIL Image.
        Iterates through multiple preprocessing filters and decoders.
        """
        # Load image into numpy BGR array
        img_bgr = None
        if isinstance(image_input, (str, Path)):
            img_bgr = cv2.imread(str(image_input))
        elif isinstance(image_input, bytes):
            nparr = np.frombuffer(image_input, np.uint8)
            img_bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        elif isinstance(image_input, Image.Image):
            rgb = np.array(image_input.convert("RGB"))
            img_bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
        elif isinstance(image_input, np.ndarray):
            if len(image_input.shape) == 2:
                img_bgr = cv2.cvtColor(image_input, cv2.COLOR_GRAY2BGR)
            elif image_input.shape[2] == 4:
                img_bgr = cv2.cvtColor(image_input, cv2.COLOR_BGRA2BGR)
            else:
                img_bgr = image_input

        if img_bgr is None or img_bgr.size == 0:
            return QRDetectionResult(detected=False, engine="None", strategy="Invalid Image")

        # Multi-stage evaluation
        # Round 1: Fast ZXing check across variants
        for strategy, variant in self._generate_preprocessed_variants(img_bgr):
            res = self._decode_zxing(variant, strategy)
            if res and res.detected:
                return res

        # Round 2: OpenCV fallback across variants
        for strategy, variant in self._generate_preprocessed_variants(img_bgr):
            res = self._decode_opencv(variant, strategy)
            if res and res.detected:
                return res

        return QRDetectionResult(detected=False, engine="None", strategy="Exhausted all strategies")

# Global singleton
qr_engine = MultiStrategyQREngine()
