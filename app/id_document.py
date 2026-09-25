import base64
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import cv2
import numpy as np

MAX_IMAGE_BYTES = 12 * 1024 * 1024
ALLOWED_QR_HOSTS = {"licencias.intrantmoto.com"}


def _decode_b64(value: str) -> bytes:
    if "," in value and value.lstrip().startswith("data:"):
        value = value.split(",", 1)[1]
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("invalid base64 image") from exc
    if not raw:
        raise ValueError("empty image")
    if len(raw) > MAX_IMAGE_BYTES:
        raise ValueError("image exceeds maximum size")
    return raw


def _image(raw: bytes) -> np.ndarray:
    arr = np.frombuffer(raw, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("image is not decodable")
    h, w = img.shape[:2]
    if h < 240 or w < 320:
        raise ValueError("image resolution is too small for document scanning")
    if h * w > 24_000_000:
        raise ValueError("image dimensions are too large")
    return img


def _qr_candidates(img: np.ndarray):
    yield img
    h, w = img.shape[:2]
    # Dominican licence QR is commonly on the upper-left of the reverse side.
    yield img[: max(1, int(h * 0.58)), : max(1, int(w * 0.56))]
    for scale in (1.5, 2.0, 3.0):
        yield cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)


def decode_qr(img: np.ndarray) -> str | None:
    detector = cv2.QRCodeDetector()
    for candidate in _qr_candidates(img):
        try:
            data, points, _ = detector.detectAndDecode(candidate)
        except cv2.error:
            continue
        if data:
            return data.strip()
    return None


def _ocr_image(img: np.ndarray) -> str:
    # Contrast-normalized grayscale improves text extraction from laminated cards.
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    gray = cv2.bilateralFilter(gray, 7, 35, 35)
    with tempfile.TemporaryDirectory(prefix="faceid-idscan-") as tmp:
        path = Path(tmp) / "document.png"
        if not cv2.imwrite(str(path), gray):
            raise ValueError("could not prepare document image")
        cmd = ["tesseract", str(path), "stdout", "-l", "spa+eng", "--psm", "6"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError("OCR runtime unavailable") from exc
        if result.returncode != 0:
            # Fall back to the default language pack if Spanish is unavailable.
            fallback = ["tesseract", str(path), "stdout", "--psm", "6"]
            result = subprocess.run(fallback, capture_output=True, text=True, timeout=20, check=False)
        if result.returncode != 0:
            raise RuntimeError("OCR failed")
        return result.stdout.strip()


def _clean(text: str) -> str:
    text = text.replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


def _date_after(label: str, text: str) -> str | None:
    m = re.search(label + r"[^0-9]{0,30}(\d{1,2}[/-]\d{1,2}[/-]\d{4})", text, re.I)
    return m.group(1) if m else None


def _value_after(label: str, text: str, pattern: str) -> str | None:
    m = re.search(label + r"[^A-Za-z0-9+\-]{0,18}(" + pattern + r")", text, re.I)
    return m.group(1).strip() if m else None


def _full_name(front: str) -> str | None:
    lines=[re.sub(r"[^A-ZÁÉÍÓÚÑ ]", "", x.upper()).strip() for x in front.splitlines()]
    lines=[x for x in lines if x]
    stop={"REPUBLICA DOMINICANA","REPÚBLICA DOMINICANA","LICENCIA DE CONDUCIR","INSTITUTO NACIONAL DE TRANSITO Y TRANSPORTE TERRESTRE"}
    candidates=[]
    for line in lines:
        if line in stop or "DIRECCI" in line or "LICENCIA" in line or "REPUBLIC" in line:
            continue
        words=line.split()
        if 1 <= len(words) <= 5 and all(len(w) >= 2 for w in words):
            if not any(k in line for k in ("ESTATURA","PESO","SEXO","SANGRE","NACIMIENTO","EMISION","VENCE")):
                candidates.append(line)
    # Usually the name occupies the first one or two strong uppercase lines after the title.
    for i,line in enumerate(candidates):
        if len(line.split()) >= 2:
            if i+1 < len(candidates) and len(candidates[i+1].split()) <= 3:
                combo=(line+" "+candidates[i+1]).strip()
                if 3 <= len(combo.split()) <= 5:
                    return combo.title()
            return line.title()
    return None


def parse_dr_driver_license(front_text: str, back_text: str) -> dict:
    front=_clean(front_text)
    back=_clean(back_text)
    all_text=front+"\n"+back
    number=None
    # Dominican licence / identification number is typically 11 digits.
    ids=re.findall(r"(?<!\d)(\d{11})(?!\d)", all_text)
    if ids:
        number=ids[0]

    address=None
    m=re.search(r"Direcci[oó]n\s*\n?(.+?)(?=\n(?:Estatura|Peso|Sexo|Tipo|Nacimiento|Emisi[oó]n|Vence)|$)", front, re.I|re.S)
    if m:
        address=" ".join(x.strip() for x in m.group(1).splitlines() if x.strip())
        address=re.sub(r"\s+"," ",address)[:300]

    category=None
    m=re.search(r"Categor[ií]a\s*\n?\s*([0-9]{1,3}\s+[A-ZÁÉÍÓÚÑ ]{3,40})", back, re.I)
    if m:
        category=re.sub(r"\s+"," ",m.group(1)).strip()

    restriction=None
    m=re.search(r"Restricciones?\s*\n?\s*([A-ZÁÉÍÓÚÑ ]{4,60})", back, re.I)
    if m:
        restriction=re.sub(r"\s+"," ",m.group(1)).strip()

    card_serial=None
    seven=re.findall(r"(?<!\d)(\d{7})(?!\d)", back)
    if seven:
        card_serial=seven[-1]

    fields={
        "country":"DO",
        "document_type":"driver_license",
        "full_name":_full_name(front),
        "document_number":number,
        "address":address,
        "height":_value_after(r"Estatura",front,r"[0-9]{1,2}[-'][0-9]{1,2}"),
        "weight_lb":_value_after(r"Peso",front,r"[0-9]{2,3}"),
        "sex":_value_after(r"Sexo",front,r"[MF]"),
        "blood_type":_value_after(r"Tipo\s+de\s+Sangre",front,r"(?:A|B|AB|O)[+-]"),
        "birth_date":_date_after(r"Nacimiento",front),
        "issue_date":_date_after(r"Emisi[oó]n",front),
        "expiry_date":_date_after(r"Vence",front),
        "category":category,
        "restriction":restriction,
        "first_issue_date":_date_after(r"Primera\s+Emisi[oó]n",back),
        "card_serial":card_serial,
    }
    return {k:v for k,v in fields.items() if v not in (None,"")}


def scan_license(front_b64: str, back_b64: str | None = None) -> dict:
    front_raw=_decode_b64(front_b64)
    front_img=_image(front_raw)
    back_raw=_decode_b64(back_b64) if back_b64 else b""
    back_img=_image(back_raw) if back_raw else None

    front_text=_ocr_image(front_img)
    back_text=_ocr_image(back_img) if back_img is not None else ""
    qr=decode_qr(back_img) if back_img is not None else None

    fields=parse_dr_driver_license(front_text,back_text)
    warnings=[]
    if not fields.get("document_number"):
        warnings.append("document_number_not_confident")
    if not fields.get("full_name"):
        warnings.append("full_name_not_confident")

    authority_url=None
    qr_hash=None
    if qr:
        qr_hash=hashlib.sha256(qr.encode()).hexdigest()
        parsed=urlparse(qr)
        if parsed.scheme=="https" and parsed.hostname in ALLOWED_QR_HOSTS:
            authority_url=qr
        else:
            warnings.append("qr_host_not_allowlisted")

    doc_number=fields.get("document_number")
    doc_hash=(hashlib.sha256(("DO|driver_license|"+doc_number).encode()).hexdigest() if doc_number else None)
    return {
        "fields":fields,
        "document_hash":doc_hash,
        "document_last4":doc_number[-4:] if doc_number else None,
        "authority_lookup_url":authority_url,
        "authority_lookup_hash":qr_hash,
        "warnings":warnings,
        "ocr_front":front_text,
        "ocr_back":back_text,
    }
