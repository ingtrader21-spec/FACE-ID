import base64

from app import main
from app.id_document import parse_dr_driver_license


def test_parser_extracts_expected_fields():
    front = """REPUBLICA DOMINICANA
LICENCIA DE CONDUCIR
QA CLIENTE
EJEMPLO DOS
Dirección
CALLE DEMO 10
Estatura 5-10 Peso 170 Sexo M
Tipo de Sangre O+
Nacimiento 01/01/2000
Emisión 02/02/2023
Vence 01/01/2030
99999999999"""
    back = """Categoría
02 CONDUCTOR
Restricciones
TRANSMISION AUTOMATICA
Primera Emisión
2/2/2023
7654321"""
    out = parse_dr_driver_license(front, back)
    assert out["document_number"] == "99999999999"
    assert out["birth_date"] == "01/01/2000"
    assert out["expiry_date"] == "01/01/2030"
    assert out["category"].startswith("02")
    assert out["restriction"].startswith("TRANSMISION")


def test_scan_requires_operator_confirmation_and_does_not_persist_full_number(client, monkeypatch):
    monkeypatch.setattr(
        main,
        "scan_license",
        lambda front, back=None: {
            "fields": {
                "country": "DO",
                "document_type": "driver_license",
                "full_name": "QA Client",
                "document_number": "99999999999",
                "address": "QA Address",
            },
            "document_hash": "a" * 64,
            "document_last4": "9999",
            "authority_lookup_url": None,
            "authority_lookup_hash": None,
            "warnings": [],
            "ocr_front": "QA",
            "ocr_back": "",
        },
    )
    response = client.post(
        "/v1/id-documents/scan",
        json={"front_image_base64": base64.b64encode(b"placeholder").decode()},
    )
    assert response.status_code == 200
    scan = response.json()
    scan_id = scan["scan_id"]
    stored = main.conn().execute(
        "select fields,document_last4,status from id_scan_sessions where scan_id=%s",
        (scan_id,),
    ).fetchone()
    assert "document_number" not in stored[0]
    assert stored[1] == "9999"
    assert stored[2] == "scanned"

    create = client.post(
        "/v1/clients/from-id-scan",
        json={"scan_id": scan_id, "operator_ref": "qa"},
    )
    assert create.status_code == 409

    fields = dict(scan["fields"])
    fields["document_number"] = "99999999999"
    confirm = client.post(
        f"/v1/id-documents/{scan_id}/confirm",
        json={
            "fields": fields,
            "operator_confirmed": True,
            "operator_ref": "qa",
            "note": "reviewed",
        },
    )
    assert confirm.status_code == 200
    stored = main.conn().execute(
        "select fields,document_hash,document_last4,status from id_scan_sessions where scan_id=%s",
        (scan_id,),
    ).fetchone()
    assert "document_number" not in stored[0]
    assert len(stored[1]) == 64
    assert stored[2] == "9999"
    assert stored[3] == "confirmed"

    create = client.post(
        "/v1/clients/from-id-scan",
        json={"scan_id": scan_id, "operator_ref": "qa"},
    )
    assert create.status_code == 200
    client_id = create.json()["client_id"]
    got = client.get(f"/v1/clients/{client_id}")
    assert got.status_code == 200
    payload = got.json()
    assert payload["display_name"] == "QA Client"
    assert payload["document_last4"] == "9999"
    assert "document_number" not in payload["attributes"]
    assert payload["face_enrolled"] is False


def test_face_enrollment_requires_explicit_consent(client):
    response = client.post(
        "/v1/clients/not-found/face-enrollment",
        json={
            "image_base64": "x",
            "consent_obtained": False,
            "consent_reference": "qa",
        },
    )
    assert response.status_code == 400


def test_id_scan_and_clients_are_local_admin_only(lan):
    assert lan.get("/v1/clients").status_code == 403
    assert lan.get("/v1/id-documents/not-found").status_code == 403
