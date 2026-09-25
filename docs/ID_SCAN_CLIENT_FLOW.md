# ID Scan -> Client -> Face Enrollment

FACE-ID can now intake a Dominican driver licence from front/back images, extract structured fields, create a reviewed client record, and then link that client to a separate consented biometric face enrollment.

## Flow

1. Operator opens **ID Scan & Clients** in the local FACE-ID dashboard.
2. Operator uploads front/back licence images.
3. FACE-ID runs local OCR and QR extraction.
4. Extracted fields are returned for human review.
5. Operator confirms/corrects the fields.
6. FACE-ID creates a client record using a SHA-256 document reference and last four digits.
7. Operator captures or uploads a separate face image after explicit biometric consent.
8. FACE-ID creates the face embedding and links the subject to the client.

Raw ID-card images are not persisted by the ID-scan workflow.

## Extracted licence fields

The scanner attempts to extract:

- full name
- 11-digit document/licence number
- address
- height
- weight
- sex
- blood type
- birth date
- issue date
- expiry date
- licence category
- restrictions
- first issue date
- card serial
- QR authority lookup URL when it is HTTPS and on the allowlisted issuing-authority host

OCR values are advisory until an operator confirms them.

## API

- `POST /v1/id-documents/scan`
- `GET /v1/id-documents/{scan_id}`
- `POST /v1/id-documents/{scan_id}/confirm`
- `POST /v1/clients/from-id-scan`
- `GET /v1/clients`
- `GET /v1/clients/{client_id}`
- `POST /v1/clients/{client_id}/face-enrollment`

## Security and privacy

- admin/local boundary remains in force
- no raw document image persistence
- full document number is stored only inside confirmed client attributes and represented by a SHA-256 document reference plus last four digits in index fields
- QR lookup is returned transiently and only for an allowlisted HTTPS host; only its digest is persisted
- OCR/QR does not prove that a document is genuine
- face enrollment requires explicit biometric consent
- the ID portrait is not automatically enrolled as a biometric template
- Middleware V3 remains the cross-system integration authority

Government/source verification is a separate integration and must not be inferred from OCR or QR extraction alone.
