# Codestra FACE-ID

Codestra FACE-ID is the service boundary for camera ingestion, biometric enrollment, detection, verification, search, events, and integrations.

## Target architecture

Camera (RTSP/ONVIF) -> Codestra FACE-ID -> Recognition Engine -> PostgreSQL/Event API -> Codestra integrations.

## Planned API

- GET /healthz
- GET /readyz
- GET /metrics
- GET /v1/capabilities
- POST /v1/faces/enroll
- DELETE /v1/faces/{subject_id}
- POST /v1/faces/detect
- POST /v1/faces/verify
- POST /v1/faces/search
- POST /v1/cameras
- GET /v1/cameras
- DELETE /v1/cameras/{camera_id}
- POST /v1/streams/{camera_id}/test
- GET /v1/events

## Engineering rules

Local-first biometric processing, explicit enrollment/consent metadata, auditability, configurable retention/deletion, no raw biometric images in logs by default, versioned OpenAPI, reproducible deployments, and rollback evidence.

Third-party licenses, copyright notices, NOTICE files, model licenses, and required attribution must be preserved.
