# Codestra FACE-ID
Local-first face recognition and camera-ingestion service.

Architecture: EZVIZ / RTSP camera -> FACE-ID API -> Recognition Engine -> PostgreSQL -> events/integrations.

Local endpoints: FACE-ID on 127.0.0.1:8094 and recognition engine on 127.0.0.1:8091.
Camera passwords are never committed. Store the EZVIZ verification/device password in EZVIZ_CAMERA_PASSWORD in .env.
Enrollment requires explicit consent metadata. Raw biometric images are not stored or logged by default.
