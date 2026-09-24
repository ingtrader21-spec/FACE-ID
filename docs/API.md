# Codestra FACE-ID API Contract

Base path: /v1

## Platform
GET /healthz
GET /readyz
GET /metrics
GET /v1/capabilities

## Faces
POST /v1/faces/enroll
DELETE /v1/faces/{subject_id}
POST /v1/faces/detect
POST /v1/faces/verify
POST /v1/faces/search

## Cameras
POST /v1/cameras
GET /v1/cameras
DELETE /v1/cameras/{camera_id}
POST /v1/streams/{camera_id}/test

## Events
GET /v1/events

All authenticated mutations should carry correlation IDs. Sensitive biometric payloads must not be written to ordinary application logs.
