from __future__ import annotations
from datetime import datetime, timezone
from uuid import uuid4
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, Field, HttpUrl
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

app = FastAPI(title="Codestra FACE-ID", version="0.1.0")

class EnrollRequest(BaseModel):
    subject_id: str = Field(min_length=1, max_length=128)
    image_b64: str = Field(min_length=16)
    consent_reference: str = Field(min_length=1, max_length=256)

class CameraCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    stream_url: str = Field(min_length=4)
    protocol: str = Field(pattern="^(rtsp|onvif)$")

class VerifyRequest(BaseModel):
    subject_id: str
    image_b64: str

subjects: dict[str, dict] = {}
cameras: dict[str, dict] = {}
events: list[dict] = []

@app.get("/healthz")
def healthz(): return {"status": "ok"}

@app.get("/readyz")
def readyz(): return {"status": "ready"}

@app.get("/metrics")
def metrics(): return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/v1/capabilities")
def capabilities():
    return {"camera_protocols":["rtsp","onvif"],"operations":["enroll","delete","detect","verify","search"],"engine":"adapter"}

@app.post("/v1/faces/enroll", status_code=201)
def enroll(body: EnrollRequest):
    subjects[body.subject_id]={"consent_reference":body.consent_reference,"enrolled_at":datetime.now(timezone.utc).isoformat()}
    events.append({"event_id":str(uuid4()),"type":"face.enrolled","subject_id":body.subject_id})
    return {"subject_id":body.subject_id,"status":"enrolled"}

@app.delete("/v1/faces/{subject_id}", status_code=204)
def delete_face(subject_id: str):
    if subjects.pop(subject_id, None) is None: raise HTTPException(404,"subject_not_found")
    return Response(status_code=204)

@app.post("/v1/faces/verify")
def verify(body: VerifyRequest):
    if body.subject_id not in subjects: raise HTTPException(404,"subject_not_found")
    return {"subject_id":body.subject_id,"matched":False,"score":None,"engine_status":"not_configured"}

@app.post("/v1/faces/detect")
def detect(payload: dict): return {"faces":[],"engine_status":"not_configured"}

@app.post("/v1/faces/search")
def search(payload: dict): return {"matches":[],"engine_status":"not_configured"}

@app.post("/v1/cameras", status_code=201)
def create_camera(body: CameraCreate):
    camera_id=str(uuid4()); cameras[camera_id]={"camera_id":camera_id,**body.model_dump()}
    return cameras[camera_id]

@app.get("/v1/cameras")
def list_cameras(): return {"items":list(cameras.values())}

@app.delete("/v1/cameras/{camera_id}", status_code=204)
def delete_camera(camera_id: str):
    if cameras.pop(camera_id,None) is None: raise HTTPException(404,"camera_not_found")
    return Response(status_code=204)

@app.post("/v1/streams/{camera_id}/test")
def test_stream(camera_id: str):
    if camera_id not in cameras: raise HTTPException(404,"camera_not_found")
    return {"camera_id":camera_id,"configured":True,"network_probe":"not_executed"}

@app.get("/v1/events")
def get_events(): return {"items":events[-100:]}
