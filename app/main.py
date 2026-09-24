import base64, json, os, time, threading, uuid
from typing import Optional
import cv2, httpx, psycopg
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

app=FastAPI(title="Codestra FACE-ID",version="1.0.0")
DB=os.environ["DATABASE_URL"]
ENGINE=os.getenv("RECOGNITION_ENGINE_URL","http://recognition-engine:8080")

class Enroll(BaseModel):
    subject_id: str
    display_name: str
    image_base64: str
    consent_obtained: bool
    consent_reference: Optional[str]=None
    retention_days: int=Field(default=365,ge=1,le=3650)
class SearchReq(BaseModel):
    image_base64: str
    threshold: float=0.363
    top_k: int=5
class CameraIn(BaseModel):
    camera_id: str
    name: str
    host: str
    rtsp_path: str="/Streaming/Channels/101"
    username: str="admin"
    password_env: str
    enabled: bool=True

def conn(): return psycopg.connect(DB)
def init_db():
    with conn() as c:
        c.execute("""create table if not exists subjects(subject_id text primary key, display_name text not null, embedding jsonb not null, consent_obtained boolean not null, consent_reference text, retention_days int not null, created_at timestamptz not null default now(), updated_at timestamptz not null default now())""")
        c.execute("""create table if not exists cameras(camera_id text primary key, name text not null, host text not null, rtsp_path text not null, username text not null, password_env text not null, enabled boolean not null default true, created_at timestamptz not null default now())""")
        c.execute("""create table if not exists events(event_id text primary key, camera_id text, subject_id text, score double precision, event_type text not null, occurred_at timestamptz not null default now(), metadata jsonb not null default '{}'::jsonb)""")

WORKER_INTERVAL=float(os.getenv("FACEID_WORKER_INTERVAL_SECONDS","2"))
EVENT_COOLDOWN=float(os.getenv("FACEID_EVENT_COOLDOWN_SECONDS","15"))
_last_events={}

def _gallery():
    with conn() as c:
        rows=c.execute("select subject_id,display_name,embedding from subjects").fetchall()
    return rows

def _record_event(camera_id, subject_id, score, event_type, metadata=None):
    key=(camera_id,subject_id or event_type)
    now=time.time()
    if now-_last_events.get(key,0)<EVENT_COOLDOWN:
        return
    _last_events[key]=now
    with conn() as c:
        c.execute("insert into events(event_id,camera_id,subject_id,score,event_type,metadata) values(%s,%s,%s,%s,%s,%s::jsonb)",
                  (str(uuid.uuid4()),camera_id,subject_id,score,event_type,json.dumps(metadata or {})))

def _process_camera(row):
    camera_id,name,host,path,user,pwenv,enabled=row
    if not enabled: return
    pw=os.getenv(pwenv)
    if not pw: return
    url=f"rtsp://{user}:{pw}@{host}:554{path}"
    cap=cv2.VideoCapture(url,cv2.CAP_FFMPEG)
    ok,frame=cap.read(); cap.release()
    if not ok or frame is None: return
    ok,jpg=cv2.imencode(".jpg",frame,[int(cv2.IMWRITE_JPEG_QUALITY),80])
    if not ok: return
    b64=base64.b64encode(jpg).decode()
    er=httpx.post(ENGINE+"/v1/embeddings",json={"image_base64":b64},timeout=20)
    if er.status_code==422: return
    if not er.is_success: return
    embedding=er.json()["embedding"]
    rows=_gallery()
    if not rows:
        _record_event(camera_id,None,None,"unknown_face",{"camera_name":name})
        return
    gallery=[{"subject_id":r[0],"embedding":r[2]} for r in rows]
    rr=httpx.post(ENGINE+"/v1/search",json={"embedding":embedding,"gallery":gallery,"threshold":0.363,"top_k":1},timeout=20)
    if not rr.is_success: return
    hits=rr.json().get("hits",[])
    top=hits[0] if hits else None
    if top and top.get("match"):
        _record_event(camera_id,top["subject_id"],top["score"],"recognized_face",{"camera_name":name})
    else:
        _record_event(camera_id,None,top.get("score") if top else None,"unknown_face",{"camera_name":name})

def _worker():
    time.sleep(3)
    while True:
        try:
            with conn() as c:
                cameras=c.execute("select camera_id,name,host,rtsp_path,username,password_env,enabled from cameras where enabled=true").fetchall()
            for row in cameras:
                try: _process_camera(row)
                except Exception: pass
        except Exception: pass
        time.sleep(WORKER_INTERVAL)

@app.on_event("startup")
def startup():
    last=None
    for _ in range(30):
        try:
            init_db()
            threading.Thread(target=_worker,daemon=True).start()
            return
        except Exception as e:
            last=e; time.sleep(1)
    raise last
@app.get("/healthz")
def healthz(): return {"ok":True}
@app.get("/readyz")
def readyz():
    try:
        with conn() as c: c.execute("select 1")
        r=httpx.get(ENGINE+"/readyz",timeout=3)
        if not r.is_success: raise RuntimeError("recognition engine not ready")
        return {"ok":True,"database":True,"recognition_engine":True}
    except Exception as e: raise HTTPException(503,str(e))
@app.get("/metrics",response_class=PlainTextResponse)
def metrics(): return PlainTextResponse(generate_latest().decode(),media_type=CONTENT_TYPE_LATEST)
@app.get("/v1/capabilities")
def capabilities(): return {"camera_ingest":["rtsp"],"recognition":["enroll","verify","search"],"storage":"postgresql","local_first":True}
@app.post("/v1/faces/enroll")
def enroll(req:Enroll):
    if not req.consent_obtained: raise HTTPException(400,"explicit enrollment consent is required")
    er=httpx.post(ENGINE+"/v1/embeddings",json={"image_base64":req.image_base64},timeout=20)
    if not er.is_success: raise HTTPException(er.status_code,er.text)
    emb=er.json()["embedding"]
    with conn() as c:
        c.execute("""insert into subjects(subject_id,display_name,embedding,consent_obtained,consent_reference,retention_days) values(%s,%s,%s::jsonb,%s,%s,%s) on conflict(subject_id) do update set display_name=excluded.display_name,embedding=excluded.embedding,consent_obtained=excluded.consent_obtained,consent_reference=excluded.consent_reference,retention_days=excluded.retention_days,updated_at=now()""",(req.subject_id,req.display_name,json.dumps(emb),req.consent_obtained,req.consent_reference,req.retention_days))
    return {"subject_id":req.subject_id,"display_name":req.display_name,"enrolled":True}
@app.delete("/v1/faces/{subject_id}")
def delete_face(subject_id:str):
    with conn() as c: c.execute("delete from subjects where subject_id=%s",(subject_id,))
    return {"deleted":True,"subject_id":subject_id}
@app.post("/v1/faces/detect")
def detect(req:SearchReq):
    er=httpx.post(ENGINE+"/v1/embeddings",json={"image_base64":req.image_base64},timeout=20)
    if not er.is_success: raise HTTPException(er.status_code,er.text)
    return {"face_detected":True,"bbox":er.json().get("bbox")}
@app.post("/v1/faces/search")
def search(req:SearchReq):
    with conn() as c: rows=c.execute("select subject_id,display_name,embedding from subjects").fetchall()
    gallery=[{"subject_id":r[0],"embedding":r[2]} for r in rows]
    rr=httpx.post(ENGINE+"/v1/search",json={"image_base64":req.image_base64,"gallery":gallery,"threshold":req.threshold,"top_k":req.top_k},timeout=20)
    if not rr.is_success: raise HTTPException(rr.status_code,rr.text)
    names={r[0]:r[1] for r in rows}; out=rr.json()
    for h in out["hits"]: h["display_name"]=names.get(h["subject_id"])
    return out
@app.post("/v1/faces/verify")
def verify(req:SearchReq):
    out=search(req); top=out["hits"][0] if out["hits"] else None
    return {"recognized":bool(top and top["match"]),"best":top}
@app.get("/v1/subjects")
def subjects():
    with conn() as c:
        rows=c.execute("select subject_id,display_name,consent_obtained,consent_reference,retention_days,created_at,updated_at from subjects order by display_name").fetchall()
    return [{"subject_id":r[0],"display_name":r[1],"consent_obtained":r[2],"consent_reference":r[3],"retention_days":r[4],"created_at":r[5],"updated_at":r[6]} for r in rows]

@app.post("/v1/cameras")
def camera_add(req:CameraIn):
    with conn() as c:
        c.execute("""insert into cameras(camera_id,name,host,rtsp_path,username,password_env,enabled) values(%s,%s,%s,%s,%s,%s,%s) on conflict(camera_id) do update set name=excluded.name,host=excluded.host,rtsp_path=excluded.rtsp_path,username=excluded.username,password_env=excluded.password_env,enabled=excluded.enabled""",(req.camera_id,req.name,req.host,req.rtsp_path,req.username,req.password_env,req.enabled))
    return {"camera_id":req.camera_id,"saved":True}
@app.get("/v1/cameras")
def camera_list():
    with conn() as c: rows=c.execute("select camera_id,name,host,rtsp_path,username,password_env,enabled from cameras order by camera_id").fetchall()
    return [{"camera_id":r[0],"name":r[1],"host":r[2],"rtsp_path":r[3],"username":r[4],"password_env":r[5],"enabled":r[6]} for r in rows]
@app.delete("/v1/cameras/{camera_id}")
def camera_delete(camera_id:str):
    with conn() as c: c.execute("delete from cameras where camera_id=%s",(camera_id,))
    return {"deleted":True,"camera_id":camera_id}
@app.post("/v1/streams/{camera_id}/test")
def stream_test(camera_id:str):
    with conn() as c: row=c.execute("select host,rtsp_path,username,password_env from cameras where camera_id=%s",(camera_id,)).fetchone()
    if not row: raise HTTPException(404,"camera not found")
    host,path,user,pwenv=row; pw=os.getenv(pwenv)
    if not pw: raise HTTPException(424,f"required secret environment variable {pwenv} is not set")
    url=f"rtsp://{user}:{pw}@{host}:554{path}"
    cap=cv2.VideoCapture(url,cv2.CAP_FFMPEG); ok,frame=cap.read(); cap.release()
    if not ok or frame is None: raise HTTPException(502,"unable to read RTSP frame")
    return {"camera_id":camera_id,"ok":True,"width":int(frame.shape[1]),"height":int(frame.shape[0])}
@app.get("/v1/events")
def events(limit:int=100):
    limit=max(1,min(limit,1000))
    with conn() as c: rows=c.execute("select event_id,camera_id,subject_id,score,event_type,occurred_at,metadata from events order by occurred_at desc limit %s",(limit,)).fetchall()
    return [{"event_id":r[0],"camera_id":r[1],"subject_id":r[2],"score":r[3],"event_type":r[4],"occurred_at":r[5],"metadata":r[6]} for r in rows]
