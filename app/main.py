import base64, json, os, time, threading, uuid, hashlib, hmac, io, datetime
from typing import Optional
import cv2, httpx, psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse, HTMLResponse, Response, StreamingResponse
from pydantic import BaseModel, Field
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
import qrcode

app=FastAPI(title="Codestra FACE-ID",version="1.0.0")
DB=os.environ["DATABASE_URL"]
ENGINE=os.getenv("RECOGNITION_ENGINE_URL","http://recognition-engine:8080")
EVENT_DIR=os.getenv("FACEID_EVENT_DIR","/data/events")
MATCH_THRESHOLD=float(os.getenv("FACEID_MATCH_THRESHOLD","0.363"))
EVENT_RETENTION_DAYS=int(os.getenv("FACEID_EVENT_RETENTION_DAYS","30"))
REGISTRATION_SECRET=os.environ.get("FACEID_REGISTRATION_SECRET","")
PUBLIC_HOST=os.getenv("FACEID_PUBLIC_HOST","10.0.0.73")
PUBLIC_PORT=int(os.getenv("FACEID_PUBLIC_PORT","8094"))
_cleanup_last=0.0

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
class PublicEnroll(BaseModel):
    full_name: str
    id_hash: str
    id_last4: str
    image_base64: str
    consent_obtained: bool
    consent_text_version: str="2026-09"
    token: str

class RegistrationDecision(BaseModel):
    action: str
    note: Optional[str]=None

class EventReview(BaseModel):
    status: str
    note: Optional[str]=None
    subject_id: Optional[str]=None



class ZoneIn(BaseModel):
    zone_id: str
    name: str
    description: Optional[str]=None
    enabled: bool=True

class AccessPolicyIn(BaseModel):
    policy_id: str
    name: str
    subject_id: Optional[str]=None
    zone_id: str
    allowed: bool=True
    schedule: dict=Field(default_factory=dict)
    enabled: bool=True

class VisitorPassIn(BaseModel):
    pass_id: str
    display_name: str
    host_subject_id: Optional[str]=None
    valid_from: str
    valid_until: str
    registration_request_id: Optional[str]=None
    status: str="active"

class AlertRuleIn(BaseModel):
    rule_id: str
    name: str
    event_type: str
    camera_id: Optional[str]=None
    delivery_channel: str="browser"
    recipient_ref: Optional[str]=None
    enabled: bool=True

class IncidentIn(BaseModel):
    incident_id: str
    title: str
    severity: str="medium"
    status: str="open"
    event_ids: list[str]=Field(default_factory=list)
    notes: Optional[str]=None

class RetentionPolicyIn(BaseModel):
    policy_id: str
    resource_type: str
    days: int=Field(ge=1,le=3650)
    enabled: bool=True

class SubjectLabelsIn(BaseModel):
    labels: list[str]=Field(default_factory=list)

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
        c.execute("alter table subjects add column if not exists id_country text")
        c.execute("alter table subjects add column if not exists id_type text")
        c.execute("alter table subjects add column if not exists id_hash text")
        c.execute("alter table subjects add column if not exists id_last4 text")
        c.execute("alter table subjects add column if not exists enrollment_source text")
        c.execute("alter table events add column if not exists snapshot_path text")
        c.execute("alter table events add column if not exists review_status text not null default 'pending'")
        c.execute("alter table events add column if not exists reviewed_at timestamptz")
        c.execute("alter table events add column if not exists review_note text")
        c.execute("alter table events add column if not exists reviewed_subject_id text")
        c.execute("""create table if not exists registration_requests(
          request_id text primary key,
          display_name text not null,
          id_country text not null default 'DO',
          id_type text not null default 'cedula',
          id_hash text not null,
          id_last4 text not null,
          embedding jsonb not null,
          consent_reference text not null,
          status text not null default 'pending',
          decision_note text,
          created_at timestamptz not null default now(),
          decided_at timestamptz)""")
        c.execute("create unique index if not exists registration_requests_id_hash_idx on registration_requests(id_hash) where status='pending'")
        c.execute("""create table if not exists audit_log(
          audit_id text primary key,
          actor text not null,
          action text not null,
          target_type text not null,
          target_id text,
          details jsonb not null default '{}'::jsonb,
          occurred_at timestamptz not null default now())""")

        c.execute("""create table if not exists zones(
          zone_id text primary key,
          name text not null,
          description text,
          enabled boolean not null default true,
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now())""")
        c.execute("""create table if not exists access_policies(
          policy_id text primary key,
          name text not null,
          subject_id text,
          zone_id text not null,
          allowed boolean not null default true,
          schedule jsonb not null default '{}'::jsonb,
          enabled boolean not null default true,
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now())""")
        c.execute("""create table if not exists visitor_passes(
          pass_id text primary key,
          display_name text not null,
          host_subject_id text,
          valid_from timestamptz not null,
          valid_until timestamptz not null,
          registration_request_id text,
          status text not null default 'active',
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now())""")
        c.execute("""create table if not exists alert_rules(
          rule_id text primary key,
          name text not null,
          event_type text not null,
          camera_id text,
          delivery_channel text not null,
          recipient_ref text,
          enabled boolean not null default true,
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now())""")
        c.execute("""create table if not exists incidents(
          incident_id text primary key,
          title text not null,
          severity text not null,
          status text not null,
          event_ids jsonb not null default '[]'::jsonb,
          notes text,
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now())""")
        c.execute("""create table if not exists retention_policies(
          policy_id text primary key,
          resource_type text not null unique,
          days int not null,
          enabled boolean not null default true,
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now())""")
        c.execute("""create table if not exists subject_labels(
          subject_id text not null,
          label text not null,
          created_at timestamptz not null default now(),
          primary key(subject_id,label))""")

WORKER_INTERVAL=float(os.getenv("FACEID_WORKER_INTERVAL_SECONDS","2"))
EVENT_COOLDOWN=float(os.getenv("FACEID_EVENT_COOLDOWN_SECONDS","15"))
_last_events={}
_latest_jpegs={}
_latest_frame_meta={}
_frame_lock=threading.Lock()

def _gallery():
    with conn() as c:
        rows=c.execute("select subject_id,display_name,embedding from subjects").fetchall()
    return rows

def _audit(action, target_type, target_id=None, details=None, actor="local-admin"):
    with conn() as c:
        c.execute("insert into audit_log(audit_id,actor,action,target_type,target_id,details) values(%s,%s,%s,%s,%s,%s::jsonb)",
                  (str(uuid.uuid4()),actor,action,target_type,target_id,json.dumps(details or {})))

def _cleanup_expired():
    global _cleanup_last
    now=time.time()
    if now-_cleanup_last<3600:
        return
    _cleanup_last=now
    paths=[]
    expired_subjects=[]
    with conn() as c:
        paths=[r[0] for r in c.execute("""select snapshot_path from events
                                          where occurred_at < now() - (%s * interval '1 day')
                                          and snapshot_path is not null""",(EVENT_RETENTION_DAYS,)).fetchall()]
        c.execute("delete from events where occurred_at < now() - (%s * interval '1 day')",(EVENT_RETENTION_DAYS,))
        expired_subjects=[r[0] for r in c.execute("""select subject_id from subjects
                                                     where created_at + (retention_days * interval '1 day') < now()""").fetchall()]
        if expired_subjects:
            c.execute("delete from subjects where subject_id = any(%s)",(expired_subjects,))
    for path in paths:
        try:
            if path and os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
    for subject_id in expired_subjects:
        try:
            _audit("subject.retention_expired","subject",subject_id,{"retention_enforced":True},actor="system")
        except Exception:
            pass

def _record_event(camera_id, subject_id, score, event_type, metadata=None, snapshot=None):
    key=(camera_id,subject_id or event_type)
    now=time.time()
    if now-_last_events.get(key,0)<EVENT_COOLDOWN:
        return
    _last_events[key]=now
    event_id=str(uuid.uuid4())
    snapshot_path=None
    if snapshot:
        try:
            os.makedirs(EVENT_DIR,exist_ok=True)
            snapshot_path=os.path.join(EVENT_DIR,event_id+".jpg")
            with open(snapshot_path,"wb") as f:
                f.write(snapshot)
        except Exception:
            snapshot_path=None
    with conn() as c:
        c.execute("insert into events(event_id,camera_id,subject_id,score,event_type,metadata,snapshot_path) values(%s,%s,%s,%s,%s,%s::jsonb,%s)",
                  (event_id,camera_id,subject_id,score,event_type,json.dumps(metadata or {}),snapshot_path))

def _process_camera(row):
    camera_id,name,host,path,user,pwenv,enabled=row
    if not enabled: return
    pw=os.getenv(pwenv)
    if not pw: return
    url=f"rtsp://{user}:{pw}@{host}:554{path}"
    cap=cv2.VideoCapture(url,cv2.CAP_FFMPEG)
    ok,frame=cap.read(); cap.release()
    if not ok or frame is None: return
    ok,jpg=cv2.imencode(".jpg",frame,[int(cv2.IMWRITE_JPEG_QUALITY),82])
    if not ok: return
    with _frame_lock:
        _latest_jpegs[camera_id]=jpg.tobytes()
        _latest_frame_meta[camera_id]={"width":int(frame.shape[1]),"height":int(frame.shape[0]),"updated_at":time.time()}
    b64=base64.b64encode(jpg).decode()
    er=httpx.post(ENGINE+"/v1/embeddings",json={"image_base64":b64},timeout=20)
    if er.status_code==422: return
    if not er.is_success: return
    embedding=er.json()["embedding"]
    rows=_gallery()
    if not rows:
        _record_event(camera_id,None,None,"unknown_face",{"camera_name":name},jpg.tobytes())
        return
    gallery=[{"subject_id":r[0],"embedding":r[2]} for r in rows]
    rr=httpx.post(ENGINE+"/v1/search",json={"embedding":embedding,"gallery":gallery,"threshold":MATCH_THRESHOLD,"top_k":1},timeout=20)
    if not rr.is_success: return
    hits=rr.json().get("hits",[])
    top=hits[0] if hits else None
    if top and top.get("match"):
        _record_event(camera_id,top["subject_id"],top["score"],"recognized_face",{"camera_name":name},jpg.tobytes())
    else:
        _record_event(camera_id,None,top.get("score") if top else None,"unknown_face",{"camera_name":name},jpg.tobytes())

def _worker():
    time.sleep(3)
    while True:
        try:
            _cleanup_expired()
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
            os.makedirs(EVENT_DIR,exist_ok=True)
            threading.Thread(target=_worker,daemon=True).start()
            return
        except Exception as e:
            last=e; time.sleep(1)
    raise last

def _registration_token(day=None):
    if not REGISTRATION_SECRET:
        raise HTTPException(503,"registration secret is not configured")
    day=day or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    return hmac.new(REGISTRATION_SECRET.encode(),("faceid-registration:"+day).encode(),hashlib.sha256).hexdigest()[:32]

def _valid_registration_token(token:str):
    today=datetime.datetime.now(datetime.timezone.utc)
    for delta in (0,1):
        day=(today-datetime.timedelta(days=delta)).strftime("%Y-%m-%d")
        if hmac.compare_digest(token or "",_registration_token(day)):
            return True
    return False

@app.get("/v1/registration/info")
def registration_info():
    token=_registration_token()
    return {"url":f"http://{PUBLIC_HOST}:{PUBLIC_PORT}/register?token={token}","expires":"daily","country":"DO","id_type":"cedula"}

@app.get("/v1/registration/qr")
def registration_qr():
    token=_registration_token()
    url=f"http://{PUBLIC_HOST}:{PUBLIC_PORT}/register?token={token}"
    qr=qrcode.QRCode(version=None,box_size=8,border=3,error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(url); qr.make(fit=True)
    img=qr.make_image(fill_color="black",back_color="white")
    buf=io.BytesIO(); img.save(buf,format="PNG")
    return Response(buf.getvalue(),media_type="image/png",headers={"Cache-Control":"no-store"})

@app.middleware("http")
async def local_admin_boundary(request:Request, call_next):
    path=request.url.path
    public = path == "/register" or path == "/v1/public/enroll" or path == "/healthz"
    host = request.client.host if request.client else ""
    local = host in {"127.0.0.1","::1","localhost"} or host.startswith("172.")
    if not public and not local:
        return Response("Local admin access only",status_code=403,media_type="text/plain")
    return await call_next(request)

@app.post("/v1/public/enroll")
def public_enroll(req:PublicEnroll):
    if not _valid_registration_token(req.token):
        raise HTTPException(403,"invalid or expired registration token")
    if not req.consent_obtained:
        raise HTTPException(400,"explicit consent is required")
    name=req.full_name.strip()
    if len(name)<2:
        raise HTTPException(400,"full name is required")
    id_hash=req.id_hash.lower().strip()
    if len(id_hash)!=64 or any(c not in "0123456789abcdef" for c in id_hash):
        raise HTTPException(400,"invalid identity reference")
    if len(req.id_last4)!=4 or not req.id_last4.isdigit():
        raise HTTPException(400,"invalid ID reference")
    er=httpx.post(ENGINE+"/v1/embeddings",json={"image_base64":req.image_base64},timeout=25)
    if not er.is_success:
        raise HTTPException(er.status_code,er.text)
    emb=er.json()["embedding"]
    request_id="reg-"+uuid.uuid4().hex[:16]
    consent_ref=f"qr-do-self-registration:{req.consent_text_version}"
    with conn() as c:
        existing=c.execute("select request_id,status from registration_requests where id_hash=%s order by created_at desc limit 1",(id_hash,)).fetchone()
        if existing and existing[1]=="pending":
            request_id=existing[0]
            c.execute("""update registration_requests set display_name=%s,id_last4=%s,embedding=%s::jsonb,consent_reference=%s,created_at=now()
                         where request_id=%s""",(name,req.id_last4,json.dumps(emb),consent_ref,request_id))
        else:
            c.execute("""insert into registration_requests(request_id,display_name,id_hash,id_last4,embedding,consent_reference)
                         values(%s,%s,%s,%s,%s::jsonb,%s)""",
                      (request_id,name,id_hash,req.id_last4,json.dumps(emb),consent_ref))
    _audit("registration.submitted","registration_request",request_id,{"display_name":name,"id_country":"DO","id_type":"cedula","id_last4":req.id_last4},actor="self-registration")
    return {"submitted":True,"request_id":request_id,"status":"pending_review","display_name":name}

@app.get("/register", response_class=HTMLResponse)
def registration_page(token:str=""):
    if not _valid_registration_token(token):
        return HTMLResponse("<h2>Registration link is invalid or expired.</h2>",status_code=403)
    page=os.path.join(os.path.dirname(__file__),"static","register.html")
    with open(page,"r",encoding="utf-8") as f:
        return HTMLResponse(f.read().replace("__REG_TOKEN__",token),headers={"Cache-Control":"no-store"})

@app.get("/", response_class=HTMLResponse)
def dashboard():
    page=os.path.join(os.path.dirname(__file__),"static","dashboard.html")
    with open(page,"r",encoding="utf-8") as f:
        return HTMLResponse(f.read())

def _camera_row(camera_id:str):
    with conn() as c:
        row=c.execute("select camera_id,name,host,rtsp_path,username,password_env,enabled from cameras where camera_id=%s",(camera_id,)).fetchone()
    if not row: raise HTTPException(404,"camera not found")
    return row

def _read_camera_jpeg(camera_id:str):
    with _frame_lock:
        cached=_latest_jpegs.get(camera_id)
        meta=_latest_frame_meta.get(camera_id)
        if cached and meta and time.time()-meta.get("updated_at",0)<5:
            return cached,meta
    _,name,host,path,user,pwenv,enabled=_camera_row(camera_id)
    pw=os.getenv(pwenv)
    if not pw: raise HTTPException(424,f"required secret environment variable {pwenv} is not set")
    url=f"rtsp://{user}:{pw}@{host}:554{path}"
    cap=cv2.VideoCapture(url,cv2.CAP_FFMPEG)
    ok,frame=cap.read(); cap.release()
    if not ok or frame is None: raise HTTPException(502,"unable to read RTSP frame")
    ok,jpg=cv2.imencode(".jpg",frame,[int(cv2.IMWRITE_JPEG_QUALITY),82])
    if not ok: raise HTTPException(500,"unable to encode camera frame")
    data=jpg.tobytes()
    meta={"width":int(frame.shape[1]),"height":int(frame.shape[0]),"updated_at":time.time()}
    with _frame_lock:
        _latest_jpegs[camera_id]=data
        _latest_frame_meta[camera_id]=meta
    return data,meta

@app.get("/v1/cameras/{camera_id}/snapshot")
def camera_snapshot(camera_id:str):
    data,_=_read_camera_jpeg(camera_id)
    return Response(content=data,media_type="image/jpeg",headers={"Cache-Control":"no-store, no-cache, must-revalidate"})

@app.get("/v1/cameras/{camera_id}/stream.mjpg")
def camera_mjpeg(camera_id:str):
    _camera_row(camera_id)
    def frames():
        while True:
            try:
                with _frame_lock:
                    data=_latest_jpegs.get(camera_id)
                if not data:
                    data,_=_read_camera_jpeg(camera_id)
                yield b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "+str(len(data)).encode()+b"\r\n\r\n"+data+b"\r\n"
            except Exception:
                pass
            time.sleep(.35)
    return StreamingResponse(frames(),media_type="multipart/x-mixed-replace; boundary=frame",headers={"Cache-Control":"no-store"})

@app.get("/v1/dashboard")
def dashboard_data():
    with conn() as c:
        subjects_count=c.execute("select count(*) from subjects").fetchone()[0]
        events_count=c.execute("select count(*) from events").fetchone()[0]
        recognized_count=c.execute("select count(*) from events where event_type='recognized_face'").fetchone()[0]
        unknown_count=c.execute("select count(*) from events where event_type='unknown_face'").fetchone()[0]
        pending_unknown=c.execute("select count(*) from events where event_type='unknown_face' and review_status='pending'").fetchone()[0]
        pending_registrations=c.execute("select count(*) from registration_requests where status='pending'").fetchone()[0]
        cams=c.execute("select camera_id,name,host,enabled from cameras order by camera_id").fetchall()
        recent=c.execute("""select e.event_id,e.camera_id,e.subject_id,e.score,e.event_type,e.occurred_at,e.metadata,s.display_name,
                                   e.snapshot_path,e.review_status
                            from events e left join subjects s on s.subject_id=e.subject_id
                            order by e.occurred_at desc limit 12""").fetchall()
    with _frame_lock:
        frame_meta=dict(_latest_frame_meta)
    return {"stats":{"subjects":subjects_count,"events":events_count,"recognized":recognized_count,"unknown":unknown_count,
                     "pending_unknown":pending_unknown,"pending_registrations":pending_registrations},
            "cameras":[{"camera_id":r[0],"name":r[1],"host":r[2],"enabled":r[3],"frame":frame_meta.get(r[0])} for r in cams],
            "recent":[{"event_id":r[0],"camera_id":r[1],"subject_id":r[2],"score":r[3],"event_type":r[4],"occurred_at":r[5],
                       "metadata":r[6],"display_name":r[7],"has_snapshot":bool(r[8]),"review_status":r[9]} for r in recent]}

@app.get("/healthz")
def healthz(): return {"ok":True}
@app.get("/readyz")
@app.get("/health/ready")
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
def capabilities(): return {"camera_ingest":["rtsp","onvif"],"recognition":["enroll","verify","search"],"review_workflow":True,"registration_approval":True,"event_snapshots":True,"audit_log":True,"browser_notifications":True,"multi_camera_dashboard":True,"liveness":False,"match_threshold":MATCH_THRESHOLD,"event_retention_days":EVENT_RETENTION_DAYS,"admin_access":"local-only","storage":"postgresql","local_first":True}
@app.post("/v1/faces/enroll")
def enroll(req:Enroll):
    if not req.consent_obtained: raise HTTPException(400,"explicit enrollment consent is required")
    er=httpx.post(ENGINE+"/v1/embeddings",json={"image_base64":req.image_base64},timeout=20)
    if not er.is_success: raise HTTPException(er.status_code,er.text)
    emb=er.json()["embedding"]
    with conn() as c:
        c.execute("""insert into subjects(subject_id,display_name,embedding,consent_obtained,consent_reference,retention_days) values(%s,%s,%s::jsonb,%s,%s,%s) on conflict(subject_id) do update set display_name=excluded.display_name,embedding=excluded.embedding,consent_obtained=excluded.consent_obtained,consent_reference=excluded.consent_reference,retention_days=excluded.retention_days,updated_at=now()""",(req.subject_id,req.display_name,json.dumps(emb),req.consent_obtained,req.consent_reference,req.retention_days))
    _audit("subject.enrolled","subject",req.subject_id,{"display_name":req.display_name,"source":"manual"})
    return {"subject_id":req.subject_id,"display_name":req.display_name,"enrolled":True}
@app.delete("/v1/faces/{subject_id}")
def delete_face(subject_id:str):
    with conn() as c: c.execute("delete from subjects where subject_id=%s",(subject_id,))
    _audit("subject.deleted","subject",subject_id)
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
        rows=c.execute("select subject_id,display_name,consent_obtained,consent_reference,retention_days,created_at,updated_at,id_country,id_type,id_last4,enrollment_source from subjects order by display_name").fetchall()
    return [{"subject_id":r[0],"display_name":r[1],"consent_obtained":r[2],"consent_reference":r[3],"retention_days":r[4],
             "created_at":r[5],"updated_at":r[6],"id_country":r[7],"id_type":r[8],"id_last4":r[9],"enrollment_source":r[10]} for r in rows]

@app.get("/v1/registrations")
def registration_requests(status:str="pending", limit:int=200):
    limit=max(1,min(limit,1000))
    with conn() as c:
        rows=c.execute("""select request_id,display_name,id_country,id_type,id_last4,consent_reference,status,decision_note,created_at,decided_at
                          from registration_requests
                          where (%s='all' or status=%s)
                          order by created_at desc limit %s""",(status,status,limit)).fetchall()
    return [{"request_id":r[0],"display_name":r[1],"id_country":r[2],"id_type":r[3],"id_last4":r[4],
             "consent_reference":r[5],"status":r[6],"decision_note":r[7],"created_at":r[8],"decided_at":r[9]} for r in rows]

@app.post("/v1/registrations/{request_id}/decision")
def registration_decision(request_id:str, req:RegistrationDecision):
    action=req.action.lower().strip()
    if action not in {"approve","reject"}:
        raise HTTPException(400,"action must be approve or reject")
    with conn() as c:
        row=c.execute("""select display_name,id_hash,id_last4,embedding,consent_reference,status
                         from registration_requests where request_id=%s""",(request_id,)).fetchone()
        if not row:
            raise HTTPException(404,"registration request not found")
        if row[5]!="pending":
            raise HTTPException(409,"registration request already decided")
        name,id_hash,id_last4,embedding,consent_ref,_=row
        if action=="approve":
            subject_id="do-"+id_hash[:16]
            c.execute("""insert into subjects(subject_id,display_name,embedding,consent_obtained,consent_reference,retention_days,
                         id_country,id_type,id_hash,id_last4,enrollment_source)
                         values(%s,%s,%s::jsonb,true,%s,365,'DO','cedula',%s,%s,'qr-self-registration')
                         on conflict(subject_id) do update set display_name=excluded.display_name,embedding=excluded.embedding,
                         consent_obtained=true,consent_reference=excluded.consent_reference,updated_at=now(),
                         id_country='DO',id_type='cedula',id_hash=excluded.id_hash,id_last4=excluded.id_last4,
                         enrollment_source='qr-self-registration'""",
                      (subject_id,name,json.dumps(embedding),consent_ref,id_hash,id_last4))
            c.execute("update registration_requests set status='approved',decision_note=%s,decided_at=now() where request_id=%s",(req.note,request_id))
            _audit("registration.approved","registration_request",request_id,{"subject_id":subject_id,"display_name":name})
            return {"request_id":request_id,"status":"approved","subject_id":subject_id,"display_name":name}
        c.execute("update registration_requests set status='rejected',decision_note=%s,decided_at=now() where request_id=%s",(req.note,request_id))
    _audit("registration.rejected","registration_request",request_id,{"display_name":name})
    return {"request_id":request_id,"status":"rejected"}

@app.get("/v1/audit")
def audit_log(limit:int=200):
    limit=max(1,min(limit,1000))
    with conn() as c:
        rows=c.execute("""select audit_id,actor,action,target_type,target_id,details,occurred_at
                          from audit_log order by occurred_at desc limit %s""",(limit,)).fetchall()
    return [{"audit_id":r[0],"actor":r[1],"action":r[2],"target_type":r[3],"target_id":r[4],"details":r[5],"occurred_at":r[6]} for r in rows]


@app.get("/v1/zones")
def list_zones():
    with conn() as c:
        rows=c.execute("select zone_id,name,description,enabled,created_at,updated_at from zones order by name").fetchall()
    return [{"zone_id":r[0],"name":r[1],"description":r[2],"enabled":r[3],"created_at":r[4],"updated_at":r[5]} for r in rows]

@app.post("/v1/zones")
def save_zone(req:ZoneIn):
    with conn() as c:
        c.execute("""insert into zones(zone_id,name,description,enabled) values(%s,%s,%s,%s)
                     on conflict(zone_id) do update set name=excluded.name,description=excluded.description,
                     enabled=excluded.enabled,updated_at=now()""",(req.zone_id,req.name,req.description,req.enabled))
    _audit("zone.saved","zone",req.zone_id,{"name":req.name,"enabled":req.enabled})
    return {"zone_id":req.zone_id,"saved":True}

@app.get("/v1/access-policies")
def list_access_policies():
    with conn() as c:
        rows=c.execute("""select policy_id,name,subject_id,zone_id,allowed,schedule,enabled,created_at,updated_at
                          from access_policies order by name""").fetchall()
    return [{"policy_id":r[0],"name":r[1],"subject_id":r[2],"zone_id":r[3],"allowed":r[4],
             "schedule":r[5],"enabled":r[6],"created_at":r[7],"updated_at":r[8]} for r in rows]

@app.post("/v1/access-policies")
def save_access_policy(req:AccessPolicyIn):
    with conn() as c:
        if not c.execute("select 1 from zones where zone_id=%s",(req.zone_id,)).fetchone():
            raise HTTPException(400,"zone_id does not exist")
        if req.subject_id and not c.execute("select 1 from subjects where subject_id=%s",(req.subject_id,)).fetchone():
            raise HTTPException(400,"subject_id does not exist")
        c.execute("""insert into access_policies(policy_id,name,subject_id,zone_id,allowed,schedule,enabled)
                     values(%s,%s,%s,%s,%s,%s::jsonb,%s)
                     on conflict(policy_id) do update set name=excluded.name,subject_id=excluded.subject_id,
                     zone_id=excluded.zone_id,allowed=excluded.allowed,schedule=excluded.schedule,
                     enabled=excluded.enabled,updated_at=now()""",
                  (req.policy_id,req.name,req.subject_id,req.zone_id,req.allowed,json.dumps(req.schedule),req.enabled))
    _audit("access_policy.saved","access_policy",req.policy_id,{"zone_id":req.zone_id,"allowed":req.allowed})
    return {"policy_id":req.policy_id,"saved":True}

@app.get("/v1/visitor-passes")
def list_visitor_passes():
    with conn() as c:
        rows=c.execute("""select pass_id,display_name,host_subject_id,valid_from,valid_until,registration_request_id,status,
                          created_at,updated_at from visitor_passes order by created_at desc""").fetchall()
    return [{"pass_id":r[0],"display_name":r[1],"host_subject_id":r[2],"valid_from":r[3],"valid_until":r[4],
             "registration_request_id":r[5],"status":r[6],"created_at":r[7],"updated_at":r[8]} for r in rows]

@app.post("/v1/visitor-passes")
def save_visitor_pass(req:VisitorPassIn):
    try:
        start=datetime.datetime.fromisoformat(req.valid_from.replace("Z","+00:00"))
        end=datetime.datetime.fromisoformat(req.valid_until.replace("Z","+00:00"))
    except ValueError:
        raise HTTPException(400,"valid_from and valid_until must be ISO-8601 timestamps")
    if end <= start:
        raise HTTPException(400,"valid_until must be after valid_from")
    with conn() as c:
        if req.host_subject_id and not c.execute("select 1 from subjects where subject_id=%s",(req.host_subject_id,)).fetchone():
            raise HTTPException(400,"host_subject_id does not exist")
        c.execute("""insert into visitor_passes(pass_id,display_name,host_subject_id,valid_from,valid_until,registration_request_id,status)
                     values(%s,%s,%s,%s,%s,%s,%s)
                     on conflict(pass_id) do update set display_name=excluded.display_name,
                     host_subject_id=excluded.host_subject_id,valid_from=excluded.valid_from,valid_until=excluded.valid_until,
                     registration_request_id=excluded.registration_request_id,status=excluded.status,updated_at=now()""",
                  (req.pass_id,req.display_name,req.host_subject_id,start,end,req.registration_request_id,req.status))
    _audit("visitor_pass.saved","visitor_pass",req.pass_id,{"display_name":req.display_name,"status":req.status})
    return {"pass_id":req.pass_id,"saved":True}

@app.get("/v1/alert-rules")
def list_alert_rules():
    with conn() as c:
        rows=c.execute("""select rule_id,name,event_type,camera_id,delivery_channel,recipient_ref,enabled,created_at,updated_at
                          from alert_rules order by name""").fetchall()
    return [{"rule_id":r[0],"name":r[1],"event_type":r[2],"camera_id":r[3],"delivery_channel":r[4],
             "recipient_ref":r[5],"enabled":r[6],"created_at":r[7],"updated_at":r[8]} for r in rows]

@app.post("/v1/alert-rules")
def save_alert_rule(req:AlertRuleIn):
    allowed_channels={"browser","email","sms","webhook"}
    if req.delivery_channel not in allowed_channels:
        raise HTTPException(400,"unsupported delivery_channel")
    with conn() as c:
        if req.camera_id and not c.execute("select 1 from cameras where camera_id=%s",(req.camera_id,)).fetchone():
            raise HTTPException(400,"camera_id does not exist")
        c.execute("""insert into alert_rules(rule_id,name,event_type,camera_id,delivery_channel,recipient_ref,enabled)
                     values(%s,%s,%s,%s,%s,%s,%s)
                     on conflict(rule_id) do update set name=excluded.name,event_type=excluded.event_type,
                     camera_id=excluded.camera_id,delivery_channel=excluded.delivery_channel,
                     recipient_ref=excluded.recipient_ref,enabled=excluded.enabled,updated_at=now()""",
                  (req.rule_id,req.name,req.event_type,req.camera_id,req.delivery_channel,req.recipient_ref,req.enabled))
    _audit("alert_rule.saved","alert_rule",req.rule_id,{"event_type":req.event_type,"channel":req.delivery_channel})
    return {"rule_id":req.rule_id,"saved":True}

@app.get("/v1/incidents")
def list_incidents():
    with conn() as c:
        rows=c.execute("""select incident_id,title,severity,status,event_ids,notes,created_at,updated_at
                          from incidents order by updated_at desc""").fetchall()
    return [{"incident_id":r[0],"title":r[1],"severity":r[2],"status":r[3],"event_ids":r[4],
             "notes":r[5],"created_at":r[6],"updated_at":r[7]} for r in rows]

@app.post("/v1/incidents")
def save_incident(req:IncidentIn):
    if req.severity not in {"low","medium","high","critical"}:
        raise HTTPException(400,"unsupported severity")
    if req.status not in {"open","investigating","resolved","closed"}:
        raise HTTPException(400,"unsupported status")
    with conn() as c:
        if req.event_ids:
            found={r[0] for r in c.execute("select event_id from events where event_id = any(%s)",(req.event_ids,)).fetchall()}
            missing=[x for x in req.event_ids if x not in found]
            if missing:
                raise HTTPException(400,"one or more event_ids do not exist")
        c.execute("""insert into incidents(incident_id,title,severity,status,event_ids,notes)
                     values(%s,%s,%s,%s,%s::jsonb,%s)
                     on conflict(incident_id) do update set title=excluded.title,severity=excluded.severity,
                     status=excluded.status,event_ids=excluded.event_ids,notes=excluded.notes,updated_at=now()""",
                  (req.incident_id,req.title,req.severity,req.status,json.dumps(req.event_ids),req.notes))
    _audit("incident.saved","incident",req.incident_id,{"severity":req.severity,"status":req.status})
    return {"incident_id":req.incident_id,"saved":True}

@app.get("/v1/retention-policies")
def list_retention_policies():
    with conn() as c:
        rows=c.execute("""select policy_id,resource_type,days,enabled,created_at,updated_at
                          from retention_policies order by resource_type""").fetchall()
    return [{"policy_id":r[0],"resource_type":r[1],"days":r[2],"enabled":r[3],"created_at":r[4],"updated_at":r[5]} for r in rows]

@app.post("/v1/retention-policies")
def save_retention_policy(req:RetentionPolicyIn):
    allowed={"events","event_snapshots","visitors","incidents","audit"}
    if req.resource_type not in allowed:
        raise HTTPException(400,"unsupported resource_type")
    with conn() as c:
        c.execute("""insert into retention_policies(policy_id,resource_type,days,enabled) values(%s,%s,%s,%s)
                     on conflict(policy_id) do update set resource_type=excluded.resource_type,days=excluded.days,
                     enabled=excluded.enabled,updated_at=now()""",(req.policy_id,req.resource_type,req.days,req.enabled))
    _audit("retention_policy.saved","retention_policy",req.policy_id,{"resource_type":req.resource_type,"days":req.days})
    return {"policy_id":req.policy_id,"saved":True}

@app.get("/v1/subjects/{subject_id}/labels")
def get_subject_labels(subject_id:str):
    with conn() as c:
        if not c.execute("select 1 from subjects where subject_id=%s",(subject_id,)).fetchone():
            raise HTTPException(404,"subject not found")
        rows=c.execute("select label,created_at from subject_labels where subject_id=%s order by label",(subject_id,)).fetchall()
    return [{"label":r[0],"created_at":r[1]} for r in rows]

@app.put("/v1/subjects/{subject_id}/labels")
def set_subject_labels(subject_id:str, req:SubjectLabelsIn):
    labels=sorted({x.strip().lower() for x in req.labels if x.strip()})
    if any(len(x)>64 for x in labels):
        raise HTTPException(400,"labels must be 64 characters or fewer")
    with conn() as c:
        if not c.execute("select 1 from subjects where subject_id=%s",(subject_id,)).fetchone():
            raise HTTPException(404,"subject not found")
        c.execute("delete from subject_labels where subject_id=%s",(subject_id,))
        for label in labels:
            c.execute("insert into subject_labels(subject_id,label) values(%s,%s)",(subject_id,label))
    _audit("subject.labels_updated","subject",subject_id,{"labels":labels})
    return {"subject_id":subject_id,"labels":labels}

@app.get("/v1/privacy/subjects/{subject_id}/export")
def privacy_export(subject_id:str):
    with conn() as c:
        s=c.execute("""select subject_id,display_name,consent_obtained,consent_reference,retention_days,created_at,updated_at,
                       id_country,id_type,id_last4,enrollment_source from subjects where subject_id=%s""",(subject_id,)).fetchone()
        if not s:
            raise HTTPException(404,"subject not found")
        labels=[r[0] for r in c.execute("select label from subject_labels where subject_id=%s order by label",(subject_id,)).fetchall()]
        events=c.execute("""select event_id,camera_id,score,event_type,occurred_at,review_status
                            from events where subject_id=%s or reviewed_subject_id=%s order by occurred_at desc limit 1000""",
                         (subject_id,subject_id)).fetchall()
    _audit("privacy.exported","subject",subject_id)
    return {"subject":{"subject_id":s[0],"display_name":s[1],"consent_obtained":s[2],"consent_reference":s[3],
            "retention_days":s[4],"created_at":s[5],"updated_at":s[6],"id_country":s[7],"id_type":s[8],
            "id_last4":s[9],"enrollment_source":s[10],"labels":labels},
            "events":[{"event_id":e[0],"camera_id":e[1],"score":e[2],"event_type":e[3],"occurred_at":e[4],"review_status":e[5]} for e in events]}

@app.delete("/v1/privacy/subjects/{subject_id}")
def privacy_delete(subject_id:str):
    snapshot_paths=[]
    with conn() as c:
        exists=c.execute("select 1 from subjects where subject_id=%s",(subject_id,)).fetchone()
        if not exists:
            raise HTTPException(404,"subject not found")
        snapshot_paths=[r[0] for r in c.execute("select snapshot_path from events where subject_id=%s and snapshot_path is not null",(subject_id,)).fetchall()]
        c.execute("delete from subject_labels where subject_id=%s",(subject_id,))
        c.execute("update events set subject_id=null,reviewed_subject_id=null where subject_id=%s or reviewed_subject_id=%s",(subject_id,subject_id))
        c.execute("delete from access_policies where subject_id=%s",(subject_id,))
        c.execute("update visitor_passes set host_subject_id=null where host_subject_id=%s",(subject_id,))
        c.execute("delete from subjects where subject_id=%s",(subject_id,))
    for path in snapshot_paths:
        try:
            if path and os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
    _audit("privacy.deleted","subject",subject_id)
    return {"subject_id":subject_id,"deleted":True}

@app.get("/v1/integrations/status")
def integrations_status():
    engine={"ready":False}
    try:
        r=httpx.get(ENGINE+"/readyz",timeout=3)
        engine={"ready":r.is_success,"status_code":r.status_code}
    except Exception:
        pass
    with conn() as c:
        cams=c.execute("select count(*) from cameras where enabled=true").fetchone()[0]
    return {"middleware_authority":"Caddy -> Kong -> Middleware V3 :8095 -> service API",
            "recognition_engine":engine,"enabled_cameras":cams,
            "liveness":{"configured":bool(os.getenv("FACEID_LIVENESS_URL"))},
            "camera_gateway":{"configured":bool(os.getenv("FACEID_CAMERA_GATEWAY_URL"))},
            "postgresql_management":{"configured":bool(os.getenv("FACEID_POSTGRESQL_MANAGEMENT_URL"))}}

@app.post("/v1/cameras")
def camera_add(req:CameraIn):
    with conn() as c:
        c.execute("""insert into cameras(camera_id,name,host,rtsp_path,username,password_env,enabled) values(%s,%s,%s,%s,%s,%s,%s) on conflict(camera_id) do update set name=excluded.name,host=excluded.host,rtsp_path=excluded.rtsp_path,username=excluded.username,password_env=excluded.password_env,enabled=excluded.enabled""",(req.camera_id,req.name,req.host,req.rtsp_path,req.username,req.password_env,req.enabled))
    _audit("camera.saved","camera",req.camera_id,{"name":req.name,"host":req.host,"enabled":req.enabled})
    return {"camera_id":req.camera_id,"saved":True}
@app.get("/v1/cameras")
def camera_list():
    with conn() as c: rows=c.execute("select camera_id,name,host,rtsp_path,username,password_env,enabled from cameras order by camera_id").fetchall()
    return [{"camera_id":r[0],"name":r[1],"host":r[2],"rtsp_path":r[3],"username":r[4],"password_env":r[5],"enabled":r[6]} for r in rows]
@app.delete("/v1/cameras/{camera_id}")
def camera_delete(camera_id:str):
    with conn() as c: c.execute("delete from cameras where camera_id=%s",(camera_id,))
    return {"deleted":True,"camera_id":camera_id}

@app.get("/v1/cameras/{camera_id}/onvif")
def camera_onvif(camera_id:str):
    with conn() as c:
        row=c.execute("select host,username,password_env from cameras where camera_id=%s",(camera_id,)).fetchone()
    if not row: raise HTTPException(404,"camera not found")
    host,user,pwenv=row
    pw=os.getenv(pwenv)
    if not pw: raise HTTPException(424,f"required secret environment variable {pwenv} is not set")
    auth=httpx.DigestAuth(user,pw)
    headers_profiles={"Content-Type":'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/media/wsdl/GetProfiles"'}
    body_profiles='<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><trt:GetProfiles xmlns:trt="http://www.onvif.org/ver10/media/wsdl"/></s:Body></s:Envelope>'
    try:
        rp=httpx.post(f"http://{host}/onvif/Media",content=body_profiles,headers=headers_profiles,auth=auth,timeout=10)
    except Exception as e:
        raise HTTPException(502,f"ONVIF GetProfiles failed: {type(e).__name__}")
    if rp.status_code != 200:
        raise HTTPException(rp.status_code,"ONVIF GetProfiles rejected")
    import xml.etree.ElementTree as ET
    root=ET.fromstring(rp.text)
    ns={"trt":"http://www.onvif.org/ver10/media/wsdl","tt":"http://www.onvif.org/ver10/schema"}
    profiles=[]
    for pr in root.findall(".//trt:Profiles",ns):
        token=pr.attrib.get("token")
        name_el=pr.find("tt:Name",ns)
        enc=pr.find("tt:VideoEncoderConfiguration",ns)
        item={"token":token,"name":name_el.text if name_el is not None else None}
        if enc is not None:
            encname=enc.find("tt:Encoding",ns)
            res=enc.find("tt:Resolution",ns)
            item["encoding"]=encname.text if encname is not None else None
            if res is not None:
                w=res.find("tt:Width",ns); h=res.find("tt:Height",ns)
                item["width"]=int(w.text) if w is not None else None
                item["height"]=int(h.text) if h is not None else None
        uri_body=f'<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><trt:GetStreamUri xmlns:trt="http://www.onvif.org/ver10/media/wsdl"><trt:StreamSetup><tt:Stream xmlns:tt="http://www.onvif.org/ver10/schema">RTP-Unicast</tt:Stream><tt:Transport xmlns:tt="http://www.onvif.org/ver10/schema"><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>{token}</trt:ProfileToken></trt:GetStreamUri></s:Body></s:Envelope>'
        headers_uri={"Content-Type":'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/media/wsdl/GetStreamUri"'}
        ru=httpx.post(f"http://{host}/onvif/Media",content=uri_body,headers=headers_uri,auth=auth,timeout=10)
        if ru.status_code==200:
            rr=ET.fromstring(ru.text)
            uri_el=rr.find(".//tt:Uri",ns)
            if uri_el is not None: item["rtsp_uri"]=uri_el.text
        profiles.append(item)
    return {"camera_id":camera_id,"profiles":profiles}

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
@app.get("/v1/events/{event_id}/snapshot")
def event_snapshot(event_id:str):
    with conn() as c:
        row=c.execute("select snapshot_path from events where event_id=%s",(event_id,)).fetchone()
    if not row:
        raise HTTPException(404,"event not found")
    path=row[0]
    if not path or not os.path.exists(path):
        raise HTTPException(404,"event snapshot not available")
    with open(path,"rb") as f:
        return Response(f.read(),media_type="image/jpeg",headers={"Cache-Control":"no-store"})

@app.post("/v1/events/{event_id}/review")
def review_event(event_id:str, req:EventReview):
    status=req.status.lower().strip()
    if status not in {"reviewed","dismissed","confirmed"}:
        raise HTTPException(400,"status must be reviewed, dismissed, or confirmed")
    with conn() as c:
        row=c.execute("select event_id,event_type,subject_id from events where event_id=%s",(event_id,)).fetchone()
        if not row:
            raise HTTPException(404,"event not found")
        if req.subject_id:
            exists=c.execute("select 1 from subjects where subject_id=%s",(req.subject_id,)).fetchone()
            if not exists:
                raise HTTPException(400,"subject_id does not exist")
        c.execute("""update events set review_status=%s,reviewed_at=now(),review_note=%s,reviewed_subject_id=%s
                     where event_id=%s""",(status,req.note,req.subject_id,event_id))
    _audit("event.reviewed","event",event_id,{"status":status,"subject_id":req.subject_id,"note":req.note})
    return {"event_id":event_id,"review_status":status,"subject_id":req.subject_id}

@app.get("/v1/events")
def events(limit:int=100, review_status:str="all"):
    limit=max(1,min(limit,1000))
    with conn() as c:
        rows=c.execute("""select event_id,camera_id,subject_id,score,event_type,occurred_at,metadata,
                          snapshot_path,review_status,reviewed_at,review_note,reviewed_subject_id
                          from events
                          where (%s='all' or review_status=%s)
                          order by occurred_at desc limit %s""",(review_status,review_status,limit)).fetchall()
    return [{"event_id":r[0],"camera_id":r[1],"subject_id":r[2],"score":r[3],"event_type":r[4],"occurred_at":r[5],
             "metadata":r[6],"has_snapshot":bool(r[7]),"review_status":r[8],"reviewed_at":r[9],
             "review_note":r[10],"reviewed_subject_id":r[11]} for r in rows]
