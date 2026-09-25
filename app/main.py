import base64, json, os, re, time, threading, uuid, hashlib, hmac, io, datetime, zoneinfo
from typing import Optional
import cv2, httpx, psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse, HTMLResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
import qrcode

app=FastAPI(title="Codestra FACE-ID",version="1.1.0")
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

class AccessEvaluateIn(BaseModel):
    model_config=ConfigDict(extra="forbid")
    subject_ref: Optional[str]=None
    subject_id: Optional[str]=None
    zone_id: str
    occurred_at: str
    visitor_pass_id: Optional[str]=None

class PresenceEventIn(BaseModel):
    model_config=ConfigDict(extra="forbid")
    event_ref: str
    direction: str
    subject_ref: Optional[str]=None
    subject_id: Optional[str]=None
    visitor_pass_id: Optional[str]=None
    event_id: Optional[str]=None
    camera_id: Optional[str]=None
    zone_id: Optional[str]=None
    occurred_at: Optional[str]=None

class UnknownClusterIn(BaseModel):
    model_config=ConfigDict(extra="forbid")
    cluster_id: Optional[str]=None
    label: str=Field(min_length=1,max_length=120)
    status: str="open"
    notes: Optional[str]=Field(default=None,max_length=2000)
    owner_ref: Optional[str]=None

class UnknownClusterPatch(BaseModel):
    model_config=ConfigDict(extra="forbid")
    label: Optional[str]=Field(default=None,min_length=1,max_length=120)
    status: Optional[str]=None
    notes: Optional[str]=Field(default=None,max_length=2000)
    owner_ref: Optional[str]=None

class ClusterEventsIn(BaseModel):
    model_config=ConfigDict(extra="forbid")
    event_ids: list[str]=Field(min_length=1,max_length=500)

class CameraZoneIn(BaseModel):
    model_config=ConfigDict(extra="forbid")
    camera_id: str
    zone_id: str
    priority: int=Field(default=100,ge=0,le=1000)
    enabled: bool=True
    notes: Optional[str]=Field(default=None,max_length=500)

class CameraZonePatch(BaseModel):
    model_config=ConfigDict(extra="forbid")
    priority: Optional[int]=Field(default=None,ge=0,le=1000)
    enabled: Optional[bool]=None
    notes: Optional[str]=Field(default=None,max_length=500)

class ReviewQueueIn(BaseModel):
    model_config=ConfigDict(extra="forbid")
    queue_id: str
    name: str=Field(min_length=1,max_length=120)
    description: Optional[str]=Field(default=None,max_length=1000)
    status: str="active"
    default_priority: str="normal"

class ReviewQueuePatch(BaseModel):
    model_config=ConfigDict(extra="forbid")
    name: Optional[str]=Field(default=None,min_length=1,max_length=120)
    description: Optional[str]=Field(default=None,max_length=1000)
    status: Optional[str]=None
    default_priority: Optional[str]=None

class ReviewItemIn(BaseModel):
    model_config=ConfigDict(extra="forbid")
    item_type: str
    item_ref: str
    priority: Optional[str]=None
    assignee_ref: Optional[str]=None
    notes: Optional[str]=Field(default=None,max_length=2000)

class ReviewItemPatch(BaseModel):
    model_config=ConfigDict(extra="forbid")
    status: Optional[str]=None
    priority: Optional[str]=None
    assignee_ref: Optional[str]=None
    notes: Optional[str]=Field(default=None,max_length=2000)

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
        c.execute("""create table if not exists camera_zones(
          mapping_id text primary key,
          camera_id text not null,
          zone_id text not null,
          priority int not null default 100,
          enabled boolean not null default true,
          notes text,
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now(),
          unique(camera_id,zone_id))""")
        c.execute("""create table if not exists presence_sessions(
          session_id text primary key,
          subject_kind text not null,
          subject_ref text not null,
          zone_id text not null,
          camera_id text,
          entered_at timestamptz not null,
          exited_at timestamptz,
          enter_event_ref text not null,
          exit_event_ref text,
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now())""")
        c.execute("create unique index if not exists presence_sessions_open_idx on presence_sessions(subject_kind,subject_ref,zone_id) where exited_at is null")
        c.execute("create index if not exists presence_sessions_entered_idx on presence_sessions(entered_at desc)")
        c.execute("""create table if not exists presence_observations(
          event_ref text primary key,
          request_hash text not null,
          direction text not null,
          subject_kind text not null,
          subject_ref text not null,
          zone_id text not null,
          camera_id text,
          event_id text,
          occurred_at timestamptz not null,
          session_id text,
          outcome text not null,
          received_at timestamptz not null default now())""")
        c.execute("""create table if not exists unknown_clusters(
          cluster_id text primary key,
          label text not null,
          status text not null default 'open',
          notes text,
          owner_ref text,
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now())""")
        c.execute("""create table if not exists unknown_cluster_events(
          event_id text primary key,
          cluster_id text not null,
          attached_at timestamptz not null default now())""")
        c.execute("create index if not exists unknown_cluster_events_cluster_idx on unknown_cluster_events(cluster_id)")
        c.execute("""create table if not exists review_queues(
          queue_id text primary key,
          name text not null,
          description text,
          status text not null default 'active',
          default_priority text not null default 'normal',
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now())""")
        c.execute("""create table if not exists review_queue_items(
          item_id text primary key,
          queue_id text not null,
          item_type text not null,
          item_ref text not null,
          status text not null default 'open',
          priority text not null default 'normal',
          assignee_ref text,
          notes text,
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now(),
          resolved_at timestamptz,
          unique(queue_id,item_type,item_ref))""")

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
        c.execute("delete from unknown_cluster_events u where not exists (select 1 from events e where e.event_id=u.event_id)")
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
def capabilities(): return {"camera_ingest":["rtsp","onvif"],"recognition":["enroll","verify","search"],"review_workflow":True,"registration_approval":True,"event_snapshots":True,"audit_log":True,"browser_notifications":True,"multi_camera_dashboard":True,"liveness":False,"match_threshold":MATCH_THRESHOLD,"event_retention_days":EVENT_RETENTION_DAYS,"admin_access":"local-only","storage":"postgresql","local_first":True,
    "access_decisions":{"endpoint":"/v1/access/evaluate","decision_only":True,"actuation":False,"fail_closed":True,"audited":True,"schedule_keys":sorted(_SCHEDULE_KEYS)},
    "presence":{"endpoints":["/v1/presence/events","/v1/presence/current","/v1/presence/history"],"idempotency_key":"event_ref","single_open_session_per_subject_zone":True},
    "unknown_clusters":{"endpoint":"/v1/unknown-clusters","identity_assertion":False,"attachable_event_types":["unknown_face"]},
    "camera_zone_mapping":{"endpoint":"/v1/camera-zones","priority":"lower value preferred","stores_camera_credentials":False},
    "review_queues":{"endpoint":"/v1/review-queues","item_types":sorted(_REVIEW_ITEM_TYPES),"priorities":list(_REVIEW_PRIORITIES),"assignee_ref":"opaque","identity_authority":"keycloak","trusts_role_headers":False},
    "middleware_authority":"Caddy -> Kong -> Middleware V3 :8095 -> service API"}
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
    err=_schedule_error(req.schedule)
    if err:
        raise HTTPException(400,err)
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
        presence=c.execute("""select session_id,zone_id,camera_id,entered_at,exited_at from presence_sessions
                              where subject_kind='subject' and subject_ref=%s order by entered_at desc limit 1000""",(subject_id,)).fetchall()
    _audit("privacy.exported","subject",subject_id)
    return {"subject":{"subject_id":s[0],"display_name":s[1],"consent_obtained":s[2],"consent_reference":s[3],
            "retention_days":s[4],"created_at":s[5],"updated_at":s[6],"id_country":s[7],"id_type":s[8],
            "id_last4":s[9],"enrollment_source":s[10],"labels":labels},
            "events":[{"event_id":e[0],"camera_id":e[1],"score":e[2],"event_type":e[3],"occurred_at":e[4],"review_status":e[5]} for e in events],
            "presence_sessions":[{"session_id":p[0],"zone_id":p[1],"camera_id":p[2],"entered_at":p[3],"exited_at":p[4]} for p in presence]}

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
        c.execute("delete from presence_observations where subject_kind='subject' and subject_ref=%s",(subject_id,))
        c.execute("delete from presence_sessions where subject_kind='subject' and subject_ref=%s",(subject_id,))
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
    with conn() as c:
        c.execute("delete from camera_zones where camera_id=%s",(camera_id,))
        c.execute("delete from cameras where camera_id=%s",(camera_id,))
    _audit("camera.deleted","camera",camera_id)
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

# --- Missions 21-25: access decisions, presence, unknown clusters, camera-zones, review queues ---

_REF_RE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
_DAYS=("mon","tue","wed","thu","fri","sat","sun")
_SCHEDULE_KEYS={"days","start","end","timezone"}
_CLUSTER_STATUSES={"open","monitoring","resolved","dismissed"}
_QUEUE_STATUSES={"active","paused","archived"}
_REVIEW_PRIORITIES=("low","normal","high","urgent")
_REVIEW_ITEM_STATUSES={"open","in_progress","resolved","dismissed"}
_REVIEW_ITEM_TYPES={"event":("events","event_id"),"registration":("registration_requests","request_id"),
                    "incident":("incidents","incident_id"),"unknown_cluster":("unknown_clusters","cluster_id")}

def _ref(value, field, required=False):
    """Validate an opaque reference; references are never interpreted as roles or identities."""
    if value is None or (isinstance(value,str) and not value.strip()):
        if required:
            raise HTTPException(400,f"{field} is required")
        return None
    v=value.strip()
    if not _REF_RE.match(v):
        raise HTTPException(400,f"{field} must be an opaque reference of 1-128 characters [A-Za-z0-9._:@-]")
    return v

def _parse_ts(value, field, default_now=False):
    if value is None or not value.strip():
        if default_now:
            return datetime.datetime.now(datetime.timezone.utc)
        raise HTTPException(400,f"{field} is required")
    try:
        ts=datetime.datetime.fromisoformat(value.strip().replace("Z","+00:00"))
    except ValueError:
        raise HTTPException(400,f"{field} must be an ISO-8601 timestamp")
    if ts.tzinfo is None:
        raise HTTPException(400,f"{field} must include a timezone offset")
    return ts

def _hhmm(value):
    try:
        h,m=str(value).split(":")
        h,m=int(h),int(m)
    except ValueError:
        return None
    if not (0<=h<=23 and 0<=m<=59):
        return None
    return h*60+m

def _schedule_error(schedule):
    """Return a validation error for an access-policy schedule, or None. Unknown keys fail closed."""
    if not isinstance(schedule,dict):
        return "schedule must be an object"
    extra=set(schedule)-_SCHEDULE_KEYS
    if extra:
        return "unsupported schedule keys: "+", ".join(sorted(extra))
    days=schedule.get("days")
    if days is not None and (not isinstance(days,list) or not days or any(str(d).lower() not in _DAYS for d in days)):
        return "schedule.days must be a non-empty list of mon,tue,wed,thu,fri,sat,sun"
    if ("start" in schedule)!=("end" in schedule):
        return "schedule.start and schedule.end must be provided together"
    if "start" in schedule:
        start,end=_hhmm(schedule["start"]),_hhmm(schedule["end"])
        if start is None or end is None:
            return "schedule.start and schedule.end must be HH:MM"
        if start==end:
            return "schedule.start and schedule.end must differ"
    if "timezone" in schedule:
        try:
            zoneinfo.ZoneInfo(str(schedule["timezone"]))
        except Exception:
            return "schedule.timezone must be a valid IANA timezone"
    return None

def _schedule_matches(schedule, ts):
    local=ts.astimezone(zoneinfo.ZoneInfo(str(schedule.get("timezone","UTC"))))
    if "days" in schedule and _DAYS[local.weekday()] not in {str(d).lower() for d in schedule["days"]}:
        return False
    if "start" in schedule:
        start,end=_hhmm(schedule["start"]),_hhmm(schedule["end"])
        minute=local.hour*60+local.minute
        return start<=minute<end if start<end else (minute>=start or minute<end)
    return True

def _exists(c, table, column, value):
    return bool(value) and c.execute(f"select 1 from {table} where {column}=%s",(value,)).fetchone() is not None

def _subject_ref(subject_ref, subject_id):
    a=_ref(subject_ref,"subject_ref"); b=_ref(subject_id,"subject_id")
    if a and b and a!=b:
        raise HTTPException(400,"subject_ref and subject_id must match when both are provided")
    return a or b

# Mission 21 - access decisions (decision-only, never actuates hardware)

@app.post("/v1/access/evaluate",tags=["access-decisions"])
def access_evaluate(req:AccessEvaluateIn):
    subject_id=_subject_ref(req.subject_ref,req.subject_id)
    zone_id=_ref(req.zone_id,"zone_id",required=True)
    pass_id=_ref(req.visitor_pass_id,"visitor_pass_id")
    ts=_parse_ts(req.occurred_at,"occurred_at")
    if not subject_id and not pass_id:
        raise HTTPException(400,"subject_ref/subject_id or visitor_pass_id is required")
    reasons=[]; allow_ids=[]; deny_ids=[]; invalid_ids=[]; matched_pass=None
    with conn() as c:
        zone=c.execute("select enabled from zones where zone_id=%s",(zone_id,)).fetchone()
        if not zone: reasons.append("zone_not_found")
        elif not zone[0]: reasons.append("zone_disabled")
        if subject_id and not _exists(c,"subjects","subject_id",subject_id):
            reasons.append("subject_not_found")
        if pass_id:
            vp=c.execute("select status,valid_from,valid_until from visitor_passes where pass_id=%s",(pass_id,)).fetchone()
            if not vp: reasons.append("visitor_pass_not_found")
            elif vp[0]!="active": reasons.append("visitor_pass_inactive")
            elif ts<vp[1]: reasons.append("visitor_pass_not_yet_valid")
            elif ts>=vp[2]: reasons.append("visitor_pass_expired")
            else: matched_pass=pass_id
        if not reasons:
            policies=c.execute("""select policy_id,allowed,schedule from access_policies
                                  where zone_id=%s and enabled=true and (subject_id is null or subject_id=%s)
                                  order by policy_id""",(zone_id,subject_id)).fetchall()
            for policy_id,allowed,schedule in policies:
                if _schedule_error(schedule):
                    invalid_ids.append(policy_id)
                elif _schedule_matches(schedule,ts):
                    (allow_ids if allowed else deny_ids).append(policy_id)
            if invalid_ids: reasons.append("policy_invalid")
            elif deny_ids: reasons.append("policy_denied")
            elif not allow_ids: reasons.append("no_matching_policy")
    allowed=not reasons
    if allowed:
        reasons=["policy_allowed"]+(["visitor_pass_valid"] if matched_pass else [])
    matched=invalid_ids or deny_ids or allow_ids
    decision_id="dec-"+uuid.uuid4().hex[:20]
    result={"decision_id":decision_id,"decision":"allow" if allowed else "deny","allowed":allowed,
            "reason_codes":reasons,"matched_policy_ids":matched,"matched_visitor_pass_id":matched_pass,
            "subject_id":subject_id,"zone_id":zone_id,"visitor_pass_id":pass_id,"occurred_at":ts.isoformat(),
            "decision_only":True,"actuation":"none"}
    _audit("access.evaluated","access_decision",decision_id,{k:result[k] for k in
           ("decision","reason_codes","matched_policy_ids","matched_visitor_pass_id","subject_id","zone_id","visitor_pass_id","occurred_at")})
    return result

# Mission 24 - camera-zone mapping (metadata only; no credentials or stream changes)

def _camera_zone_dict(r):
    return {"mapping_id":r[0],"camera_id":r[1],"zone_id":r[2],"priority":r[3],"enabled":r[4],"notes":r[5],"created_at":r[6],"updated_at":r[7]}
_CAMERA_ZONE_COLS="mapping_id,camera_id,zone_id,priority,enabled,notes,created_at,updated_at"

@app.get("/v1/camera-zones",tags=["camera-zones"])
def list_camera_zones(camera_id:Optional[str]=None, zone_id:Optional[str]=None):
    with conn() as c:
        rows=c.execute(f"""select {_CAMERA_ZONE_COLS} from camera_zones
                           where (%s::text is null or camera_id=%s) and (%s::text is null or zone_id=%s)
                           order by camera_id,priority,zone_id""",(camera_id,camera_id,zone_id,zone_id)).fetchall()
    return [_camera_zone_dict(r) for r in rows]

@app.post("/v1/camera-zones",tags=["camera-zones"])
def save_camera_zone(req:CameraZoneIn):
    camera_id=_ref(req.camera_id,"camera_id",required=True); zone_id=_ref(req.zone_id,"zone_id",required=True)
    with conn() as c:
        if not _exists(c,"cameras","camera_id",camera_id): raise HTTPException(400,"camera_id does not exist")
        if not _exists(c,"zones","zone_id",zone_id): raise HTTPException(400,"zone_id does not exist")
        row=c.execute(f"""insert into camera_zones(mapping_id,camera_id,zone_id,priority,enabled,notes) values(%s,%s,%s,%s,%s,%s)
                          on conflict(camera_id,zone_id) do update set priority=excluded.priority,enabled=excluded.enabled,
                          notes=excluded.notes,updated_at=now()
                          returning {_CAMERA_ZONE_COLS},(xmax=0)""",
                      ("cz-"+uuid.uuid4().hex[:16],camera_id,zone_id,req.priority,req.enabled,req.notes)).fetchone()
    out=_camera_zone_dict(row); out["created"]=row[8]
    _audit("camera_zone.created" if row[8] else "camera_zone.updated","camera_zone",out["mapping_id"],
           {"camera_id":camera_id,"zone_id":zone_id,"priority":req.priority,"enabled":req.enabled})
    return out

@app.patch("/v1/camera-zones/{mapping_id}",tags=["camera-zones"])
def patch_camera_zone(mapping_id:str, req:CameraZonePatch):
    changes=req.model_dump(exclude_unset=True)
    if changes.get("priority",0) is None or changes.get("enabled",False) is None:
        raise HTTPException(400,"priority and enabled cannot be null")
    with conn() as c:
        if not _exists(c,"camera_zones","mapping_id",mapping_id): raise HTTPException(404,"camera-zone mapping not found")
        for k,v in changes.items():
            c.execute(f"update camera_zones set {k}=%s,updated_at=now() where mapping_id=%s",(v,mapping_id))
        row=c.execute(f"select {_CAMERA_ZONE_COLS} from camera_zones where mapping_id=%s",(mapping_id,)).fetchone()
    _audit("camera_zone.updated","camera_zone",mapping_id,{"changes":changes})
    return _camera_zone_dict(row)

@app.delete("/v1/camera-zones/{mapping_id}",tags=["camera-zones"])
def delete_camera_zone(mapping_id:str):
    with conn() as c:
        row=c.execute("delete from camera_zones where mapping_id=%s returning camera_id,zone_id",(mapping_id,)).fetchone()
    if not row: raise HTTPException(404,"camera-zone mapping not found")
    _audit("camera_zone.deleted","camera_zone",mapping_id,{"camera_id":row[0],"zone_id":row[1]})
    return {"mapping_id":mapping_id,"deleted":True}

# Mission 22 - presence sessions and zone occupancy

def _presence_session_dict(r):
    return {"session_id":r[0],"subject_kind":r[1],"subject_ref":r[2],"zone_id":r[3],"camera_id":r[4],"entered_at":r[5],
            "exited_at":r[6],"enter_event_ref":r[7],"exit_event_ref":r[8],"status":"open" if r[6] is None else "closed"}
_PRESENCE_COLS="session_id,subject_kind,subject_ref,zone_id,camera_id,entered_at,exited_at,enter_event_ref,exit_event_ref"

@app.post("/v1/presence/events",tags=["presence"])
def presence_event(req:PresenceEventIn):
    event_ref=_ref(req.event_ref,"event_ref",required=True)
    direction=req.direction.strip().lower()
    if direction not in {"enter","exit"}:
        raise HTTPException(400,"direction must be enter or exit")
    request_hash=hashlib.sha256(json.dumps(req.model_dump(),sort_keys=True).encode()).hexdigest()
    with conn() as c:
        prior=c.execute("select request_hash,session_id,outcome,direction,subject_kind,subject_ref,zone_id,camera_id,occurred_at from presence_observations where event_ref=%s",(event_ref,)).fetchone()
        if prior:
            if prior[0]!=request_hash:
                raise HTTPException(409,"event_ref already recorded with a different payload")
            return {"event_ref":event_ref,"session_id":prior[1],"outcome":prior[2],"direction":prior[3],"subject_kind":prior[4],
                    "subject_ref":prior[5],"zone_id":prior[6],"camera_id":prior[7],"occurred_at":prior[8],"idempotent_replay":True}
        subject_id=_subject_ref(req.subject_ref,req.subject_id)
        pass_id=_ref(req.visitor_pass_id,"visitor_pass_id")
        event_id=_ref(req.event_id,"event_id")
        camera_id=_ref(req.camera_id,"camera_id")
        zone_id=_ref(req.zone_id,"zone_id")
        ts=_parse_ts(req.occurred_at,"occurred_at",default_now=True)
        if event_id:
            ev=c.execute("select camera_id,coalesce(reviewed_subject_id,subject_id) from events where event_id=%s",(event_id,)).fetchone()
            if not ev: raise HTTPException(400,"event_id does not exist")
            camera_id=camera_id or ev[0]
            if not subject_id and not pass_id: subject_id=ev[1]
        if subject_id and pass_id:
            raise HTTPException(400,"provide either a subject reference or visitor_pass_id, not both")
        if subject_id:
            if not _exists(c,"subjects","subject_id",subject_id): raise HTTPException(400,"subject reference does not exist")
            kind,subject=("subject",subject_id)
        elif pass_id:
            if not _exists(c,"visitor_passes","pass_id",pass_id): raise HTTPException(400,"visitor_pass_id does not exist")
            kind,subject=("visitor_pass",pass_id)
        else:
            raise HTTPException(400,"a subject reference, visitor_pass_id, or attributed event_id is required")
        if camera_id and not _exists(c,"cameras","camera_id",camera_id): raise HTTPException(400,"camera_id does not exist")
        if zone_id:
            if not _exists(c,"zones","zone_id",zone_id): raise HTTPException(400,"zone_id does not exist")
            if camera_id and not c.execute("select 1 from camera_zones where camera_id=%s and zone_id=%s and enabled=true",(camera_id,zone_id)).fetchone():
                raise HTTPException(400,"camera_id is not mapped to zone_id")
        elif camera_id:
            m=c.execute("select zone_id from camera_zones where camera_id=%s and enabled=true order by priority,zone_id limit 1",(camera_id,)).fetchone()
            if not m: raise HTTPException(400,"camera_id has no enabled zone mapping")
            zone_id=m[0]
        else:
            raise HTTPException(400,"zone_id or a mapped camera_id is required")
        open_row=c.execute("select session_id,entered_at from presence_sessions where subject_kind=%s and subject_ref=%s and zone_id=%s and exited_at is null for update",
                           (kind,subject,zone_id)).fetchone()
        session_id=open_row[0] if open_row else None
        if direction=="enter":
            if open_row:
                outcome="already_present"
            else:
                session_id="ps-"+uuid.uuid4().hex[:20]
                inserted=c.execute("""insert into presence_sessions(session_id,subject_kind,subject_ref,zone_id,camera_id,entered_at,enter_event_ref)
                                      values(%s,%s,%s,%s,%s,%s,%s) on conflict do nothing returning session_id""",
                                   (session_id,kind,subject,zone_id,camera_id,ts,event_ref)).fetchone()
                if inserted:
                    outcome="session_opened"
                else:
                    session_id=c.execute("select session_id from presence_sessions where subject_kind=%s and subject_ref=%s and zone_id=%s and exited_at is null",
                                         (kind,subject,zone_id)).fetchone()[0]
                    outcome="already_present"
        elif not open_row:
            outcome="no_open_session"
        elif ts<open_row[1]:
            outcome="exit_before_entry_ignored"
        else:
            c.execute("update presence_sessions set exited_at=%s,exit_event_ref=%s,updated_at=now() where session_id=%s",(ts,event_ref,session_id))
            outcome="session_closed"
        inserted=c.execute("""insert into presence_observations(event_ref,request_hash,direction,subject_kind,subject_ref,zone_id,camera_id,event_id,occurred_at,session_id,outcome)
                              values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) on conflict(event_ref) do nothing returning event_ref""",
                           (event_ref,request_hash,direction,kind,subject,zone_id,camera_id,event_id,ts,session_id,outcome)).fetchone()
        if not inserted:
            raise HTTPException(409,"event_ref was recorded concurrently; retry to read the stored result")
    _audit("presence.observed","presence_observation",event_ref,{"direction":direction,"subject_kind":kind,"subject_ref":subject,
           "zone_id":zone_id,"camera_id":camera_id,"session_id":session_id,"outcome":outcome})
    return {"event_ref":event_ref,"session_id":session_id,"outcome":outcome,"direction":direction,"subject_kind":kind,
            "subject_ref":subject,"zone_id":zone_id,"camera_id":camera_id,"occurred_at":ts,"idempotent_replay":False}

@app.get("/v1/presence/current",tags=["presence"])
def presence_current(zone_id:Optional[str]=None):
    with conn() as c:
        rows=c.execute(f"""select {_PRESENCE_COLS} from presence_sessions where exited_at is null and (%s::text is null or zone_id=%s)
                           order by zone_id,entered_at""",(zone_id,zone_id)).fetchall()
        zones=c.execute("select zone_id,name,enabled from zones where (%s::text is null or zone_id=%s) order by zone_id",(zone_id,zone_id)).fetchall()
    counts={}
    for r in rows: counts[r[3]]=counts.get(r[3],0)+1
    return {"occupancy":[{"zone_id":z[0],"name":z[1],"enabled":z[2],"count":counts.get(z[0],0)} for z in zones],
            "total":len(rows),"sessions":[_presence_session_dict(r) for r in rows]}

@app.get("/v1/presence/history",tags=["presence"])
def presence_history(zone_id:Optional[str]=None, subject_ref:Optional[str]=None, since:Optional[str]=None, until:Optional[str]=None,
                     status:str="all", limit:int=200):
    if status not in {"all","open","closed"}: raise HTTPException(400,"status must be all, open, or closed")
    since_ts=_parse_ts(since,"since") if since else None
    until_ts=_parse_ts(until,"until") if until else None
    limit=max(1,min(limit,1000))
    with conn() as c:
        rows=c.execute(f"""select {_PRESENCE_COLS} from presence_sessions
                           where (%s::text is null or zone_id=%s) and (%s::text is null or subject_ref=%s)
                           and (%s::timestamptz is null or entered_at>=%s) and (%s::timestamptz is null or entered_at<%s)
                           and (%s='all' or (%s='open' and exited_at is null) or (%s='closed' and exited_at is not null))
                           order by entered_at desc limit %s""",
                       (zone_id,zone_id,subject_ref,subject_ref,since_ts,since_ts,until_ts,until_ts,status,status,status,limit)).fetchall()
    return [_presence_session_dict(r) for r in rows]

# Mission 23 - operator-owned unknown clusters. A cluster label is an operator note,
# NOT a real-world identity: clusters never carry subject_id and never assert who someone is.

def _cluster_dict(r, event_count=None):
    out={"cluster_id":r[0],"label":r[1],"status":r[2],"notes":r[3],"owner_ref":r[4],"created_at":r[5],"updated_at":r[6],
         "identity_asserted":False}
    if event_count is not None: out["event_count"]=event_count
    return out
_CLUSTER_COLS="cluster_id,label,status,notes,owner_ref,created_at,updated_at"

def _cluster_or_404(c, cluster_id):
    row=c.execute(f"select {_CLUSTER_COLS} from unknown_clusters where cluster_id=%s",(cluster_id,)).fetchone()
    if not row: raise HTTPException(404,"unknown cluster not found")
    return row

@app.get("/v1/unknown-clusters",tags=["unknown-clusters"])
def list_unknown_clusters(status:str="all"):
    with conn() as c:
        rows=c.execute(f"""select {",".join("u."+x for x in _CLUSTER_COLS.split(","))},count(e.event_id)
                           from unknown_clusters u left join unknown_cluster_events e on e.cluster_id=u.cluster_id
                           where (%s='all' or u.status=%s) group by u.cluster_id order by u.updated_at desc""",(status,status)).fetchall()
    return [_cluster_dict(r,r[7]) for r in rows]

@app.post("/v1/unknown-clusters",tags=["unknown-clusters"])
def create_unknown_cluster(req:UnknownClusterIn):
    cluster_id=_ref(req.cluster_id,"cluster_id") or "uc-"+uuid.uuid4().hex[:16]
    if req.status not in _CLUSTER_STATUSES: raise HTTPException(400,"unsupported cluster status")
    owner_ref=_ref(req.owner_ref,"owner_ref")
    with conn() as c:
        row=c.execute(f"""insert into unknown_clusters(cluster_id,label,status,notes,owner_ref) values(%s,%s,%s,%s,%s)
                          on conflict(cluster_id) do nothing returning {_CLUSTER_COLS}""",
                      (cluster_id,req.label.strip(),req.status,req.notes,owner_ref)).fetchone()
    if not row: raise HTTPException(409,"cluster_id already exists; use PATCH to update it")
    _audit("unknown_cluster.created","unknown_cluster",cluster_id,{"label":row[1],"status":row[2],"owner_ref":owner_ref})
    return _cluster_dict(row,0)

@app.get("/v1/unknown-clusters/{cluster_id}",tags=["unknown-clusters"])
def get_unknown_cluster(cluster_id:str):
    with conn() as c:
        row=_cluster_or_404(c,cluster_id)
        evs=c.execute("""select e.event_id,e.camera_id,e.occurred_at,e.review_status,e.snapshot_path is not null,u.attached_at
                         from unknown_cluster_events u join events e on e.event_id=u.event_id
                         where u.cluster_id=%s order by e.occurred_at desc""",(cluster_id,)).fetchall()
    out=_cluster_dict(row,len(evs))
    out["events"]=[{"event_id":e[0],"camera_id":e[1],"occurred_at":e[2],"review_status":e[3],"has_snapshot":e[4],"attached_at":e[5]} for e in evs]
    return out

@app.patch("/v1/unknown-clusters/{cluster_id}",tags=["unknown-clusters"])
def patch_unknown_cluster(cluster_id:str, req:UnknownClusterPatch):
    changes=req.model_dump(exclude_unset=True)
    if "label" in changes:
        if changes["label"] is None or not changes["label"].strip(): raise HTTPException(400,"label cannot be empty")
        changes["label"]=changes["label"].strip()
    if "status" in changes and changes["status"] not in _CLUSTER_STATUSES: raise HTTPException(400,"unsupported cluster status")
    if "owner_ref" in changes: changes["owner_ref"]=_ref(changes["owner_ref"],"owner_ref")
    with conn() as c:
        _cluster_or_404(c,cluster_id)
        for k,v in changes.items():
            c.execute(f"update unknown_clusters set {k}=%s,updated_at=now() where cluster_id=%s",(v,cluster_id))
        row=_cluster_or_404(c,cluster_id)
    _audit("unknown_cluster.updated","unknown_cluster",cluster_id,{"changes":changes})
    return _cluster_dict(row)

@app.post("/v1/unknown-clusters/{cluster_id}/events",tags=["unknown-clusters"])
def attach_cluster_events(cluster_id:str, req:ClusterEventsIn):
    event_ids=list(dict.fromkeys(_ref(x,"event_id",required=True) for x in req.event_ids))
    with conn() as c:
        _cluster_or_404(c,cluster_id)
        found={r[0]:r[1] for r in c.execute("select event_id,event_type from events where event_id = any(%s)",(event_ids,)).fetchall()}
        if any(x not in found for x in event_ids): raise HTTPException(400,"one or more event_ids do not exist")
        if any(found[x]!="unknown_face" for x in event_ids): raise HTTPException(400,"only unknown_face events can be attached to unknown clusters")
        owners={r[0]:r[1] for r in c.execute("select event_id,cluster_id from unknown_cluster_events where event_id = any(%s)",(event_ids,)).fetchall()}
        if any(v!=cluster_id for v in owners.values()): raise HTTPException(409,"one or more events are already attached to another cluster")
        attached=[x for x in event_ids if x not in owners]
        for x in attached:
            c.execute("insert into unknown_cluster_events(event_id,cluster_id) values(%s,%s)",(x,cluster_id))
        if attached: c.execute("update unknown_clusters set updated_at=now() where cluster_id=%s",(cluster_id,))
    if attached: _audit("unknown_cluster.events_attached","unknown_cluster",cluster_id,{"event_ids":attached})
    return {"cluster_id":cluster_id,"attached":attached,"already_attached":[x for x in event_ids if x in owners]}

@app.delete("/v1/unknown-clusters/{cluster_id}/events/{event_id}",tags=["unknown-clusters"])
def detach_cluster_event(cluster_id:str, event_id:str):
    with conn() as c:
        _cluster_or_404(c,cluster_id)
        if not c.execute("delete from unknown_cluster_events where cluster_id=%s and event_id=%s returning event_id",(cluster_id,event_id)).fetchone():
            raise HTTPException(404,"event is not attached to this cluster")
        c.execute("update unknown_clusters set updated_at=now() where cluster_id=%s",(cluster_id,))
    _audit("unknown_cluster.event_detached","unknown_cluster",cluster_id,{"event_id":event_id})
    return {"cluster_id":cluster_id,"event_id":event_id,"detached":True}

# Mission 25 - review queues. assignee_ref is an opaque reference; Keycloak remains the identity authority
# and no request header is trusted as a role or user assertion.

_QUEUE_COLS="queue_id,name,description,status,default_priority,created_at,updated_at"
_ITEM_COLS="item_id,queue_id,item_type,item_ref,status,priority,assignee_ref,notes,created_at,updated_at,resolved_at"
_PRIORITY_ORDER="case priority when 'urgent' then 0 when 'high' then 1 when 'normal' then 2 else 3 end"

def _queue_dict(r):
    return {"queue_id":r[0],"name":r[1],"description":r[2],"status":r[3],"default_priority":r[4],"created_at":r[5],"updated_at":r[6]}

def _item_dict(r):
    return {"item_id":r[0],"queue_id":r[1],"item_type":r[2],"item_ref":r[3],"status":r[4],"priority":r[5],"assignee_ref":r[6],
            "notes":r[7],"created_at":r[8],"updated_at":r[9],"resolved_at":r[10]}

def _queue_or_404(c, queue_id):
    row=c.execute(f"select {_QUEUE_COLS} from review_queues where queue_id=%s",(queue_id,)).fetchone()
    if not row: raise HTTPException(404,"review queue not found")
    return row

def _check_priority(p):
    if p not in _REVIEW_PRIORITIES: raise HTTPException(400,"priority must be one of low, normal, high, urgent")

@app.get("/v1/review-queues",tags=["review-queues"])
def list_review_queues(status:str="all"):
    with conn() as c:
        rows=c.execute(f"""select {",".join("q."+x for x in _QUEUE_COLS.split(","))},
                           count(i.item_id) filter (where i.status in ('open','in_progress'))
                           from review_queues q left join review_queue_items i on i.queue_id=q.queue_id
                           where (%s='all' or q.status=%s) group by q.queue_id order by q.name""",(status,status)).fetchall()
    return [{**_queue_dict(r),"open_items":r[7]} for r in rows]

@app.post("/v1/review-queues",tags=["review-queues"])
def create_review_queue(req:ReviewQueueIn):
    queue_id=_ref(req.queue_id,"queue_id",required=True)
    if req.status not in _QUEUE_STATUSES: raise HTTPException(400,"status must be active, paused, or archived")
    _check_priority(req.default_priority)
    with conn() as c:
        row=c.execute(f"""insert into review_queues(queue_id,name,description,status,default_priority) values(%s,%s,%s,%s,%s)
                          on conflict(queue_id) do nothing returning {_QUEUE_COLS}""",
                      (queue_id,req.name.strip(),req.description,req.status,req.default_priority)).fetchone()
    if not row: raise HTTPException(409,"queue_id already exists; use PATCH to update it")
    _audit("review_queue.created","review_queue",queue_id,{"name":row[1],"status":row[3]})
    return _queue_dict(row)

@app.get("/v1/review-queues/{queue_id}",tags=["review-queues"])
def get_review_queue(queue_id:str):
    with conn() as c:
        row=_queue_or_404(c,queue_id)
        counts=dict(c.execute("select status,count(*) from review_queue_items where queue_id=%s group by status",(queue_id,)).fetchall())
    return {**_queue_dict(row),"item_counts":counts}

@app.patch("/v1/review-queues/{queue_id}",tags=["review-queues"])
def patch_review_queue(queue_id:str, req:ReviewQueuePatch):
    changes=req.model_dump(exclude_unset=True)
    if "name" in changes and (changes["name"] is None or not changes["name"].strip()): raise HTTPException(400,"name cannot be empty")
    if "status" in changes and changes["status"] not in _QUEUE_STATUSES: raise HTTPException(400,"status must be active, paused, or archived")
    if "default_priority" in changes: _check_priority(changes["default_priority"])
    with conn() as c:
        _queue_or_404(c,queue_id)
        for k,v in changes.items():
            c.execute(f"update review_queues set {k}=%s,updated_at=now() where queue_id=%s",(v,queue_id))
        row=_queue_or_404(c,queue_id)
    _audit("review_queue.updated","review_queue",queue_id,{"changes":changes})
    return _queue_dict(row)

@app.delete("/v1/review-queues/{queue_id}",tags=["review-queues"])
def delete_review_queue(queue_id:str):
    with conn() as c:
        _queue_or_404(c,queue_id)
        if c.execute("select 1 from review_queue_items where queue_id=%s limit 1",(queue_id,)).fetchone():
            raise HTTPException(409,"queue has items; archive it with PATCH status=archived instead")
        c.execute("delete from review_queues where queue_id=%s",(queue_id,))
    _audit("review_queue.deleted","review_queue",queue_id)
    return {"queue_id":queue_id,"deleted":True}

@app.get("/v1/review-queues/{queue_id}/items",tags=["review-queues"])
def list_review_items(queue_id:str, status:str="all", assignee_ref:Optional[str]=None, priority:Optional[str]=None, limit:int=200):
    limit=max(1,min(limit,1000))
    with conn() as c:
        _queue_or_404(c,queue_id)
        rows=c.execute(f"""select {_ITEM_COLS} from review_queue_items
                           where queue_id=%s and (%s='all' or status=%s) and (%s::text is null or assignee_ref=%s)
                           and (%s::text is null or priority=%s)
                           order by {_PRIORITY_ORDER},created_at limit %s""",
                       (queue_id,status,status,assignee_ref,assignee_ref,priority,priority,limit)).fetchall()
    return [_item_dict(r) for r in rows]

@app.post("/v1/review-queues/{queue_id}/items",tags=["review-queues"])
def create_review_item(queue_id:str, req:ReviewItemIn):
    if req.item_type not in _REVIEW_ITEM_TYPES: raise HTTPException(400,"item_type must be one of "+", ".join(sorted(_REVIEW_ITEM_TYPES)))
    item_ref=_ref(req.item_ref,"item_ref",required=True)
    assignee_ref=_ref(req.assignee_ref,"assignee_ref")
    with conn() as c:
        queue=_queue_or_404(c,queue_id)
        if queue[3]=="archived": raise HTTPException(409,"queue is archived")
        priority=req.priority or queue[4]
        _check_priority(priority)
        table,column=_REVIEW_ITEM_TYPES[req.item_type]
        if not _exists(c,table,column,item_ref): raise HTTPException(400,f"{req.item_type} reference does not exist")
        row=c.execute(f"""insert into review_queue_items(item_id,queue_id,item_type,item_ref,priority,assignee_ref,notes)
                          values(%s,%s,%s,%s,%s,%s,%s) on conflict(queue_id,item_type,item_ref) do nothing returning {_ITEM_COLS}""",
                      ("rqi-"+uuid.uuid4().hex[:16],queue_id,req.item_type,item_ref,priority,assignee_ref,req.notes)).fetchone()
        created=row is not None
        if not created:
            row=c.execute(f"select {_ITEM_COLS} from review_queue_items where queue_id=%s and item_type=%s and item_ref=%s",
                          (queue_id,req.item_type,item_ref)).fetchone()
    if created: _audit("review_item.created","review_queue_item",row[0],{"queue_id":queue_id,"item_type":req.item_type,"item_ref":item_ref,"priority":priority,"assignee_ref":assignee_ref})
    return {**_item_dict(row),"created":created}

@app.get("/v1/review-queues/{queue_id}/items/{item_id}",tags=["review-queues"])
def get_review_item(queue_id:str, item_id:str):
    with conn() as c:
        row=c.execute(f"select {_ITEM_COLS} from review_queue_items where queue_id=%s and item_id=%s",(queue_id,item_id)).fetchone()
    if not row: raise HTTPException(404,"review item not found")
    return _item_dict(row)

@app.patch("/v1/review-queues/{queue_id}/items/{item_id}",tags=["review-queues"])
def patch_review_item(queue_id:str, item_id:str, req:ReviewItemPatch):
    changes=req.model_dump(exclude_unset=True)
    if "status" in changes and changes["status"] not in _REVIEW_ITEM_STATUSES: raise HTTPException(400,"status must be open, in_progress, resolved, or dismissed")
    if "priority" in changes: _check_priority(changes["priority"])
    if "assignee_ref" in changes: changes["assignee_ref"]=_ref(changes["assignee_ref"],"assignee_ref")
    with conn() as c:
        if not c.execute("select 1 from review_queue_items where queue_id=%s and item_id=%s",(queue_id,item_id)).fetchone():
            raise HTTPException(404,"review item not found")
        for k,v in changes.items():
            c.execute(f"update review_queue_items set {k}=%s,updated_at=now() where item_id=%s",(v,item_id))
        if "status" in changes:
            c.execute("update review_queue_items set resolved_at=case when status in ('resolved','dismissed') then now() else null end where item_id=%s",(item_id,))
        row=c.execute(f"select {_ITEM_COLS} from review_queue_items where item_id=%s",(item_id,)).fetchone()
    _audit("review_item.updated","review_queue_item",item_id,{"queue_id":queue_id,"changes":changes})
    return _item_dict(row)
