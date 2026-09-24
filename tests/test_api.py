from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)
def test_health(): assert client.get("/healthz").json()["status"]=="ok"
def test_capabilities(): assert "rtsp" in client.get("/v1/capabilities").json()["camera_protocols"]
