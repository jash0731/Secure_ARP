import http.client
import json
import threading

import pytest

from secure_arp.config import Config
from secure_arp.engine import MonitorEngine
from secure_arp.web import DashboardServer


@pytest.fixture
def server(tmp_path):
    config = Config(database_path=str(tmp_path / "web.sqlite3"),
                    log_path=str(tmp_path / "events.jsonl"), report_dir=str(tmp_path / "reports"))
    service = DashboardServer(("127.0.0.1", 0), config, demo=True)
    worker = threading.Thread(target=service.serve_forever, daemon=True)
    worker.start()
    yield service
    service.shutdown()
    worker.join(timeout=3)
    service.server_close()


def request(server, method, path, payload=None, token=True, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    supplied = headers or {}
    if token:
        supplied["X-CSRF-Token"] = server.csrf_token
    body = json.dumps(payload) if payload is not None else None
    if body is not None:
        supplied["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body, supplied)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def test_dashboard_assets_and_empty_state(server):
    status, headers, body = request(server, "GET", "/")
    assert status == 200
    assert server.csrf_token.encode() in body
    assert b"Your network, in focus." in body
    assert headers["X-Frame-Options"] == "DENY"
    assert request(server, "GET", "/app.js")[0] == 200
    assert request(server, "GET", "/style.css")[0] == 200
    data = json.loads(request(server, "GET", "/api/state")[2])
    assert data["summary"]["events"] == 0
    assert data["demo"]


def test_device_approval_requires_csrf_and_valid_origin(server):
    payload = {"ip": "192.0.2.5", "mac": "02:00:00:00:00:05", "label": "Lab laptop"}
    assert request(server, "POST", "/api/devices/approve", payload, token=False)[0] == 403
    assert request(server, "POST", "/api/devices/approve", payload,
                   headers={"Origin": "https://example.invalid"})[0] == 403
    assert request(server, "POST", "/api/devices/approve", payload)[0] == 200
    device = json.loads(request(server, "GET", "/api/state")[2])["devices"][0]
    assert device["label"] == "Lab laptop"
    assert device["approved"]
    assert request(server, "POST", "/api/devices/revoke", {"ip": "192.0.2.5"})[0] == 200
    assert not json.loads(request(server, "GET", "/api/state")[2])["devices"][0]["approved"]


def test_host_rebinding_and_invalid_device_rejected(server):
    assert request(server, "GET", "/", headers={"Host": "example.invalid"})[0] == 403
    assert request(server, "POST", "/api/devices/approve",
                   {"ip": "not an IP", "mac": "no MAC"})[0] == 400
    assert request(server, "GET", "/api/state?from=invalid")[0] == 400
    assert request(server, "GET", "/../../config.json")[0] == 404


def test_demo_filtering_notifications_and_exports(server):
    result = json.loads(request(server, "POST", "/api/demo", {})[2])
    assert result["new_events"] > 0
    state = json.loads(request(server, "GET", "/api/state?since_id=0")[2])
    assert state["notifications"]
    cursor = state["cursor"]
    assert json.loads(request(server, "GET", f"/api/state?since_id={cursor}")[2])["notifications"] == []
    filtered = json.loads(request(server, "GET", "/api/state?type=REPLAY_SUSPECTED")[2])
    assert filtered["summary"]["events"] == 1
    status, headers, content = request(server, "GET", "/api/export.csv?type=REPLAY_SUSPECTED")
    assert status == 200
    assert len(content.decode("utf-8-sig").splitlines()) == 2
    assert "attachment" in headers["Content-Disposition"]
    report = request(server, "GET", "/api/report.html?severity=CRITICAL")[2].decode()
    assert "REPLAY_SUSPECTED" in report
    assert "ARP_REPLY_FLOOD" not in report


def test_live_workspace_has_no_demo_mutation(server):
    server.demo = False
    assert request(server, "POST", "/api/demo", {})[0] == 403
    assert server.repository.summary()["packets"] == 0


def test_unapproved_conflict_remains_after_refresh_and_approval_resolves_it(server):
    engine = MonitorEngine(server.config, server.repository)
    engine.process("192.0.2.7", "02:00:00:00:00:07")
    engine.process("192.0.2.7", "02:00:00:00:00:77")
    state = json.loads(request(server, "GET", "/api/state?q=192.0.2.7")[2])
    assert state["summary"]["critical"] == 1
    assert any(device["conflict"] for device in state["devices"])
    request(server, "POST", "/api/devices/approve",
            {"ip": "192.0.2.7", "mac": "02:00:00:00:00:77", "label": "Replacement"})
    assert engine.process("192.0.2.7", "02:00:00:00:00:77") == []
