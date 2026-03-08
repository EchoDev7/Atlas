import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock

from backend.models.vpn_user import VPNUser
from backend.services.scheduler_service import LimitEnforcementScheduler, OpenVPNConfig


class _DummyQuery:
    def __init__(self, users):
        self._users = users

    def filter(self, *args, **kwargs):
        return self

    def all(self):
        return self._users


class _DummySession:
    def __init__(self, users, call_order=None):
        self._users = users
        self.call_order = call_order if call_order is not None else []
        self.commit_count = 0
        self.rollback_count = 0
        self.close_count = 0

    def query(self, _model):
        return _DummyQuery(self._users)

    def commit(self):
        self.commit_count += 1
        self.call_order.append("commit")

    def rollback(self):
        self.rollback_count += 1

    def close(self):
        self.close_count += 1


def _build_user(
    username="alice",
    *,
    traffic_limit_bytes=1_000,
    traffic_used_bytes=0,
    total_bytes_sent=0,
    total_bytes_received=0,
    access_expires_at=None,
):
    return VPNUser(
        username=username,
        password="hashed",
        is_enabled=True,
        max_devices=1,
        max_concurrent_connections=1,
        current_connections=0,
        traffic_limit_bytes=traffic_limit_bytes,
        traffic_used_bytes=traffic_used_bytes,
        total_bytes_sent=total_bytes_sent,
        total_bytes_received=total_bytes_received,
        access_expires_at=access_expires_at,
    )


def test_live_enforcement_quota_updates_before_kill(monkeypatch):
    scheduler = LimitEnforcementScheduler()
    user = _build_user(total_bytes_sent=100, total_bytes_received=50, traffic_used_bytes=10)

    call_order = []
    session = _DummySession([user], call_order)

    monkeypatch.setattr("backend.services.scheduler_service.SessionLocal", lambda: session)
    monkeypatch.setattr(
        scheduler,
        "_get_openvpn_runtime_stats",
        lambda: {
            "alice": {
                "connections": 1,
                "bytes_sent": 700,
                "bytes_received": 300,
            }
        },
    )

    def _sync_side_effect():
        call_order.append("sync")

    monkeypatch.setattr(scheduler, "_sync_openvpn_auth_db_snapshot", _sync_side_effect)

    def _kill_side_effect(username):
        call_order.append("kill")
        return {"success": True, "message": f"killed {username}"}

    kill_mock = Mock(side_effect=_kill_side_effect)
    monkeypatch.setattr(scheduler.openvpn_manager, "kill_user", kill_mock)

    asyncio.run(scheduler.enforce_live_traffic_quotas())

    assert session.commit_count == 1
    assert kill_mock.call_count == 1
    assert call_order[:3] == ["commit", "sync", "kill"]
    assert user.is_enabled is False
    assert user.is_data_limit_exceeded is True
    assert user.traffic_used_bytes >= 1_000


def test_live_enforcement_respects_kill_cooldown(monkeypatch):
    scheduler = LimitEnforcementScheduler()
    user = _build_user(total_bytes_sent=200, total_bytes_received=200, traffic_used_bytes=0)
    session = _DummySession([user])

    monkeypatch.setattr("backend.services.scheduler_service.SessionLocal", lambda: session)
    monkeypatch.setattr(
        scheduler,
        "_get_openvpn_runtime_stats",
        lambda: {
            "alice": {
                "connections": 1,
                "bytes_sent": 700,
                "bytes_received": 700,
            }
        },
    )
    monkeypatch.setattr(scheduler, "_sync_openvpn_auth_db_snapshot", lambda: None)

    kill_mock = Mock(return_value={"success": True, "message": "ok"})
    monkeypatch.setattr(scheduler.openvpn_manager, "kill_user", kill_mock)

    asyncio.run(scheduler.enforce_live_traffic_quotas())
    asyncio.run(scheduler.enforce_live_traffic_quotas())

    assert kill_mock.call_count == 1
    assert session.commit_count == 1


def test_live_enforcement_kills_expired_user(monkeypatch):
    scheduler = LimitEnforcementScheduler()
    expired_at = datetime.utcnow() - timedelta(minutes=5)
    user = _build_user(
        traffic_limit_bytes=None,
        access_expires_at=expired_at,
        total_bytes_sent=10,
        total_bytes_received=10,
    )
    session = _DummySession([user])

    monkeypatch.setattr("backend.services.scheduler_service.SessionLocal", lambda: session)
    monkeypatch.setattr(
        scheduler,
        "_get_openvpn_runtime_stats",
        lambda: {"alice": {"connections": 1, "bytes_sent": 1, "bytes_received": 1}},
    )
    monkeypatch.setattr(scheduler, "_sync_openvpn_auth_db_snapshot", lambda: None)

    kill_mock = Mock(return_value={"success": True, "message": "ok"})
    monkeypatch.setattr(scheduler.openvpn_manager, "kill_user", kill_mock)

    asyncio.run(scheduler.enforce_live_traffic_quotas())

    assert kill_mock.call_count == 1
    assert user.is_enabled is False
    assert user.disabled_reason
    assert "expired" in user.disabled_reason.lower()


def test_status_parser_supports_tab_and_comma_delimiters(monkeypatch, tmp_path):
    scheduler = LimitEnforcementScheduler()
    status_file = tmp_path / "status-server.log"
    status_file.write_text(
        "\n".join(
            [
                "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Bytes Received,Bytes Sent,Connected Since",
                "CLIENT_LIST\talice\t10.0.0.1:1111\t10.8.0.2\t300\t700\tFri Mar  6 10:00:00 2026",
                "CLIENT_LIST,alice,10.0.0.2:2222,10.8.0.3,100,200,Fri Mar  6 10:01:00 2026",
                "CLIENT_LIST,bob,10.0.0.3:3333,10.8.0.4,50,60,Fri Mar  6 10:02:00 2026",
            ]
        )
    )

    monkeypatch.setattr(OpenVPNConfig, "STATUS_LOG", status_file)

    stats = scheduler._parse_openvpn_status_runtime_stats()

    assert stats["alice"]["connections"] == 2
    assert stats["alice"]["bytes_received"] == 400
    assert stats["alice"]["bytes_sent"] == 900
    assert stats["bob"]["connections"] == 1
    assert stats["bob"]["bytes_received"] == 50
    assert stats["bob"]["bytes_sent"] == 60
