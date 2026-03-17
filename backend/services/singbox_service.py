from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import quote, urlencode

from backend.models.general_settings import GeneralSettings
from backend.models.hysteria_inbound import HysteriaInbound
from backend.models.shadowsocks_inbound import ShadowsocksInbound
from backend.models.trojan_inbound import TrojanInbound
from backend.models.tuic_inbound import TuicInbound
from backend.models.vless_inbound import VlessInbound
from backend.models.vpn_user import VPNUser
from backend.services.protocols.base import BaseProtocolService


class SingBoxService(BaseProtocolService):
    """Protocol adapter for sing-box core runtime."""

    protocol_name = "singbox"
    service_name = "sing-box"
    config_path = Path("/usr/local/etc/sing-box/config.json")
    _allowed_log_levels = {"trace", "debug", "info", "warn", "error", "fatal"}

    def start_client(self, db: Any, username: str) -> Dict[str, Any]:
        _ = db
        normalized_username = str(username or "").strip()
        if not normalized_username:
            return {"success": False, "protocol": self.protocol_name, "message": "Missing username"}
        return {
            "success": True,
            "protocol": self.protocol_name,
            "username": normalized_username,
            "message": "Sing-box client runtime is protocol-specific and not enabled in Phase 1",
        }

    def stop_client(self, username: str) -> Dict[str, Any]:
        normalized_username = str(username or "").strip()
        if not normalized_username:
            return {"success": False, "protocol": self.protocol_name, "message": "Missing username"}
        return {
            "success": True,
            "protocol": self.protocol_name,
            "username": normalized_username,
            "message": "Sing-box client runtime disconnect is not enabled in Phase 1",
        }

    def get_status(self, db: Optional[Any] = None) -> Dict[str, Any]:
        _ = db
        if shutil.which("systemctl") is None:
            return {
                "success": False,
                "protocol": self.protocol_name,
                "service_name": self.service_name,
                "message": "systemctl is not available",
            }

        active = subprocess.run(
            ["systemctl", "is-active", self.service_name],
            capture_output=True,
            text=True,
            check=False,
        )
        enabled = subprocess.run(
            ["systemctl", "is-enabled", self.service_name],
            capture_output=True,
            text=True,
            check=False,
        )
        return {
            "success": True,
            "protocol": self.protocol_name,
            "service_name": self.service_name,
            "is_active": active.returncode == 0 and active.stdout.strip().lower() == "active",
            "is_enabled": enabled.returncode == 0 and enabled.stdout.strip().lower() in {"enabled", "static", "indirect", "generated"},
        }

    async def enforce_limits(self, db: Any) -> Dict[str, Any]:
        _ = db
        return {
            "success": True,
            "protocol": self.protocol_name,
            "message": "Sing-box enforcement is delegated to future protocol adapters",
        }

    def _parse_port(self, raw_port: Any, fallback: int) -> int:
        text = str(raw_port or "").strip()
        if not text:
            return fallback
        try:
            port = int(text)
        except ValueError:
            if "-" in text:
                start_part = text.split("-", 1)[0].strip()
                try:
                    port = int(start_part)
                except ValueError:
                    return fallback
            else:
                return fallback
        if port < 1 or port > 65535:
            return fallback
        return port

    def _split_alpn(self, raw_alpn: Any, fallback: list[str]) -> list[str]:
        value = str(raw_alpn or "").strip()
        if not value:
            return list(fallback)
        parts = [item.strip() for item in value.split(",") if item.strip()]
        return parts or list(fallback)

    def _build_tls_block(
        self,
        cert_mode: str,
        sni: Optional[str],
        cert_pem: Optional[str],
        key_pem: Optional[str],
        alpn: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        tls: dict[str, Any] = {"enabled": True}
        server_name = str(sni or "").strip()
        if server_name:
            tls["server_name"] = server_name
        if alpn:
            tls["alpn"] = alpn

        cert_mode_normalized = str(cert_mode or "self_signed").strip().lower()
        inline_cert = str(cert_pem or "").strip()
        inline_key = str(key_pem or "").strip()
        if cert_mode_normalized == "self_signed":
            if inline_cert and inline_key:
                tls["certificate"] = [inline_cert]
                tls["key"] = [inline_key]
        elif inline_cert and inline_key:
            tls["certificate"] = [inline_cert]
            tls["key"] = [inline_key]
        return tls

    def _build_transport(self, network: str, transport_settings: Any) -> Optional[dict[str, Any]]:
        net = str(network or "tcp").strip().lower()
        source = transport_settings if isinstance(transport_settings, dict) else {}
        path = str(source.get("path", "/") or "/").strip() or "/"
        host = str(source.get("host", "") or "").strip()

        if net == "ws":
            transport: dict[str, Any] = {"type": "ws", "path": path}
            if host:
                transport["headers"] = {"Host": [host]}
            return transport
        if net == "grpc":
            return {
                "type": "grpc",
                "service_name": str(source.get("service_name", "") or "").strip(),
            }
        if net == "httpupgrade":
            transport = {"type": "httpupgrade", "path": path}
            if host:
                transport["host"] = host
            return transport
        if net == "xhttp":
            transport = {
                "type": "http",
                "path": path,
                "method": str(source.get("mode", "auto") or "auto").strip() or "auto",
            }
            if host:
                transport["host"] = [host]
            return transport
        return None

    def generate_config(self, db: Any) -> Dict[str, Any]:
        settings = db.query(GeneralSettings).order_by(GeneralSettings.id.asc()).first()
        raw_level = str(getattr(settings, "singbox_log_level", "info") or "info").strip().lower() if settings else "info"
        log_level = raw_level if raw_level in self._allowed_log_levels else "info"

        vpn_users = (
            db.query(VPNUser)
            .filter(VPNUser.is_enabled.is_(True))
            .order_by(VPNUser.id.asc())
            .all()
        )
        active_users: list[VPNUser] = []
        for user in vpn_users:
            if not bool(getattr(user, "is_active", False)):
                continue
            active_users.append(user)

        def _user_uuid(user: VPNUser) -> str:
            candidate = getattr(user, "uuid", None)
            if candidate is None:
                candidate = getattr(user, "vless_uuid", "")
            return str(candidate or "").strip()

        vless_users: list[dict[str, Any]] = []
        trojan_users: list[dict[str, Any]] = []
        hysteria_users: list[dict[str, Any]] = []
        tuic_users: list[dict[str, Any]] = []
        for user in active_users:
            user_uuid = _user_uuid(user)
            username = str(getattr(user, "username", "") or "").strip()
            if not user_uuid or not username:
                continue
            vless_users.append({"uuid": user_uuid, "name": username})
            trojan_users.append({"password": user_uuid, "name": username})
            hysteria_users.append({"password": user_uuid, "name": username})
            tuic_users.append(
                {
                    "uuid": user_uuid,
                    "password": str(getattr(user, "password", "") or ""),
                    "name": username,
                }
            )

        active_vless_inbounds = db.query(VlessInbound).filter(VlessInbound.is_active.is_(True)).order_by(VlessInbound.id.asc()).all()
        active_hysteria_inbounds = (
            db.query(HysteriaInbound).filter(HysteriaInbound.is_active.is_(True)).order_by(HysteriaInbound.id.asc()).all()
        )
        active_trojan_inbounds = (
            db.query(TrojanInbound).filter(TrojanInbound.is_active.is_(True)).order_by(TrojanInbound.id.asc()).all()
        )
        active_tuic_inbounds = db.query(TuicInbound).filter(TuicInbound.is_active.is_(True)).order_by(TuicInbound.id.asc()).all()
        active_shadowsocks_inbounds = (
            db.query(ShadowsocksInbound).filter(ShadowsocksInbound.is_active.is_(True)).order_by(ShadowsocksInbound.id.asc()).all()
        )

        inbounds: list[dict[str, Any]] = []

        for inbound in active_vless_inbounds:
            item: dict[str, Any] = {
                "type": "vless",
                "tag": f"vless-{inbound.id}",
                "listen": "::",
                "listen_port": self._parse_port(inbound.port, 443),
                "users": [
                    {
                        **user_item,
                        "flow": str(getattr(inbound, "flow", "xtls-rprx-vision") or "xtls-rprx-vision").strip(),
                    }
                    for user_item in vless_users
                ],
            }
            security_mode = str(getattr(inbound, "security", "reality") or "reality").strip().lower()
            tls_settings = getattr(inbound, "tls_settings", None) if isinstance(getattr(inbound, "tls_settings", None), dict) else {}
            sni = str(getattr(inbound, "sni", "") or "").strip() or str(tls_settings.get("server_name", "") or "").strip()
            if security_mode == "tls":
                item["tls"] = self._build_tls_block(
                    cert_mode="self_signed",
                    sni=sni or None,
                    cert_pem=tls_settings.get("certificate", ""),
                    key_pem=tls_settings.get("key", ""),
                    alpn=self._split_alpn(tls_settings.get("alpn", "h2,http/1.1"), ["h2", "http/1.1"]),
                )
            elif security_mode == "reality":
                short_id_value = str(tls_settings.get("short_id", "") or "").strip()
                reality_short_ids = [short_id_value] if short_id_value else ["0123456789abcdef"]
                item["tls"] = {
                    "enabled": True,
                    "server_name": sni or "www.microsoft.com",
                    "alpn": self._split_alpn(tls_settings.get("alpn", "h2,http/1.1"), ["h2", "http/1.1"]),
                    "reality": {
                        "enabled": True,
                        "handshake": {
                            "server": sni or "www.microsoft.com",
                            "server_port": self._parse_port(tls_settings.get("server_port", 443), 443),
                        },
                        "private_key": str(tls_settings.get("private_key", "") or "").strip(),
                        "short_id": reality_short_ids,
                    },
                }
            transport = self._build_transport(getattr(inbound, "network", "tcp"), getattr(inbound, "transport_settings", None))
            if transport:
                item["transport"] = transport
            inbounds.append(item)

        for inbound in active_hysteria_inbounds:
            item = {
                "type": "hysteria2",
                "tag": f"hysteria2-{inbound.id}",
                "listen": "::",
                "listen_port": self._parse_port(getattr(inbound, "port", 443), 443),
                "users": hysteria_users,
                "tls": self._build_tls_block(
                    cert_mode=str(getattr(inbound, "cert_mode", "self_signed") or "self_signed"),
                    sni=getattr(inbound, "sni", None),
                    cert_pem=getattr(inbound, "cert_pem", None),
                    key_pem=getattr(inbound, "key_pem", None),
                ),
            }
            obfs_password = str(getattr(inbound, "obfs_password", "") or "").strip()
            if obfs_password:
                item["obfs"] = {"type": "salamander", "password": obfs_password}
            masquerade = str(getattr(inbound, "masquerade", "") or "").strip()
            if masquerade:
                item["masquerade"] = masquerade
            up_mbps = getattr(inbound, "up_mbps", None)
            down_mbps = getattr(inbound, "down_mbps", None)
            if up_mbps is not None:
                item["up_mbps"] = int(up_mbps)
            if down_mbps is not None:
                item["down_mbps"] = int(down_mbps)
            inbounds.append(item)

        for inbound in active_trojan_inbounds:
            item = {
                "type": "trojan",
                "tag": f"trojan-{inbound.id}",
                "listen": "::",
                "listen_port": self._parse_port(getattr(inbound, "port", 443), 443),
                "users": trojan_users,
                "tls": self._build_tls_block(
                    cert_mode=str(getattr(inbound, "cert_mode", "self_signed") or "self_signed"),
                    sni=getattr(inbound, "sni", None),
                    cert_pem=getattr(inbound, "cert_pem", None),
                    key_pem=getattr(inbound, "key_pem", None),
                    alpn=self._split_alpn(getattr(inbound, "alpn", "h2,http/1.1"), ["h2", "http/1.1"]),
                ),
            }
            transport = self._build_transport(getattr(inbound, "network", "tcp"), getattr(inbound, "transport_settings", None))
            if transport:
                item["transport"] = transport
            inbounds.append(item)

        for inbound in active_tuic_inbounds:
            item = {
                "type": "tuic",
                "tag": f"tuic-{inbound.id}",
                "listen": "::",
                "listen_port": self._parse_port(getattr(inbound, "port", 8443), 8443),
                "users": tuic_users,
                "congestion_control": str(getattr(inbound, "congestion_control", "bbr") or "bbr"),
                "udp_relay_mode": str(getattr(inbound, "udp_relay_mode", "native") or "native"),
                "zero_rtt_handshake": bool(getattr(inbound, "zero_rtt_handshake", True)),
                "tls": self._build_tls_block(
                    cert_mode=str(getattr(inbound, "cert_mode", "self_signed") or "self_signed"),
                    sni=getattr(inbound, "sni", None),
                    cert_pem=getattr(inbound, "cert_pem", None),
                    key_pem=getattr(inbound, "key_pem", None),
                    alpn=["h3"],
                ),
            }
            inbounds.append(item)

        for inbound in active_shadowsocks_inbounds:
            item = {
                "type": "shadowsocks",
                "tag": f"shadowsocks-{inbound.id}",
                "listen": "::",
                "listen_port": self._parse_port(getattr(inbound, "port", 8388), 8388),
                "method": str(getattr(inbound, "method", "2022-blake3-aes-128-gcm") or "2022-blake3-aes-128-gcm"),
                "password": str(getattr(inbound, "password", "") or ""),
            }
            inbounds.append(item)

        route_rules = [{"inbound": item.get("tag"), "action": "sniff"} for item in inbounds if item.get("tag")]
        return {
            "log": {"level": log_level},
            "inbounds": inbounds,
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"rules": route_rules},
        }

    def generate_all_user_uris(self, db: Any, user: VPNUser, server_ip: str) -> list[dict[str, str]]:
        server_host = str(server_ip or "").strip()
        if not server_host:
            return []

        user_uuid = str(getattr(user, "uuid", None) or getattr(user, "vless_uuid", "") or "").strip()
        username = str(getattr(user, "username", "") or "").strip() or "user"
        user_password = str(getattr(user, "password", "") or "")

        links: list[dict[str, str]] = []

        active_vless_inbounds = db.query(VlessInbound).filter(VlessInbound.is_active.is_(True)).order_by(VlessInbound.id.asc()).all()
        for inbound in active_vless_inbounds:
            if not user_uuid:
                continue
            network = str(getattr(inbound, "network", "tcp") or "tcp").strip().lower()
            security = str(getattr(inbound, "security", "reality") or "reality").strip().lower()
            tls_settings = getattr(inbound, "tls_settings", None) if isinstance(getattr(inbound, "tls_settings", None), dict) else {}
            transport = getattr(inbound, "transport_settings", None) if isinstance(getattr(inbound, "transport_settings", None), dict) else {}
            params: dict[str, str] = {"type": network, "security": security}
            sni = str(getattr(inbound, "sni", "") or tls_settings.get("server_name", "") or "").strip()
            if sni:
                params["sni"] = sni
            flow = str(getattr(inbound, "flow", "") or "").strip()
            if flow:
                params["flow"] = flow
            fp = str(getattr(inbound, "fingerprint", "") or "").strip()
            if fp:
                params["fp"] = fp
            if security == "reality":
                pbk = str(tls_settings.get("public_key", "") or "").strip()
                sid = str(tls_settings.get("short_id", "") or "").strip()
                if pbk:
                    params["pbk"] = pbk
                if sid:
                    params["sid"] = sid
                spider_x = str(getattr(inbound, "spider_x", "/") or "/").strip() or "/"
                params["spx"] = spider_x
            if network in {"ws", "httpupgrade", "xhttp"}:
                params["path"] = str(transport.get("path", "/") or "/").strip() or "/"
                host = str(transport.get("host", "") or "").strip()
                if host:
                    params["host"] = host
            elif network == "grpc":
                service_name = str(transport.get("service_name", "") or "").strip()
                if service_name:
                    params["serviceName"] = service_name
            query = urlencode(params, quote_via=quote, safe=",")
            fragment = quote(str(getattr(inbound, "remark", "vless") or "vless"), safe="-_.")
            link = f"vless://{quote(user_uuid, safe='')}@{server_host}:{self._parse_port(getattr(inbound, 'port', 443), 443)}?{query}#{fragment}"
            links.append({"protocol": "vless", "remark": str(getattr(inbound, "remark", "")), "link": link, "user": username})

        active_hysteria_inbounds = (
            db.query(HysteriaInbound).filter(HysteriaInbound.is_active.is_(True)).order_by(HysteriaInbound.id.asc()).all()
        )
        for inbound in active_hysteria_inbounds:
            if not user_uuid:
                continue
            params = {
                "obfs": "salamander",
                "obfs-password": str(getattr(inbound, "obfs_password", "") or ""),
            }
            sni = str(getattr(inbound, "sni", "") or "").strip()
            if sni:
                params["sni"] = sni
            if str(getattr(inbound, "cert_mode", "self_signed") or "self_signed").strip().lower() == "self_signed":
                params["insecure"] = "1"
            query = urlencode(params, quote_via=quote, safe=",")
            fragment = quote(str(getattr(inbound, "remark", "hysteria2") or "hysteria2"), safe="-_.")
            link = (
                f"hysteria2://{quote(user_uuid, safe='')}@{server_host}:"
                f"{self._parse_port(getattr(inbound, 'port', 443), 443)}/?{query}#{fragment}"
            )
            links.append({"protocol": "hysteria2", "remark": str(getattr(inbound, "remark", "")), "link": link, "user": username})

        active_trojan_inbounds = (
            db.query(TrojanInbound).filter(TrojanInbound.is_active.is_(True)).order_by(TrojanInbound.id.asc()).all()
        )
        for inbound in active_trojan_inbounds:
            if not user_uuid:
                continue
            network = str(getattr(inbound, "network", "tcp") or "tcp").strip().lower()
            transport = getattr(inbound, "transport_settings", None) if isinstance(getattr(inbound, "transport_settings", None), dict) else {}
            params = {
                "security": "tls",
                "type": network,
            }
            sni = str(getattr(inbound, "sni", "") or "").strip()
            if sni:
                params["sni"] = sni
            fingerprint = str(getattr(inbound, "fingerprint", "") or "").strip()
            if fingerprint:
                params["fp"] = fingerprint
            if network in {"ws", "httpupgrade", "xhttp"}:
                params["path"] = str(transport.get("path", "/") or "/").strip() or "/"
                host = str(transport.get("host", "") or "").strip()
                if host:
                    params["host"] = host
            elif network == "grpc":
                service_name = str(transport.get("service_name", "") or "").strip()
                if service_name:
                    params["serviceName"] = service_name
            query = urlencode(params, quote_via=quote, safe=",")
            fragment = quote(str(getattr(inbound, "remark", "trojan") or "trojan"), safe="-_.")
            link = (
                f"trojan://{quote(user_uuid, safe='')}@{server_host}:"
                f"{self._parse_port(getattr(inbound, 'port', 443), 443)}?{query}#{fragment}"
            )
            links.append({"protocol": "trojan", "remark": str(getattr(inbound, "remark", "")), "link": link, "user": username})

        active_tuic_inbounds = db.query(TuicInbound).filter(TuicInbound.is_active.is_(True)).order_by(TuicInbound.id.asc()).all()
        for inbound in active_tuic_inbounds:
            if not user_uuid:
                continue
            params = {
                "congestion_control": str(getattr(inbound, "congestion_control", "bbr") or "bbr"),
                "udp_relay_mode": str(getattr(inbound, "udp_relay_mode", "native") or "native"),
                "alpn": "h3",
            }
            sni = str(getattr(inbound, "sni", "") or "").strip()
            if sni:
                params["sni"] = sni
            if str(getattr(inbound, "cert_mode", "self_signed") or "self_signed").strip().lower() == "self_signed":
                params["allow_insecure"] = "1"
            query = urlencode(params, quote_via=quote, safe=",")
            fragment = quote(str(getattr(inbound, "remark", "tuic") or "tuic"), safe="-_.")
            link = (
                f"tuic://{quote(user_uuid, safe='')}:{quote(user_password, safe='')}@{server_host}:"
                f"{self._parse_port(getattr(inbound, 'port', 8443), 8443)}/?{query}#{fragment}"
            )
            links.append({"protocol": "tuic", "remark": str(getattr(inbound, "remark", "")), "link": link, "user": username})

        active_shadowsocks_inbounds = (
            db.query(ShadowsocksInbound).filter(ShadowsocksInbound.is_active.is_(True)).order_by(ShadowsocksInbound.id.asc()).all()
        )
        for inbound in active_shadowsocks_inbounds:
            method = str(getattr(inbound, "method", "2022-blake3-aes-128-gcm") or "2022-blake3-aes-128-gcm")
            password = str(getattr(inbound, "password", "") or "")
            userinfo_raw = f"{method}:{password}".encode("utf-8")
            userinfo = base64.urlsafe_b64encode(userinfo_raw).decode("utf-8").rstrip("=")
            fragment = quote(str(getattr(inbound, "remark", "ss-2022") or "ss-2022"), safe="-_.")
            link = f"ss://{userinfo}@{server_host}:{self._parse_port(getattr(inbound, 'port', 8388), 8388)}#{fragment}"
            links.append({"protocol": "shadowsocks", "remark": str(getattr(inbound, "remark", "")), "link": link, "user": username})

        return links

    def apply_settings(self, db: Any) -> Dict[str, Any]:
        config_payload = self.generate_config(db)
        log_level = str(config_payload.get("log", {}).get("level", "info") or "info")

        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self.config_path.write_text(
                json.dumps(config_payload, indent=2, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
        except Exception as exc:
            return {
                "success": False,
                "protocol": self.protocol_name,
                "message": f"Failed to write sing-box config: {exc}",
            }

        restart_result = self._restart_service()
        if not restart_result.get("success"):
            return restart_result

        return {
            "success": True,
            "protocol": self.protocol_name,
            "service_name": self.service_name,
            "config_path": str(self.config_path),
            "log_level": log_level,
            "message": "Sing-box core config applied successfully",
        }

    def start(self) -> Dict[str, Any]:
        if shutil.which("systemctl") is None:
            return {
                "success": False,
                "protocol": self.protocol_name,
                "message": "systemctl is not available",
            }
        process = subprocess.run(
            ["systemctl", "start", self.service_name],
            capture_output=True,
            text=True,
            check=False,
        )
        if process.returncode != 0:
            return {
                "success": False,
                "protocol": self.protocol_name,
                "message": process.stderr.strip() or process.stdout.strip() or "Failed to start sing-box service",
            }
        return {"success": True, "protocol": self.protocol_name, "service_name": self.service_name}

    def restart(self) -> Dict[str, Any]:
        return self._restart_service()

    def _restart_service(self) -> Dict[str, Any]:
        if shutil.which("systemctl") is None:
            return {
                "success": False,
                "protocol": self.protocol_name,
                "message": "systemctl is not available",
            }

        process = subprocess.run(
            ["systemctl", "restart", self.service_name],
            capture_output=True,
            text=True,
            check=False,
        )
        if process.returncode != 0:
            return {
                "success": False,
                "protocol": self.protocol_name,
                "message": process.stderr.strip() or process.stdout.strip() or "Failed to restart sing-box service",
            }
        return {"success": True, "protocol": self.protocol_name, "service_name": self.service_name}
