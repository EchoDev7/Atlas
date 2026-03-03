# Atlas — Background Scheduler Service
# Phase 2 Enhancements: Automatic enforcement of data limits and expiry dates

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Dict, Optional
import logging

from backend.database import SessionLocal
from backend.models.vpn_user import VPNUser, VPNConfig
from backend.core.openvpn import OpenVPNConfig, OpenVPNManager

logger = logging.getLogger(__name__)


class LimitEnforcementScheduler:
    """
    Lightweight background scheduler for enforcing user limits.
    Uses APScheduler with AsyncIO to run periodic checks without heavy dependencies.
    """
    
    def __init__(self):
        self.scheduler: Optional[AsyncIOScheduler] = None
        self.is_running = False
        self.openvpn_manager = OpenVPNManager()
        self._runtime_usage_cache: Dict[str, Dict[str, int]] = {}
    
    def start(self):
        """Start the background scheduler"""
        if self.is_running:
            logger.warning("Scheduler is already running")
            return
        
        self.scheduler = AsyncIOScheduler()
        
        # Run enforcement check every 5 minutes
        self.scheduler.add_job(
            self.enforce_limits,
            trigger=IntervalTrigger(minutes=5),
            id='enforce_limits',
            name='Enforce user limits (data & expiry)',
            replace_existing=True
        )

        # Reconcile active sessions every 2 minutes to fix stale counters.
        self.scheduler.add_job(
            self.reconcile_openvpn_sessions,
            trigger=IntervalTrigger(minutes=2),
            id='reconcile_openvpn_sessions',
            name='Reconcile OpenVPN active sessions',
            replace_existing=True
        )
        
        self.scheduler.start()
        self.is_running = True
        logger.info("Limit enforcement scheduler started (runs every 5 minutes)")
    
    def stop(self):
        """Stop the background scheduler"""
        if self.scheduler and self.is_running:
            self.scheduler.shutdown()
            self.is_running = False
            logger.info("Limit enforcement scheduler stopped")

    def _parse_openvpn_status_runtime_stats(self) -> Dict[str, Dict[str, int]]:
        """
        Parse OpenVPN status-version 2 file and return runtime stats per common name.
        """
        status_path = OpenVPNConfig.STATUS_LOG
        runtime_stats: Dict[str, Dict[str, int]] = {}

        if not status_path.exists():
            logger.warning("OpenVPN status log not found for reconciliation: %s", status_path)
            return runtime_stats

        try:
            for raw_line in status_path.read_text(errors="ignore").splitlines():
                line = raw_line.strip()
                if not line or not line.startswith("CLIENT_LIST,"):
                    continue

                parts = [segment.strip() for segment in line.split(",")]
                if len(parts) < 2:
                    continue

                common_name = parts[1]
                if not common_name or common_name.upper() == "UNDEF":
                    continue

                item = runtime_stats.setdefault(
                    common_name,
                    {"connections": 0, "bytes_sent": 0, "bytes_received": 0},
                )
                item["connections"] += 1
                item["bytes_received"] += int(parts[4]) if len(parts) > 4 and str(parts[4]).isdigit() else 0
                item["bytes_sent"] += int(parts[5]) if len(parts) > 5 and str(parts[5]).isdigit() else 0
        except Exception as exc:
            logger.error("Failed to parse OpenVPN status log: %s", exc)

        return runtime_stats

    def _get_openvpn_runtime_stats(self) -> Dict[str, Dict[str, int]]:
        """
        Prefer OpenVPN management interface for live sessions.
        Fallback to status.log when management interface is unavailable/empty.
        """
        runtime_stats: Dict[str, Dict[str, int]] = {}

        try:
            sessions = self.openvpn_manager.get_active_sessions()
            if sessions:
                for session in sessions:
                    username = (session.get("username") or "").strip()
                    if not username:
                        continue
                    item = runtime_stats.setdefault(
                        username,
                        {"connections": 0, "bytes_sent": 0, "bytes_received": 0},
                    )
                    item["connections"] += 1
                    item["bytes_sent"] += max(0, int(session.get("bytes_sent") or 0))
                    item["bytes_received"] += max(0, int(session.get("bytes_received") or 0))

                logger.info(
                    "Reconcile source=management_interface users=%s online=%s",
                    len(runtime_stats),
                    sum(int(item.get("connections") or 0) for item in runtime_stats.values()),
                )
                return runtime_stats

            logger.warning("Management interface returned no sessions; falling back to status.log")
        except Exception as exc:
            logger.warning("Management interface read failed; falling back to status.log: %s", exc)

        runtime_stats = self._parse_openvpn_status_runtime_stats()
        logger.info(
            "Reconcile source=status_log users=%s online=%s",
            len(runtime_stats),
            sum(int(item.get("connections") or 0) for item in runtime_stats.values()),
        )
        return runtime_stats

    def _apply_runtime_disconnect_fallback_accounting(
        self,
        db: Session,
        runtime_stats: Dict[str, Dict[str, int]],
        users_by_username: Dict[str, VPNUser],
    ) -> None:
        """
        Persist previous live session counters when reconnect/disconnect is detected.

        This keeps accounting independent from UI/API reads when disconnect hooks are missed.
        """
        known_usernames = set(runtime_stats.keys()) | set(self._runtime_usage_cache.keys())

        for username in known_usernames:
            live = runtime_stats.get(username, {})
            live_connections = max(0, int(live.get("connections") or 0))
            live_sent = max(0, int(live.get("bytes_sent") or 0))
            live_received = max(0, int(live.get("bytes_received") or 0))

            previous = self._runtime_usage_cache.get(username)
            should_finalize_previous = False
            if previous and int(previous.get("connections") or 0) > 0:
                prev_sent = max(0, int(previous.get("bytes_sent") or 0))
                prev_received = max(0, int(previous.get("bytes_received") or 0))
                prev_connections = max(0, int(previous.get("connections") or 0))

                if live_connections == 0:
                    should_finalize_previous = True
                elif (
                    live_connections < prev_connections
                    or live_sent < prev_sent
                    or live_received < prev_received
                ):
                    should_finalize_previous = True

            if should_finalize_previous and previous:
                user = users_by_username.get(username)
                if user is None:
                    user = db.query(VPNUser).filter(VPNUser.username == username).first()

                if user is not None:
                    prev_sent = max(0, int(previous.get("bytes_sent") or 0))
                    prev_received = max(0, int(previous.get("bytes_received") or 0))
                    base_sent = max(0, int(previous.get("base_sent") or 0))
                    base_received = max(0, int(previous.get("base_received") or 0))

                    expected_sent = base_sent + prev_sent
                    expected_received = base_received + prev_received
                    current_sent = max(0, int(user.total_bytes_sent or 0))
                    current_received = max(0, int(user.total_bytes_received or 0))

                    missing_sent = max(0, expected_sent - current_sent)
                    missing_received = max(0, expected_received - current_received)

                    if missing_sent or missing_received:
                        user.total_bytes_sent = current_sent + missing_sent
                        user.total_bytes_received = current_received + missing_received
                        accumulated_total = max(0, int(user.traffic_used_bytes or 0)) + missing_sent + missing_received
                        user.traffic_used_bytes = max(
                            accumulated_total,
                            int(user.total_bytes_sent or 0) + int(user.total_bytes_received or 0),
                        )
                        user.updated_at = datetime.utcnow()

            if live_connections > 0:
                user_for_baseline = users_by_username.get(username)
                if user_for_baseline is None:
                    user_for_baseline = db.query(VPNUser).filter(VPNUser.username == username).first()

                if previous is None or should_finalize_previous:
                    base_sent = max(0, int(getattr(user_for_baseline, "total_bytes_sent", 0) or 0))
                    base_received = max(0, int(getattr(user_for_baseline, "total_bytes_received", 0) or 0))
                else:
                    base_sent = max(0, int(previous.get("base_sent") or 0))
                    base_received = max(0, int(previous.get("base_received") or 0))

                self._runtime_usage_cache[username] = {
                    "connections": live_connections,
                    "bytes_sent": live_sent,
                    "bytes_received": live_received,
                    "base_sent": base_sent,
                    "base_received": base_received,
                }
            else:
                self._runtime_usage_cache.pop(username, None)

        db.flush()

    async def reconcile_openvpn_sessions(self):
        """
        Reconcile vpn_users.current_connections with real OpenVPN online sessions.

        - Extract online users from status log (by common name)
        - Set current_connections to exact observed count
        - Fix stale sessions (DB > 0 while server has 0)
        """
        db: Session = SessionLocal()
        try:
            runtime_stats = self._get_openvpn_runtime_stats()
            online_counts = {
                username: max(0, int(item.get("connections") or 0))
                for username, item in runtime_stats.items()
            }
            now = datetime.utcnow()

            users = db.query(VPNUser).all()
            users_by_username = {str(user.username): user for user in users}
            self._apply_runtime_disconnect_fallback_accounting(db, runtime_stats, users_by_username)
            updated_users = 0
            stale_fixed = 0

            for user in users:
                previous_connections = int(user.current_connections or 0)
                observed_connections = int(online_counts.get(user.username, 0))

                if previous_connections > 0 and observed_connections == 0:
                    stale_fixed += 1

                if previous_connections != observed_connections:
                    user.current_connections = observed_connections
                    updated_users += 1

                user.is_connection_limit_exceeded = (
                    observed_connections > user.effective_max_concurrent_connections
                )
                user.refresh_limit_flags(now)

            db.commit()
            logger.info(
                "OpenVPN reconcile complete: users=%s updated=%s stale_fixed=%s observed_online=%s",
                len(users),
                updated_users,
                stale_fixed,
                sum(online_counts.values()),
            )
        except Exception as exc:
            logger.error("OpenVPN session reconciliation failed: %s", exc)
            db.rollback()
        finally:
            db.close()
    
    async def enforce_limits(self):
        """
        Check all users for limit violations and disable accounts if needed.
        This runs periodically in the background.
        """
        db: Session = SessionLocal()
        try:
            logger.info("Running limit enforcement check...")
            
            # Get all enabled users
            users = db.query(VPNUser).filter(VPNUser.is_enabled == True).all()
            
            disabled_count = 0
            
            for user in users:
                should_disable = False
                disable_reason = []
                now = datetime.utcnow()

                user.refresh_limit_flags(now)
                
                # Check expiry date
                if user.is_expired:
                    should_disable = True
                    expiry_point = user.effective_access_expires_at
                    expiry_label = expiry_point.strftime('%Y-%m-%d') if expiry_point else "unknown"
                    disable_reason.append(f"Expired on {expiry_label}")
                    logger.info(f"User {user.username} expired on {expiry_point}")
                
                # Check data limit
                limit_bytes = user.effective_traffic_limit_bytes
                if limit_bytes is not None:
                    used_bytes = user.total_bytes
                    if used_bytes >= limit_bytes:
                        should_disable = True
                        used_gb = used_bytes / (1024 ** 3)
                        limit_gb = limit_bytes / float(1024 ** 3)
                        disable_reason.append(f"Data limit exceeded ({used_gb:.2f} GB / {limit_gb:.2f} GB)")
                        logger.info(f"User {user.username} exceeded data limit: {used_gb:.2f} GB / {limit_gb:.2f} GB")
                
                # Disable user if any limit is violated
                if should_disable:
                    user.is_enabled = False
                    user.disabled_at = now
                    user.disabled_reason = "; ".join(disable_reason)
                    
                    # Revoke all active configs
                    for config in user.configs:
                        if config.is_active:
                            config.is_active = False
                            config.revoked_at = now
                            config.revoked_reason = "Automatic: " + user.disabled_reason
                    
                    disabled_count += 1
                    logger.warning(f"User {user.username} disabled: {user.disabled_reason}")
            
            # Commit all changes
            db.commit()
            
            if disabled_count > 0:
                logger.info(f"Limit enforcement complete: {disabled_count} user(s) disabled")
            else:
                logger.info("Limit enforcement complete: No violations found")
        
        except Exception as e:
            logger.error(f"Error during limit enforcement: {e}")
            db.rollback()
        finally:
            db.close()
    
    async def check_user_limits(self, user_id: int, db: Session) -> dict:
        """
        Manually check limits for a specific user (can be called from API).
        Returns status information.
        """
        user = db.query(VPNUser).filter(VPNUser.id == user_id).first()
        if not user:
            return {"error": "User not found"}
        
        status = {
            "username": user.username,
            "is_enabled": user.is_enabled,
            "violations": []
        }
        
        user.refresh_limit_flags(datetime.utcnow())

        # Check expiry
        expiry_point = user.effective_access_expires_at
        if expiry_point:
            if user.is_expired:
                status["violations"].append({
                    "type": "expiry",
                    "message": f"Expired on {expiry_point.strftime('%Y-%m-%d')}",
                    "is_violated": True
                })
            else:
                days_remaining = (expiry_point - datetime.utcnow()).days
                status["violations"].append({
                    "type": "expiry",
                    "message": f"{days_remaining} days remaining",
                    "is_violated": False
                })
        
        # Check data limit
        limit_bytes = user.effective_traffic_limit_bytes
        if limit_bytes is not None:
            used_gb = user.total_bytes / (1024 ** 3)
            percentage = user.data_usage_percentage
            limit_gb = limit_bytes / float(1024 ** 3)
            is_violated = user.is_data_limit_exceeded
            
            status["violations"].append({
                "type": "data_limit",
                "message": f"{used_gb:.2f} GB / {limit_gb:.2f} GB ({percentage:.1f}%)",
                "is_violated": is_violated
            })

        status["violations"].append({
            "type": "concurrent_connections",
            "message": f"{int(user.current_connections or 0)} / {user.effective_max_concurrent_connections} active",
            "is_violated": bool(user.is_connection_limit_exceeded),
        })
        
        return status


# Global scheduler instance
scheduler = LimitEnforcementScheduler()


def get_scheduler() -> LimitEnforcementScheduler:
    """Get the global scheduler instance"""
    return scheduler
