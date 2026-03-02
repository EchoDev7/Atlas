# Atlas — Background Scheduler Service
# Phase 2 Enhancements: Automatic enforcement of data limits and expiry dates

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional
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

    def _parse_openvpn_status_online_counts(self) -> dict:
        """
        Parse OpenVPN status-version 2 file and return online connection counts per common name.
        """
        status_path = OpenVPNConfig.STATUS_LOG
        online_counts = {}

        if not status_path.exists():
            logger.warning("OpenVPN status log not found for reconciliation: %s", status_path)
            return online_counts

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

                online_counts[common_name] = int(online_counts.get(common_name, 0)) + 1
        except Exception as exc:
            logger.error("Failed to parse OpenVPN status log: %s", exc)

        return online_counts

    def _get_openvpn_online_counts(self) -> dict:
        """
        Prefer OpenVPN management interface for live sessions.
        Fallback to status.log when management interface is unavailable/empty.
        """
        online_counts = {}

        try:
            sessions = self.openvpn_manager.get_active_sessions()
            if sessions:
                for session in sessions:
                    username = (session.get("username") or "").strip()
                    if not username:
                        continue
                    online_counts[username] = int(online_counts.get(username, 0)) + 1

                logger.info(
                    "Reconcile source=management_interface users=%s online=%s",
                    len(online_counts),
                    sum(online_counts.values()),
                )
                return online_counts

            logger.warning("Management interface returned no sessions; falling back to status.log")
        except Exception as exc:
            logger.warning("Management interface read failed; falling back to status.log: %s", exc)

        online_counts = self._parse_openvpn_status_online_counts()
        logger.info(
            "Reconcile source=status_log users=%s online=%s",
            len(online_counts),
            sum(online_counts.values()),
        )
        return online_counts

    async def reconcile_openvpn_sessions(self):
        """
        Reconcile vpn_users.current_connections with real OpenVPN online sessions.

        - Extract online users from status log (by common name)
        - Set current_connections to exact observed count
        - Fix stale sessions (DB > 0 while server has 0)
        """
        db: Session = SessionLocal()
        try:
            online_counts = self._get_openvpn_online_counts()
            now = datetime.utcnow()

            users = db.query(VPNUser).all()
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
