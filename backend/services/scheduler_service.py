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

logger = logging.getLogger(__name__)


class LimitEnforcementScheduler:
    """
    Lightweight background scheduler for enforcing user limits.
    Uses APScheduler with AsyncIO to run periodic checks without heavy dependencies.
    """
    
    def __init__(self):
        self.scheduler: Optional[AsyncIOScheduler] = None
        self.is_running = False
    
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
        
        self.scheduler.start()
        self.is_running = True
        logger.info("Limit enforcement scheduler started (runs every 5 minutes)")
    
    def stop(self):
        """Stop the background scheduler"""
        if self.scheduler and self.is_running:
            self.scheduler.shutdown()
            self.is_running = False
            logger.info("Limit enforcement scheduler stopped")
    
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
                
                # Check expiry date
                if user.expiry_date and datetime.utcnow() > user.expiry_date:
                    if not user.is_expired:
                        user.is_expired = True
                        should_disable = True
                        disable_reason.append(f"Expired on {user.expiry_date.strftime('%Y-%m-%d')}")
                        logger.info(f"User {user.username} expired on {user.expiry_date}")
                
                # Check data limit
                if user.data_limit_gb:
                    used_gb = user.total_gb_used
                    if used_gb >= user.data_limit_gb:
                        if not user.is_data_limit_exceeded:
                            user.is_data_limit_exceeded = True
                            should_disable = True
                            disable_reason.append(f"Data limit exceeded ({used_gb:.2f} GB / {user.data_limit_gb} GB)")
                            logger.info(f"User {user.username} exceeded data limit: {used_gb:.2f} GB / {user.data_limit_gb} GB")
                
                # Disable user if any limit is violated
                if should_disable:
                    user.is_enabled = False
                    user.disabled_at = datetime.utcnow()
                    user.disabled_reason = "; ".join(disable_reason)
                    
                    # Revoke all active configs
                    for config in user.configs:
                        if config.is_active:
                            config.is_active = False
                            config.revoked_at = datetime.utcnow()
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
        
        # Check expiry
        if user.expiry_date:
            if datetime.utcnow() > user.expiry_date:
                status["violations"].append({
                    "type": "expiry",
                    "message": f"Expired on {user.expiry_date.strftime('%Y-%m-%d')}",
                    "is_violated": True
                })
            else:
                days_remaining = (user.expiry_date - datetime.utcnow()).days
                status["violations"].append({
                    "type": "expiry",
                    "message": f"{days_remaining} days remaining",
                    "is_violated": False
                })
        
        # Check data limit
        if user.data_limit_gb:
            used_gb = user.total_gb_used
            percentage = user.data_usage_percentage
            is_violated = used_gb >= user.data_limit_gb
            
            status["violations"].append({
                "type": "data_limit",
                "message": f"{used_gb:.2f} GB / {user.data_limit_gb} GB ({percentage:.1f}%)",
                "is_violated": is_violated
            })
        
        return status


# Global scheduler instance
scheduler = LimitEnforcementScheduler()


def get_scheduler() -> LimitEnforcementScheduler:
    """Get the global scheduler instance"""
    return scheduler
