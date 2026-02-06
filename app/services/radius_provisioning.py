"""
RADIUS Provisioning Module
==========================

This module handles the complete provisioning flow for RADIUS-enabled routers.
It's designed to work alongside the existing direct API provisioning,
allowing you to migrate routers one at a time.

Flow:
1. Customer pays -> Callback triggers provisioning
2. Check router's auth_method (DIRECT_API or RADIUS)
3. If RADIUS: Create user in RADIUS tables (this module)
4. If DIRECT_API: Use existing mikrotik_api.py (unchanged)

Usage:
    from app.services.radius_provisioning import RadiusProvisioning
    
    provisioning = RadiusProvisioning(db)
    result = await provisioning.provision_hotspot_user(customer, plan, router)
"""

import logging
import secrets
import string
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.services.radius_service import (
    RadiusService, 
    RadiusCoA, 
    RadiusUserConfig,
    parse_speed_to_radius_format,
    calculate_session_timeout
)

logger = logging.getLogger(__name__)


class RadiusProvisioning:
    """
    Handles RADIUS user provisioning for hotspot customers.
    
    This replaces the direct MikroTik API provisioning for routers
    configured with auth_method = RADIUS.
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.radius = RadiusService(db)
    
    async def provision_hotspot_user(
        self,
        customer_id: int,
        mac_address: str,
        phone: str,
        plan_speed: str,
        plan_duration_value: int,
        plan_duration_unit: str,
        router_id: int,
        password: Optional[str] = None,
        existing_expiry: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Provision a hotspot user for RADIUS authentication.
        
        This creates all necessary RADIUS entries for the user to authenticate
        on a MikroTik router configured with RADIUS.
        
        Args:
            customer_id: Customer ID in ISP Billing database
            mac_address: Customer's MAC address (used as username)
            phone: Customer's phone number
            plan_speed: Plan speed (e.g., "5Mbps")
            plan_duration_value: Duration value (e.g., 24)
            plan_duration_unit: Duration unit (HOURS, DAYS, MINUTES)
            router_id: Router ID (for logging/tracking)
            password: Optional password (generated if not provided)
            existing_expiry: Existing expiry datetime for renewals
            
        Returns:
            Dict with provisioning result
        """
        try:
            # Generate username from MAC address (remove colons, uppercase)
            username = mac_address.replace(':', '').replace('-', '').upper()
            
            # Generate password if not provided
            if not password:
                password = self._generate_password()
            
            # Calculate expiry
            if existing_expiry and existing_expiry > datetime.utcnow():
                # Renewal - extend from current expiry
                base_time = existing_expiry
            else:
                base_time = datetime.utcnow()
            
            expiry = self._calculate_expiry(base_time, plan_duration_value, plan_duration_unit)
            
            # Calculate session timeout
            session_timeout = calculate_session_timeout(plan_duration_value, plan_duration_unit)
            
            # Parse speed to RADIUS format
            rate_limit = parse_speed_to_radius_format(plan_speed)
            
            # Create RADIUS user configuration
            config = RadiusUserConfig(
                username=username,
                password=password,
                rate_limit=rate_limit,
                session_timeout=session_timeout,
                idle_timeout=1800,  # 30 minutes idle timeout
                expiry=expiry,
                customer_id=customer_id,
                simultaneous_use=1  # One device per customer
            )
            
            # Create the user in RADIUS tables
            result = await self.radius.create_user(config)
            
            # Log the provisioning
            await self._log_provisioning(
                customer_id=customer_id,
                router_id=router_id,
                mac_address=mac_address,
                action='RADIUS_CREATE',
                status='SUCCESS',
                details=f"Username: {username}, Rate: {rate_limit}, Expiry: {expiry}"
            )
            
            logger.info(f"RADIUS user provisioned: {username} (Customer: {customer_id})")
            
            return {
                'success': True,
                'username': username,
                'password': password,
                'rate_limit': rate_limit,
                'session_timeout': session_timeout,
                'expiry': expiry.isoformat(),
                'customer_id': customer_id,
                'auth_method': 'RADIUS'
            }
            
        except Exception as e:
            logger.error(f"Failed to provision RADIUS user for customer {customer_id}: {e}")
            
            await self._log_provisioning(
                customer_id=customer_id,
                router_id=router_id,
                mac_address=mac_address,
                action='RADIUS_CREATE',
                status='FAILED',
                error=str(e)
            )
            
            return {
                'success': False,
                'error': str(e),
                'auth_method': 'RADIUS'
            }
    
    async def extend_subscription(
        self,
        customer_id: int,
        mac_address: str,
        plan_duration_value: int,
        plan_duration_unit: str,
        current_expiry: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Extend an existing RADIUS user's subscription.
        
        This updates the expiry date and session timeout without
        changing the password or other attributes.
        """
        try:
            username = mac_address.replace(':', '').replace('-', '').upper()
            
            # Calculate new expiry
            if current_expiry and current_expiry > datetime.utcnow():
                base_time = current_expiry
            else:
                base_time = datetime.utcnow()
            
            new_expiry = self._calculate_expiry(base_time, plan_duration_value, plan_duration_unit)
            new_session_timeout = calculate_session_timeout(plan_duration_value, plan_duration_unit)
            
            # Update the user
            updated = await self.radius.update_user_expiry(
                username=username,
                new_expiry=new_expiry,
                new_session_timeout=new_session_timeout
            )
            
            if updated:
                logger.info(f"RADIUS subscription extended: {username} until {new_expiry}")
                return {
                    'success': True,
                    'username': username,
                    'new_expiry': new_expiry.isoformat(),
                    'session_timeout': new_session_timeout
                }
            else:
                # User doesn't exist - need full provisioning
                return {
                    'success': False,
                    'error': 'User not found in RADIUS - full provisioning required'
                }
            
        except Exception as e:
            logger.error(f"Failed to extend RADIUS subscription: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def remove_user(
        self,
        customer_id: int,
        mac_address: str,
        router_ip: Optional[str] = None,
        radius_secret: Optional[str] = None,
        disconnect: bool = True
    ) -> Dict[str, Any]:
        """
        Remove a RADIUS user and optionally disconnect active session.
        
        Args:
            customer_id: Customer ID
            mac_address: Customer's MAC address
            router_ip: Router IP for CoA disconnect (optional)
            radius_secret: RADIUS shared secret for CoA (optional)
            disconnect: Whether to send disconnect request
            
        Returns:
            Dict with removal result
        """
        try:
            username = mac_address.replace(':', '').replace('-', '').upper()
            
            # Try to disconnect active session if router info provided
            disconnect_result = None
            if disconnect and router_ip and radius_secret:
                coa = RadiusCoA(router_ip, radius_secret)
                success, message = coa.disconnect_user(username=username)
                disconnect_result = {'success': success, 'message': message}
            
            # Delete from RADIUS tables
            deleted = await self.radius.delete_user(username)
            
            logger.info(f"RADIUS user removed: {username}")
            
            return {
                'success': True,
                'username': username,
                'deleted_from_radius': deleted,
                'disconnect_result': disconnect_result
            }
            
        except Exception as e:
            logger.error(f"Failed to remove RADIUS user: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def disconnect_active_session(
        self,
        mac_address: str,
        router_ip: str,
        radius_secret: str
    ) -> Tuple[bool, str]:
        """
        Disconnect a user's active session via CoA.
        
        This doesn't remove the user from RADIUS - they can reconnect
        if their subscription is still valid.
        """
        username = mac_address.replace(':', '').replace('-', '').upper()
        
        coa = RadiusCoA(router_ip, radius_secret)
        return coa.disconnect_user(username=username)
    
    async def get_active_sessions_for_router(
        self,
        router_ip: str
    ) -> list:
        """Get all active sessions for a specific router (by NAS IP)"""
        return await self.radius.get_active_sessions(nas_ip=router_ip)
    
    async def get_customer_sessions(self, customer_id: int) -> list:
        """Get all active and historical sessions for a customer"""
        # Get usernames for this customer
        usernames = await self.radius.get_users_by_customer_id(customer_id)
        
        all_sessions = []
        for username in usernames:
            sessions = await self.radius.get_active_sessions(username=username)
            all_sessions.extend(sessions)
        
        return all_sessions
    
    async def get_customer_bandwidth_usage(
        self,
        customer_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get bandwidth usage statistics for a customer"""
        usernames = await self.radius.get_users_by_customer_id(customer_id)
        
        if not usernames:
            return {
                'customer_id': customer_id,
                'total_bytes_in': 0,
                'total_bytes_out': 0,
                'total_sessions': 0
            }
        
        total_in = 0
        total_out = 0
        total_sessions = 0
        
        for username in usernames:
            stats = await self.radius.get_session_statistics(
                username=username,
                start_date=start_date,
                end_date=end_date
            )
            total_in += stats['total_bytes_in']
            total_out += stats['total_bytes_out']
            total_sessions += stats['total_sessions']
        
        return {
            'customer_id': customer_id,
            'total_bytes_in': total_in,
            'total_bytes_out': total_out,
            'total_bytes': total_in + total_out,
            'total_sessions': total_sessions,
            'total_bytes_in_mb': round(total_in / (1024 * 1024), 2),
            'total_bytes_out_mb': round(total_out / (1024 * 1024), 2)
        }
    
    def _generate_password(self, length: int = 8) -> str:
        """Generate a random password for hotspot user"""
        # Use digits and lowercase letters only (easy to type on mobile)
        chars = string.digits + string.ascii_lowercase
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def _calculate_expiry(
        self,
        base_time: datetime,
        duration_value: int,
        duration_unit: str
    ) -> datetime:
        """Calculate expiry datetime from base time and duration"""
        unit = duration_unit.upper()
        
        if unit == 'MINUTES':
            return base_time + timedelta(minutes=duration_value)
        elif unit == 'HOURS':
            return base_time + timedelta(hours=duration_value)
        elif unit == 'DAYS':
            return base_time + timedelta(days=duration_value)
        else:
            # Default to hours
            return base_time + timedelta(hours=duration_value)
    
    async def _log_provisioning(
        self,
        customer_id: int,
        router_id: int,
        mac_address: str,
        action: str,
        status: str,
        details: Optional[str] = None,
        error: Optional[str] = None
    ):
        """Log provisioning action to database"""
        try:
            await self.db.execute(text("""
                INSERT INTO provisioning_logs 
                (customer_id, router_id, mac_address, action, status, details, error, log_date)
                VALUES (:customer_id, :router_id, :mac_address, :action, :status, :details, :error, NOW())
            """), {
                'customer_id': customer_id,
                'router_id': router_id,
                'mac_address': mac_address,
                'action': action,
                'status': status,
                'details': details,
                'error': error
            })
            await self.db.commit()
        except Exception as e:
            logger.warning(f"Failed to log provisioning: {e}")


async def should_use_radius(db: AsyncSession, router_id: int) -> Tuple[bool, Optional[Dict]]:
    """
    Check if a router should use RADIUS authentication.
    
    Returns:
        Tuple of (use_radius: bool, router_config: dict or None)
    """
    result = await db.execute(text("""
        SELECT id, auth_method, radius_secret, radius_nas_identifier, ip_address
        FROM routers WHERE id = :router_id
    """), {'router_id': router_id})
    
    row = result.fetchone()
    
    if not row:
        return False, None
    
    use_radius = row.auth_method == 'RADIUS'
    
    config = {
        'router_id': row.id,
        'auth_method': row.auth_method,
        'radius_secret': row.radius_secret,
        'nas_identifier': row.radius_nas_identifier,
        'ip_address': row.ip_address
    }
    
    return use_radius, config


async def provision_customer_auto(
    db: AsyncSession,
    customer_id: int,
    mac_address: str,
    phone: str,
    plan_speed: str,
    plan_duration_value: int,
    plan_duration_unit: str,
    router_id: int,
    existing_expiry: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    Auto-provision a customer based on router's auth_method.
    
    This is a convenience function that checks the router's configuration
    and uses either RADIUS or direct API provisioning.
    
    If the router uses RADIUS, this function handles it.
    If the router uses DIRECT_API, this returns a signal to use the existing code.
    
    Usage:
        result = await provision_customer_auto(db, customer_id, ...)
        if result.get('use_direct_api'):
            # Use existing mikrotik_api.add_customer_bypass_mode()
        else:
            # RADIUS provisioning done, result contains credentials
    """
    use_radius, router_config = await should_use_radius(db, router_id)
    
    if not use_radius:
        # Signal to caller to use existing direct API provisioning
        return {
            'use_direct_api': True,
            'auth_method': 'DIRECT_API'
        }
    
    # Use RADIUS provisioning
    provisioning = RadiusProvisioning(db)
    result = await provisioning.provision_hotspot_user(
        customer_id=customer_id,
        mac_address=mac_address,
        phone=phone,
        plan_speed=plan_speed,
        plan_duration_value=plan_duration_value,
        plan_duration_unit=plan_duration_unit,
        router_id=router_id,
        existing_expiry=existing_expiry
    )
    
    result['use_direct_api'] = False
    return result
