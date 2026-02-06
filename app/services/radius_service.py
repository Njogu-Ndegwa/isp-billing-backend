"""
RADIUS Service Module for ISP Billing
=====================================

This module handles all RADIUS-related operations:
- Creating/updating RADIUS users (hotspot authentication)
- Managing bandwidth limits via RADIUS attributes
- Session timeout management
- Disconnecting users via CoA (Change of Authorization)
- Accounting queries

This is a COMPLETELY SEPARATE implementation from the direct MikroTik API approach.
It does not modify or interfere with the existing mikrotik_api.py functionality.

Usage:
    from app.services.radius_service import RadiusService
    
    radius = RadiusService(db_session)
    await radius.create_user(username, password, plan)
"""

import logging
import socket
import struct
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, select, delete, update
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RadiusUserConfig:
    """Configuration for a RADIUS user"""
    username: str
    password: str
    # Bandwidth in format "download/upload" e.g., "2M/2M" or "5M/5M"
    rate_limit: Optional[str] = None
    # Session timeout in seconds (how long until session expires)
    session_timeout: Optional[int] = None
    # Idle timeout in seconds (disconnect if no activity)
    idle_timeout: Optional[int] = 1800  # 30 minutes default
    # Expiry datetime (after this, user cannot authenticate)
    expiry: Optional[datetime] = None
    # Link to customer in ISP Billing database
    customer_id: Optional[int] = None
    # Simultaneous sessions allowed (1 = only one device)
    simultaneous_use: int = 1


class RadiusService:
    """
    Service for managing RADIUS users and sessions.
    
    This service interacts with the RADIUS database tables to:
    - Create users with authentication credentials
    - Set bandwidth limits and session timeouts
    - Track active sessions via accounting
    - Disconnect users via Change of Authorization (CoA)
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_user(self, config: RadiusUserConfig) -> Dict[str, Any]:
        """
        Create a new RADIUS user with all necessary attributes.
        
        This creates entries in:
        - radius_check: Authentication (password, simultaneous-use)
        - radius_reply: Reply attributes (bandwidth, session timeout)
        
        Args:
            config: RadiusUserConfig with user settings
            
        Returns:
            Dict with created user info
        """
        try:
            # First, remove any existing entries for this user (clean slate)
            await self._delete_user_entries(config.username)
            
            # Create authentication check entries
            check_entries = [
                # Password (Cleartext-Password for PAP, or use NT-Password for MS-CHAP)
                {
                    'username': config.username,
                    'attribute': 'Cleartext-Password',
                    'op': ':=',
                    'value': config.password,
                    'expiry': config.expiry,
                    'customer_id': config.customer_id
                },
                # Limit simultaneous connections
                {
                    'username': config.username,
                    'attribute': 'Simultaneous-Use',
                    'op': ':=',
                    'value': str(config.simultaneous_use),
                    'expiry': config.expiry,
                    'customer_id': config.customer_id
                }
            ]
            
            # Insert check entries
            for entry in check_entries:
                await self.db.execute(text("""
                    INSERT INTO radius_check (username, attribute, op, value, expiry, customer_id)
                    VALUES (:username, :attribute, :op, :value, :expiry, :customer_id)
                """), entry)
            
            # Create reply attributes (sent back to NAS)
            reply_entries = []
            
            # Bandwidth limit (MikroTik specific attribute)
            if config.rate_limit:
                reply_entries.append({
                    'username': config.username,
                    'attribute': 'Mikrotik-Rate-Limit',
                    'op': ':=',
                    'value': config.rate_limit,
                    'expiry': config.expiry,
                    'customer_id': config.customer_id
                })
            
            # Session timeout (absolute session time limit)
            if config.session_timeout:
                reply_entries.append({
                    'username': config.username,
                    'attribute': 'Session-Timeout',
                    'op': ':=',
                    'value': str(config.session_timeout),
                    'expiry': config.expiry,
                    'customer_id': config.customer_id
                })
            
            # Idle timeout (disconnect after inactivity)
            if config.idle_timeout:
                reply_entries.append({
                    'username': config.username,
                    'attribute': 'Idle-Timeout',
                    'op': ':=',
                    'value': str(config.idle_timeout),
                    'expiry': config.expiry,
                    'customer_id': config.customer_id
                })
            
            # Acct-Interim-Interval (how often router sends accounting updates)
            # This helps track bandwidth usage in real-time
            reply_entries.append({
                'username': config.username,
                'attribute': 'Acct-Interim-Interval',
                'op': ':=',
                'value': '300',  # Every 5 minutes
                'expiry': config.expiry,
                'customer_id': config.customer_id
            })
            
            # Insert reply entries
            for entry in reply_entries:
                await self.db.execute(text("""
                    INSERT INTO radius_reply (username, attribute, op, value, expiry, customer_id)
                    VALUES (:username, :attribute, :op, :value, :expiry, :customer_id)
                """), entry)
            
            await self.db.commit()
            
            logger.info(f"RADIUS user created: {config.username}")
            
            return {
                'success': True,
                'username': config.username,
                'rate_limit': config.rate_limit,
                'session_timeout': config.session_timeout,
                'expiry': config.expiry.isoformat() if config.expiry else None
            }
            
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Failed to create RADIUS user {config.username}: {e}")
            raise
    
    async def update_user_expiry(
        self, 
        username: str, 
        new_expiry: datetime,
        new_session_timeout: Optional[int] = None
    ) -> bool:
        """
        Update a user's expiry date and optionally session timeout.
        
        Args:
            username: RADIUS username
            new_expiry: New expiry datetime
            new_session_timeout: New session timeout in seconds (optional)
            
        Returns:
            True if updated, False if user not found
        """
        try:
            # Update expiry in check table
            result = await self.db.execute(text("""
                UPDATE radius_check 
                SET expiry = :expiry, updated_at = NOW()
                WHERE username = :username
            """), {'username': username, 'expiry': new_expiry})
            
            # Update expiry in reply table
            await self.db.execute(text("""
                UPDATE radius_reply 
                SET expiry = :expiry, updated_at = NOW()
                WHERE username = :username
            """), {'username': username, 'expiry': new_expiry})
            
            # Update session timeout if provided
            if new_session_timeout:
                await self.db.execute(text("""
                    UPDATE radius_reply 
                    SET value = :value, updated_at = NOW()
                    WHERE username = :username AND attribute = 'Session-Timeout'
                """), {'username': username, 'value': str(new_session_timeout)})
            
            await self.db.commit()
            
            return result.rowcount > 0
            
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Failed to update RADIUS user {username}: {e}")
            raise
    
    async def update_user_bandwidth(self, username: str, rate_limit: str) -> bool:
        """
        Update a user's bandwidth limit.
        
        Args:
            username: RADIUS username
            rate_limit: New rate limit (e.g., "5M/5M")
            
        Returns:
            True if updated, False if user not found
        """
        try:
            result = await self.db.execute(text("""
                UPDATE radius_reply 
                SET value = :value, updated_at = NOW()
                WHERE username = :username AND attribute = 'Mikrotik-Rate-Limit'
            """), {'username': username, 'value': rate_limit})
            
            await self.db.commit()
            
            return result.rowcount > 0
            
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Failed to update bandwidth for {username}: {e}")
            raise
    
    async def delete_user(self, username: str) -> bool:
        """
        Delete a RADIUS user completely.
        
        This removes all entries from radius_check and radius_reply.
        Note: This does NOT disconnect active sessions. Use disconnect_user() for that.
        
        Args:
            username: RADIUS username
            
        Returns:
            True if deleted, False if user not found
        """
        try:
            result = await self._delete_user_entries(username)
            await self.db.commit()
            return result
            
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Failed to delete RADIUS user {username}: {e}")
            raise
    
    async def _delete_user_entries(self, username: str) -> bool:
        """Delete user entries from check and reply tables (internal)"""
        result1 = await self.db.execute(text("""
            DELETE FROM radius_check WHERE username = :username
        """), {'username': username})
        
        await self.db.execute(text("""
            DELETE FROM radius_reply WHERE username = :username
        """), {'username': username})
        
        await self.db.execute(text("""
            DELETE FROM radius_usergroup WHERE username = :username
        """), {'username': username})
        
        return result1.rowcount > 0
    
    async def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Get a RADIUS user's configuration.
        
        Returns:
            Dict with user info or None if not found
        """
        check_result = await self.db.execute(text("""
            SELECT username, attribute, value, expiry, customer_id 
            FROM radius_check WHERE username = :username
        """), {'username': username})
        
        check_rows = check_result.fetchall()
        if not check_rows:
            return None
        
        reply_result = await self.db.execute(text("""
            SELECT attribute, value FROM radius_reply WHERE username = :username
        """), {'username': username})
        
        reply_rows = reply_result.fetchall()
        
        user_info = {
            'username': username,
            'expiry': None,
            'customer_id': None,
            'check_attributes': {},
            'reply_attributes': {}
        }
        
        for row in check_rows:
            user_info['check_attributes'][row.attribute] = row.value
            if row.expiry:
                user_info['expiry'] = row.expiry
            if row.customer_id:
                user_info['customer_id'] = row.customer_id
        
        for row in reply_rows:
            user_info['reply_attributes'][row.attribute] = row.value
        
        return user_info
    
    async def get_active_sessions(
        self, 
        username: Optional[str] = None,
        nas_ip: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get active sessions from accounting table.
        
        Active sessions have acctstarttime but no acctstoptime.
        
        Args:
            username: Filter by username (optional)
            nas_ip: Filter by NAS IP address (optional)
            
        Returns:
            List of active session dicts
        """
        query = """
            SELECT 
                acctsessionid, username, nasipaddress, 
                framedipaddress, callingstationid,
                acctstarttime, acctupdatetime, acctsessiontime,
                acctinputoctets, acctoutputoctets
            FROM radius_accounting 
            WHERE acctstoptime IS NULL
        """
        
        params = {}
        
        if username:
            query += " AND username = :username"
            params['username'] = username
        
        if nas_ip:
            query += " AND nasipaddress = :nas_ip"
            params['nas_ip'] = nas_ip
        
        query += " ORDER BY acctstarttime DESC"
        
        result = await self.db.execute(text(query), params)
        rows = result.fetchall()
        
        sessions = []
        for row in rows:
            sessions.append({
                'session_id': row.acctsessionid,
                'username': row.username,
                'nas_ip': row.nasipaddress,
                'client_ip': row.framedipaddress,
                'mac_address': row.callingstationid,
                'start_time': row.acctstarttime,
                'last_update': row.acctupdatetime,
                'session_time': row.acctsessiontime,
                'bytes_in': row.acctinputoctets or 0,
                'bytes_out': row.acctoutputoctets or 0
            })
        
        return sessions
    
    async def get_session_statistics(
        self, 
        username: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get session statistics for a user.
        
        Returns aggregate stats: total sessions, total bytes, total time.
        """
        query = """
            SELECT 
                COUNT(*) as total_sessions,
                COALESCE(SUM(acctsessiontime), 0) as total_time,
                COALESCE(SUM(acctinputoctets), 0) as total_bytes_in,
                COALESCE(SUM(acctoutputoctets), 0) as total_bytes_out
            FROM radius_accounting 
            WHERE username = :username
        """
        
        params = {'username': username}
        
        if start_date:
            query += " AND acctstarttime >= :start_date"
            params['start_date'] = start_date
        
        if end_date:
            query += " AND (acctstoptime <= :end_date OR acctstoptime IS NULL)"
            params['end_date'] = end_date
        
        result = await self.db.execute(text(query), params)
        row = result.fetchone()
        
        return {
            'username': username,
            'total_sessions': row.total_sessions,
            'total_time_seconds': row.total_time,
            'total_bytes_in': row.total_bytes_in,
            'total_bytes_out': row.total_bytes_out,
            'total_bytes': row.total_bytes_in + row.total_bytes_out
        }
    
    async def cleanup_expired_users(self) -> int:
        """
        Remove expired RADIUS users from the database.
        
        This removes users whose expiry date has passed.
        Note: Active sessions are handled by RADIUS - they'll fail on re-auth.
        
        Returns:
            Number of users removed
        """
        try:
            # Get expired usernames first
            result = await self.db.execute(text("""
                SELECT DISTINCT username FROM radius_check 
                WHERE expiry IS NOT NULL AND expiry < NOW()
            """))
            
            expired_users = [row.username for row in result.fetchall()]
            
            if not expired_users:
                return 0
            
            # Delete from check table
            await self.db.execute(text("""
                DELETE FROM radius_check 
                WHERE expiry IS NOT NULL AND expiry < NOW()
            """))
            
            # Delete from reply table
            await self.db.execute(text("""
                DELETE FROM radius_reply 
                WHERE expiry IS NOT NULL AND expiry < NOW()
            """))
            
            await self.db.commit()
            
            logger.info(f"Cleaned up {len(expired_users)} expired RADIUS users")
            
            return len(expired_users)
            
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Failed to cleanup expired RADIUS users: {e}")
            raise
    
    async def get_users_by_customer_id(self, customer_id: int) -> List[str]:
        """Get all RADIUS usernames associated with a customer ID"""
        result = await self.db.execute(text("""
            SELECT DISTINCT username FROM radius_check 
            WHERE customer_id = :customer_id
        """), {'customer_id': customer_id})
        
        return [row.username for row in result.fetchall()]


class RadiusCoA:
    """
    RADIUS Change of Authorization (CoA) client.
    
    Used to disconnect users or change their attributes in real-time.
    Sends CoA packets to the NAS (MikroTik router).
    
    Note: MikroTik must have RADIUS incoming enabled:
        /radius incoming set accept=yes port=3799
    """
    
    def __init__(self, nas_ip: str, secret: str, coa_port: int = 3799):
        """
        Initialize CoA client.
        
        Args:
            nas_ip: IP address of the NAS (router)
            secret: RADIUS shared secret
            coa_port: CoA port (default 3799 for MikroTik)
        """
        self.nas_ip = nas_ip
        self.secret = secret.encode()
        self.coa_port = coa_port
    
    def disconnect_user(
        self, 
        username: Optional[str] = None,
        session_id: Optional[str] = None,
        framed_ip: Optional[str] = None,
        calling_station_id: Optional[str] = None,
        timeout: float = 5.0
    ) -> Tuple[bool, str]:
        """
        Send a Disconnect-Request to terminate a user's session.
        
        You must provide at least one identifier (username, session_id, framed_ip, or calling_station_id).
        
        Args:
            username: User-Name attribute
            session_id: Acct-Session-Id attribute
            framed_ip: Framed-IP-Address attribute
            calling_station_id: Calling-Station-Id (MAC address)
            timeout: Socket timeout in seconds
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not any([username, session_id, framed_ip, calling_station_id]):
            return False, "At least one identifier must be provided"
        
        try:
            # Build RADIUS Disconnect-Request packet
            packet = self._build_disconnect_packet(
                username=username,
                session_id=session_id,
                framed_ip=framed_ip,
                calling_station_id=calling_station_id
            )
            
            # Send packet
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            try:
                sock.sendto(packet, (self.nas_ip, self.coa_port))
                response, _ = sock.recvfrom(4096)
                
                # Parse response code
                code = response[0]
                
                if code == 41:  # Disconnect-ACK
                    return True, "User disconnected successfully"
                elif code == 42:  # Disconnect-NAK
                    return False, "Disconnect rejected by NAS"
                else:
                    return False, f"Unexpected response code: {code}"
                    
            finally:
                sock.close()
                
        except socket.timeout:
            return False, "Timeout waiting for NAS response"
        except Exception as e:
            return False, f"CoA error: {str(e)}"
    
    def _build_disconnect_packet(
        self,
        username: Optional[str] = None,
        session_id: Optional[str] = None,
        framed_ip: Optional[str] = None,
        calling_station_id: Optional[str] = None
    ) -> bytes:
        """Build a RADIUS Disconnect-Request packet"""
        # Packet ID (random)
        packet_id = secrets.randbelow(256)
        
        # Build attributes
        attributes = b''
        
        if username:
            # User-Name (type 1)
            attr_value = username.encode()
            attributes += struct.pack('!BB', 1, len(attr_value) + 2) + attr_value
        
        if session_id:
            # Acct-Session-Id (type 44)
            attr_value = session_id.encode()
            attributes += struct.pack('!BB', 44, len(attr_value) + 2) + attr_value
        
        if framed_ip:
            # Framed-IP-Address (type 8)
            ip_bytes = socket.inet_aton(framed_ip)
            attributes += struct.pack('!BB', 8, 6) + ip_bytes
        
        if calling_station_id:
            # Calling-Station-Id (type 31)
            attr_value = calling_station_id.encode()
            attributes += struct.pack('!BB', 31, len(attr_value) + 2) + attr_value
        
        # Calculate length
        length = 20 + len(attributes)  # 20 = header size
        
        # Build header with placeholder authenticator
        header = struct.pack('!BBH', 40, packet_id, length)  # 40 = Disconnect-Request
        authenticator = b'\x00' * 16  # Placeholder
        
        # Calculate authenticator
        packet = header + authenticator + attributes
        authenticator = hashlib.md5(packet + self.secret).digest()
        
        # Rebuild with correct authenticator
        return header + authenticator + attributes


# Helper functions for common operations

def parse_speed_to_radius_format(speed: str) -> str:
    """
    Convert speed string to MikroTik RADIUS rate-limit format.
    
    Input formats: "2Mbps", "5 Mbps", "512Kbps", "10M"
    Output format: "2M/2M" (download/upload, symmetric)
    
    Args:
        speed: Speed string in various formats
        
    Returns:
        MikroTik rate-limit format string
    """
    speed = speed.strip().upper()
    
    # Remove common suffixes
    speed = speed.replace('BPS', '').replace('PS', '').replace(' ', '')
    
    # Extract number and unit
    number = ''
    unit = ''
    
    for char in speed:
        if char.isdigit() or char == '.':
            number += char
        else:
            unit += char
    
    if not number:
        return "1M/1M"  # Default
    
    # Normalize unit
    if unit in ['K', 'KB']:
        unit = 'k'
    elif unit in ['M', 'MB', '']:
        unit = 'M'
    elif unit in ['G', 'GB']:
        unit = 'G'
    else:
        unit = 'M'  # Default to Mbps
    
    rate = f"{number}{unit}"
    return f"{rate}/{rate}"  # Symmetric rate


def calculate_session_timeout(duration_value: int, duration_unit: str) -> int:
    """
    Calculate session timeout in seconds from duration.
    
    Args:
        duration_value: Duration value (e.g., 24)
        duration_unit: Unit (HOURS, DAYS, MINUTES)
        
    Returns:
        Timeout in seconds
    """
    multipliers = {
        'MINUTES': 60,
        'HOURS': 3600,
        'DAYS': 86400
    }
    
    return duration_value * multipliers.get(duration_unit.upper(), 3600)
