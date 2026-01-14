import socket
import struct
import re
import hashlib
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import json  # Ensure you import json for serializing logs

# Initialize logger
logger = logging.getLogger("mikrotik_api")
logger.setLevel(logging.INFO)

# Helper functions to validate and normalize MAC addresses
def validate_mac_address(mac: str) -> bool:
    """Validate MAC address format"""
    mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(mac_pattern, mac))

def normalize_mac_address(mac: str) -> str:
    """Normalize MAC address to XX:XX:XX:XX:XX:XX format"""
    clean_mac = re.sub(r'[:-]', '', mac.upper())
    return ':'.join(clean_mac[i:i+2] for i in range(0, 12, 2))

class MikroTikAPI:
    def __init__(self, host: str, username: str, password: str, port: int = 8728, timeout: int = 10):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.connected = False

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            return self.login()
        except Exception as e:
            logger.error(f"Connection failed to {self.host}: {e}")
            return False

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
            self.connected = False

    def encode_length(self, length: int) -> bytes:
        if length < 0x80:
            return struct.pack('B', length)
        elif length < 0x4000:
            length |= 0x8000
            return struct.pack('>H', length)
        elif length < 0x200000:
            length |= 0xC00000
            return struct.pack('>I', length)[1:]
        elif length < 0x10000000:
            length |= 0xE0000000
            return struct.pack('>I', length)
        else:
            return struct.pack('B', 0xF0) + struct.pack('>I', length)

    def decode_length(self) -> int:
        c = struct.unpack('B', self.sock.recv(1))[0]
        if (c & 0x80) == 0:
            return c
        elif (c & 0xC0) == 0x80:
            return ((c & ~0xC0) << 8) + struct.unpack('B', self.sock.recv(1))[0]
        elif (c & 0xE0) == 0xC0:
            return ((c & ~0xE0) << 16) + struct.unpack('>H', self.sock.recv(2))[0]
        elif (c & 0xF0) == 0xE0:
            return ((c & ~0xF0) << 24) + struct.unpack('>I', b'\x00' + self.sock.recv(3))[0]
        elif (c & 0xF8) == 0xF0:
            return struct.unpack('>I', self.sock.recv(4))[0]

    def send_word(self, word: str):
        encoded_word = word.encode('utf-8')
        self.sock.send(self.encode_length(len(encoded_word)) + encoded_word)

    def read_word(self) -> str:
        length = self.decode_length()
        if length == 0:
            return ""
        return self.sock.recv(length).decode('utf-8')

    def send_sentence(self, words: List[str]):
        for word in words:
            self.send_word(word)
        self.send_word("")

    def read_sentence(self) -> List[str]:
        sentence = []
        while True:
            try:
                word = self.read_word()
                if word == "":
                    break
                sentence.append(word)
            except Exception as e:
                logger.error(f"Error reading word in sentence: {e}")
                break
        return sentence

    def login(self) -> bool:
        try:
            self.send_sentence(["/login", f"=name={self.username}", f"=password={self.password}"])
            response = self.read_sentence()
            if response and response[0] == "!done":
                self.connected = True
                logger.info(f"Successfully logged in to {self.host}")
                return True
            else:
                logger.error(f"Login failed to {self.host}: {response}")
                return False
        except Exception as e:
            logger.error(f"Login error to {self.host}: {e}")
            return False

    def send_command(self, command: str, arguments: Dict[str, str] = None) -> Dict[str, Any]:
        if not self.connected:
            return {"error": "Not connected"}
        
        try:
            # Prepare command
            words = [command]
            if arguments:
                for key, value in arguments.items():
                    words.append(f"={key}={value}")
            
            # Send command
            self.send_sentence(words)
            
            # Read response
            responses = []
            while True:
                sentence = self.read_sentence()
                logger.info(f"Raw sentence received for command {command}: {sentence}")  # Debug log
                if not sentence:
                    break
                    
                if sentence[0] == "!done":
                    break
                elif sentence[0] == "!re":
                    # Parse response data
                    data = {}
                    for item in sentence[1:]:
                        if item.startswith("="):
                            key_value = item[1:].split("=", 1)
                            if len(key_value) == 2:
                                data[key_value[0]] = key_value[1]
                    responses.append(data)
                elif sentence[0] == "!trap":
                    error_msg = ""
                    for item in sentence[1:]:
                        if item.startswith("=message="):
                            error_msg = item[9:]
                    return {"error": error_msg or "Command failed"}
            
            return {"success": True, "data": responses}
        except Exception as e:
            logger.error(f"Command execution error on {self.host}: {e}")
            return {"error": str(e)}

    def _parse_speed_to_mikrotik(self, speed: str) -> str:
        """
        Convert speed string (e.g., '2Mbps', '5 Mbps', '512Kbps') to MikroTik format (e.g., '2M/2M').
        Returns symmetric upload/download limit.
        """
        if not speed:
            return ""
        
        # Already in MikroTik format (contains /)
        if "/" in speed:
            return speed
        
        # Clean and parse the speed string
        speed_clean = speed.upper().replace(" ", "")
        
        # Extract numeric value and unit
        match = re.match(r'^(\d+(?:\.\d+)?)\s*(K|M|G)?(?:BPS)?$', speed_clean)
        if match:
            value = match.group(1)
            unit = match.group(2) or "M"  # Default to Mbps
            mikrotik_speed = f"{value}{unit}"
            return f"{mikrotik_speed}/{mikrotik_speed}"
        
        # Fallback: try to use as-is if it looks like a number
        if speed_clean.replace(".", "").isdigit():
            return f"{speed_clean}M/{speed_clean}M"
        
        logger.warning(f"Could not parse speed '{speed}', using default 10M/10M")
        return "10M/10M"

    def _ensure_hotspot_profile(self, profile_name: str, rate_limit: str) -> Dict[str, Any]:
        """
        Ensure a hotspot user profile exists with the specified rate limit.
        Creates or updates the profile.
        """
        # Check if profile exists
        profiles = self.send_command("/ip/hotspot/user/profile/print")
        profile_exists = False
        profile_id = None
        
        if profiles.get("success") and profiles.get("data"):
            for profile in profiles["data"]:
                if profile.get("name") == profile_name:
                    profile_exists = True
                    profile_id = profile.get(".id")
                    break
        
        profile_args = {
            "name": profile_name,
            "rate-limit": rate_limit,  # Format: upload/download e.g., "2M/2M"
        }
        
        if profile_exists:
            # Update existing profile
            profile_args["numbers"] = profile_id
            result = self.send_command("/ip/hotspot/user/profile/set", profile_args)
            logger.info(f"Updated hotspot profile '{profile_name}' with rate-limit {rate_limit}")
        else:
            # Create new profile
            result = self.send_command("/ip/hotspot/user/profile/add", profile_args)
            logger.info(f"Created hotspot profile '{profile_name}' with rate-limit {rate_limit}")
        
        return result

    def add_customer_bypass_mode(
        self, mac_address: str, username: str, password: str,
        time_limit: str, bandwidth_limit: str, comment: str,
        router_ip: str, router_username: str, router_password: str
    ) -> Dict[str, Any]:
        try:
            # Convert bandwidth to MikroTik format
            rate_limit = self._parse_speed_to_mikrotik(bandwidth_limit)
            
            payload = {
                'mac_address': mac_address,
                'username': username,
                'password': password,
                'time_limit': time_limit,
                'bandwidth_limit': bandwidth_limit,
                'rate_limit_parsed': rate_limit,
                'comment': comment,
                'router_ip': router_ip,
                'router_username': router_username,
                'router_password': router_password
            }
            logger.info(f"Sending the following payload to MikroTik: {json.dumps(payload, indent=2)}")

            # 1. Create/update hotspot user profile with rate limit (this is key for speed enforcement!)
            profile_name = f"plan_{rate_limit.replace('/', '_')}"
            profile_result = self._ensure_hotspot_profile(profile_name, rate_limit)
            
            # 2. Add or update hotspot user WITH the rate-limited profile
            args = {
                "name": username,
                "password": password,
                "profile": profile_name,  # Use rate-limited profile instead of "default"
                "limit-uptime": time_limit,
                "comment": comment
            }
            result = self.send_command("/ip/hotspot/user/add", args)
            if "error" in result:
                if "already have user with this name" in result["error"]:
                    # Update existing user with new profile and limits
                    update_args = {
                        "numbers": username,
                        "profile": profile_name,
                        "limit-uptime": time_limit,
                        "comment": comment
                    }
                    update_result = self.send_command("/ip/hotspot/user/set", update_args)
                    logger.info(f"User {username} exists. Updated with profile {profile_name}: {update_result}")
                else:
                    logger.error(f"Hotspot user add error: {result['error']}")
                    return {"error": result["error"]}

            # 3. IP binding (bypassed with comment tracking for our DB-based expiry)
            # We use "bypassed" for seamless auto-login, but rely on our cron job to
            # remove the binding when the DB expiry is reached (not MikroTik's limit-uptime)
            binding_args = {
                "mac-address": mac_address,
                "type": "bypassed",
                "comment": f"USER:{username}|EXPIRES:DB_MANAGED|{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            }
            binding_result = self.send_command("/ip/hotspot/ip-binding/add", binding_args)
            if "error" in binding_result:
                if "such client already exists" in binding_result["error"]:
                    # Update existing binding
                    bindings = self.send_command("/ip/hotspot/ip-binding/print")
                    if bindings.get("success") and bindings.get("data"):
                        for b in bindings["data"]:
                            if normalize_mac_address(b.get("mac-address", "")) == normalize_mac_address(mac_address):
                                self.send_command("/ip/hotspot/ip-binding/set", {
                                    "numbers": b[".id"],
                                    "type": "bypassed",
                                    "comment": f"USER:{username}|EXPIRES:DB_MANAGED|{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                                })
                                logger.info(f"Updated existing IP binding for {mac_address}")
                                break
                else:
                    logger.error(f"IP binding error: {binding_result['error']}")
                    return {"error": binding_result["error"]}

            # 4. Create simple queue for bandwidth limiting (profile rate-limit doesn't apply to bypassed users!)
            queue_result = None
            if rate_limit:
                # Find client's current IP from multiple sources
                client_ip = None
                normalized = normalize_mac_address(mac_address)
                
                # Try 1: DHCP leases (most reliable - client may already have a lease)
                leases = self.send_command("/ip/dhcp-server/lease/print")
                if leases.get("success") and leases.get("data"):
                    for lease in leases["data"]:
                        lease_mac = lease.get("mac-address", "").upper()
                        if normalize_mac_address(lease_mac) == normalized:
                            client_ip = lease.get("address")
                            logger.info(f"Found IP {client_ip} from DHCP lease for {mac_address}")
                            break
                
                # Try 2: Hotspot active sessions
                if not client_ip:
                    active = self.send_command("/ip/hotspot/active/print")
                    if active.get("success") and active.get("data"):
                        for session in active["data"]:
                            session_mac = session.get("mac-address", "").upper()
                            if normalize_mac_address(session_mac) == normalized:
                                client_ip = session.get("address")
                                logger.info(f"Found IP {client_ip} from active session for {mac_address}")
                                break
                
                # Try 3: Hotspot hosts table
                if not client_ip:
                    hosts = self.send_command("/ip/hotspot/host/print")
                    if hosts.get("success") and hosts.get("data"):
                        for host in hosts["data"]:
                            host_mac = host.get("mac-address", "").upper()
                            if normalize_mac_address(host_mac) == normalized:
                                client_ip = host.get("address")
                                logger.info(f"Found IP {client_ip} from hotspot host for {mac_address}")
                                break
                
                # Try 4: ARP table
                if not client_ip:
                    arp = self.send_command("/ip/arp/print")
                    if arp.get("success") and arp.get("data"):
                        for entry in arp["data"]:
                            entry_mac = entry.get("mac-address", "").upper()
                            if normalize_mac_address(entry_mac) == normalized:
                                client_ip = entry.get("address")
                                logger.info(f"Found IP {client_ip} from ARP for {mac_address}")
                                break
                
                if client_ip:
                    queue_args = {
                        "name": f"queue_{username}",
                        "target": f"{client_ip}/32",
                        "max-limit": rate_limit,
                        "comment": f"Bandwidth limit for MAC: {mac_address} -> IP: {client_ip}"
                    }
                    # Try to update existing queue first
                    queue_set_result = self.send_command("/queue/simple/set", {
                        "numbers": f"queue_{username}",
                        "target": f"{client_ip}/32",
                        "max-limit": rate_limit
                    })
                    if "error" in queue_set_result:
                        queue_result = self.send_command("/queue/simple/add", queue_args)
                    else:
                        queue_result = queue_set_result
                    logger.info(f"Created/updated queue for {username} targeting {client_ip} with limit {rate_limit}")
                else:
                    # Client not connected yet - queue will need to be created when they connect
                    # The hotspot profile rate-limit is a fallback but may not work for bypassed users
                    logger.warning(f"Client {mac_address} not currently connected. Queue not created - speed limit may not apply until reconnect!")

            return {
                "message": f"MAC address {mac_address} registered/updated successfully with rate limit {rate_limit}",
                "user_details": {
                    "username": username,
                    "mac_address": mac_address,
                    "time_limit": time_limit,
                    "bandwidth_limit": bandwidth_limit,
                    "rate_limit": rate_limit,
                    "profile": profile_name
                },
                "profile_result": profile_result,
                "hotspot_user_result": result,
                "ip_binding_result": binding_result,
                "queue_result": queue_result
            }

        except Exception as e:
            logger.error(f"Error while adding customer in bypass mode: {e}")
            return {"error": str(e)}


    def remove_bypassed_user(self, mac_address: str) -> dict:
        if not self.connected:
            return {"error": "Not connected"}
        try:
            normalized_mac = normalize_mac_address(mac_address)
            username = normalized_mac.replace(":", "")
            results = {}

            # 1. Remove IP binding - match by MAC or name field
            bindings = self.send_command("/ip/hotspot/ip-binding/print")
            results["ip_binding_removed"] = 0
            if bindings.get("success") and bindings.get("data"):
                for binding in bindings["data"]:
                    binding_mac = binding.get("mac-address", "").upper()
                    binding_name = binding.get("name", "").upper()
                    # Match by MAC address OR by name field
                    if binding_mac == normalized_mac.upper() or binding_name == username.upper():
                        binding_id = binding.get(".id")
                        if binding_id:
                            self.send_command("/ip/hotspot/ip-binding/remove", {"numbers": binding_id})
                            results["ip_binding_removed"] += 1
                            logger.info(f"Removed IP binding: {binding_name} ({binding_mac})")

            # 2. Remove Hotspot user
            users = self.send_command("/ip/hotspot/user/print")
            results["hotspot_user_removed"] = False
            if users.get("success") and users.get("data"):
                for user in users["data"]:
                    if user.get("name", "").upper() == username.upper():
                        user_id = user.get(".id")
                        if user_id:
                            self.send_command("/ip/hotspot/user/remove", {"numbers": user_id})
                            results["hotspot_user_removed"] = True

            # 3. Remove simple queue - search by name OR MAC in comment
            queues = self.send_command("/queue/simple/print")
            results["queue_removed"] = 0
            if queues.get("success") and queues.get("data"):
                for queue in queues["data"]:
                    queue_name = queue.get("name", "")
                    queue_comment = queue.get("comment", "")
                    # Match by queue name OR by MAC address in comment
                    if (queue_name == f"queue_{username}" or 
                        normalized_mac.upper() in queue_comment.upper() or
                        mac_address.upper() in queue_comment.upper()):
                        queue_id = queue.get(".id")
                        if queue_id:
                            self.send_command("/queue/simple/remove", {"numbers": queue_id})
                            results["queue_removed"] += 1
                            logger.info(f"Removed queue: {queue_name}")

            # 4. Remove DHCP lease
            leases = self.send_command("/ip/dhcp-server/lease/print")
            results["dhcp_lease_removed"] = 0
            logger.info(f"[DHCP] Searching for leases to remove. Target MAC: {normalized_mac}")
            if leases.get("success") and leases.get("data"):
                logger.info(f"[DHCP] Found {len(leases['data'])} total DHCP leases")
                for lease in leases["data"]:
                    lease_mac = lease.get("mac-address", "")
                    lease_ip = lease.get("address", "N/A")
                    lease_id = lease.get(".id", "N/A")
                    logger.info(f"[DHCP] Checking lease: ID={lease_id}, MAC={lease_mac}, IP={lease_ip}")
                    if lease_mac:
                        # Normalize both MACs to compare without separators
                        lease_mac_clean = re.sub(r'[:-]', '', lease_mac.upper())
                        normalized_mac_clean = re.sub(r'[:-]', '', normalized_mac.upper())
                        logger.info(f"[DHCP] Comparing: '{lease_mac_clean}' vs '{normalized_mac_clean}'")
                        if lease_mac_clean == normalized_mac_clean:
                            lease_id = lease.get(".id")
                            if lease_id:
                                remove_result = self.send_command("/ip/dhcp-server/lease/remove", {"numbers": lease_id})
                                results["dhcp_lease_removed"] += 1
                                logger.info(f"[DHCP] ✓ Removed DHCP lease: {lease_mac} (ID: {lease_id}, IP: {lease_ip})")
                                if "error" in remove_result:
                                    logger.error(f"[DHCP] Remove command returned error: {remove_result['error']}")
                        else:
                            logger.info(f"[DHCP] ✗ No match, skipping")
                    else:
                        logger.warning(f"[DHCP] Lease {lease_id} has no MAC address")
            else:
                logger.warning(f"[DHCP] Failed to fetch leases or no data returned: {leases}")
            
            logger.info(f"[DHCP] Total leases removed: {results['dhcp_lease_removed']}")

            # 5. Disconnect active sessions (CRITICAL - prevents re-login issues)
            active_sessions = self.send_command("/ip/hotspot/active/print")
            results["sessions_disconnected"] = 0
            if active_sessions.get("success") and active_sessions.get("data"):
                for session in active_sessions["data"]:
                    session_user = session.get("user", "").upper()
                    session_mac = session.get("mac-address", "").upper()
                    # Match by username OR MAC address
                    if session_user == username.upper() or session_mac == normalized_mac.upper():
                        session_id = session.get(".id")
                        if session_id:
                            self.send_command("/ip/hotspot/active/remove", {"numbers": session_id})
                            results["sessions_disconnected"] += 1
                            logger.info(f"Disconnected active session: {session_user} ({session_mac})")

            return {"success": True, "details": results}
        except Exception as e:
            logger.error(f"Error removing bypassed user {mac_address}: {e}")
            return {"error": str(e)}

    def get_system_resources(self) -> Dict[str, Any]:
        """Get MikroTik system resource information (CPU, memory, disk, uptime)"""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/system/resource/print")
            if result.get("success") and result.get("data"):
                data = result["data"][0] if result["data"] else {}
                return {
                    "success": True,
                    "data": {
                        "uptime": data.get("uptime", ""),
                        "version": data.get("version", ""),
                        "build_time": data.get("build-time", ""),
                        "cpu": data.get("cpu", ""),
                        "cpu_count": int(data.get("cpu-count", 1)),
                        "cpu_frequency": int(data.get("cpu-frequency", 0)),
                        "cpu_load": int(data.get("cpu-load", 0)),
                        "free_memory": int(data.get("free-memory", 0)),
                        "total_memory": int(data.get("total-memory", 0)),
                        "free_hdd_space": int(data.get("free-hdd-space", 0)),
                        "total_hdd_space": int(data.get("total-hdd-space", 0)),
                        "architecture_name": data.get("architecture-name", ""),
                        "board_name": data.get("board-name", ""),
                        "platform": data.get("platform", "")
                    }
                }
            return {"error": "No resource data returned"}
        except Exception as e:
            logger.error(f"Error getting system resources: {e}")
            return {"error": str(e)}

    def get_interface_traffic(self, interface: str = None) -> Dict[str, Any]:
        """Get interface traffic statistics. If interface is None, gets all interfaces."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/interface/print")
            if result.get("success") and result.get("data"):
                interfaces = []
                for iface in result["data"]:
                    if interface and iface.get("name") != interface:
                        continue
                    interfaces.append({
                        "name": iface.get("name", ""),
                        "type": iface.get("type", ""),
                        "running": iface.get("running") == "true",
                        "disabled": iface.get("disabled") == "true",
                        "rx_byte": int(iface.get("rx-byte", 0)),
                        "tx_byte": int(iface.get("tx-byte", 0)),
                        "rx_packet": int(iface.get("rx-packet", 0)),
                        "tx_packet": int(iface.get("tx-packet", 0)),
                        "rx_error": int(iface.get("rx-error", 0)),
                        "tx_error": int(iface.get("tx-error", 0))
                    })
                return {"success": True, "data": interfaces}
            return {"error": "No interface data returned"}
        except Exception as e:
            logger.error(f"Error getting interface traffic: {e}")
            return {"error": str(e)}

    def get_active_hotspot_users(self) -> Dict[str, Any]:
        """Get all active hotspot sessions with traffic stats"""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ip/hotspot/active/print")
            if result.get("success"):
                sessions = []
                for session in result.get("data", []):
                    sessions.append({
                        "user": session.get("user", ""),
                        "address": session.get("address", ""),
                        "mac_address": session.get("mac-address", ""),
                        "uptime": session.get("uptime", ""),
                        "bytes_in": int(session.get("bytes-in", 0)),
                        "bytes_out": int(session.get("bytes-out", 0)),
                        "packets_in": int(session.get("packets-in", 0)),
                        "packets_out": int(session.get("packets-out", 0)),
                        "idle_time": session.get("idle-time", "")
                    })
                return {"success": True, "data": sessions}
            return {"error": "Failed to get active sessions"}
        except Exception as e:
            logger.error(f"Error getting active hotspot users: {e}")
            return {"error": str(e)}

    def get_health(self) -> Dict[str, Any]:
        """Get system health (temperature, voltage if available)"""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/system/health/print")
            if result.get("success") and result.get("data"):
                health = {}
                for item in result["data"]:
                    name = item.get("name", "")
                    value = item.get("value", "")
                    if name and value:
                        health[name] = value
                return {"success": True, "data": health}
            return {"success": True, "data": {}}  # Some devices don't have health sensors
        except Exception as e:
            logger.error(f"Error getting system health: {e}")
            return {"error": str(e)}

    def block_mac_address(self, mac_address: str) -> Dict[str, Any]:
        """Block a MAC address by changing IP binding to 'blocked' type"""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            normalized_mac = normalize_mac_address(mac_address)
            
            # Find existing binding
            bindings = self.send_command("/ip/hotspot/ip-binding/print")
            if bindings.get("success") and bindings.get("data"):
                for b in bindings["data"]:
                    if normalize_mac_address(b.get("mac-address", "")) == normalized_mac:
                        # Change to blocked type
                        result = self.send_command("/ip/hotspot/ip-binding/set", {
                            "numbers": b[".id"],
                            "type": "blocked",
                            "comment": f"EXPIRED|{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        })
                        logger.info(f"Blocked MAC {mac_address}")
                        return {"success": True, "action": "blocked_existing"}
            
            # If no binding exists, create a blocked one
            result = self.send_command("/ip/hotspot/ip-binding/add", {
                "mac-address": mac_address,
                "type": "blocked",
                "comment": f"EXPIRED|{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            })
            if result.get("error"):
                return {"error": result["error"]}
            return {"success": True, "action": "created_blocked"}
        except Exception as e:
            logger.error(f"Error blocking MAC {mac_address}: {e}")
            return {"error": str(e)}

    def disconnect_by_ip(self, ip_address: str) -> Dict[str, Any]:
        """Force disconnect a client by IP address"""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            # Remove from hotspot hosts (this forces immediate disconnect)
            hosts = self.send_command("/ip/hotspot/host/print")
            removed = 0
            if hosts.get("success") and hosts.get("data"):
                for host in hosts["data"]:
                    if host.get("address") == ip_address:
                        self.send_command("/ip/hotspot/host/remove", {"numbers": host[".id"]})
                        removed += 1
                        logger.info(f"Removed host entry for IP {ip_address}")
            return {"success": True, "removed": removed}
        except Exception as e:
            logger.error(f"Error disconnecting IP {ip_address}: {e}")
            return {"error": str(e)}

    def get_client_ip_by_mac(self, mac_address: str) -> Optional[str]:
        """Get client's current IP address by MAC from ARP or DHCP"""
        if not self.connected:
            return None
        try:
            normalized_mac = normalize_mac_address(mac_address)
            
            # Check ARP table
            arp = self.send_command("/ip/arp/print")
            if arp.get("success") and arp.get("data"):
                for entry in arp["data"]:
                    if normalize_mac_address(entry.get("mac-address", "")) == normalized_mac:
                        return entry.get("address")
            
            # Check DHCP leases
            leases = self.send_command("/ip/dhcp-server/lease/print")
            if leases.get("success") and leases.get("data"):
                for lease in leases["data"]:
                    if normalize_mac_address(lease.get("mac-address", "")) == normalized_mac:
                        return lease.get("address")
            
            return None
        except Exception as e:
            logger.error(f"Error getting IP for MAC {mac_address}: {e}")
            return None
