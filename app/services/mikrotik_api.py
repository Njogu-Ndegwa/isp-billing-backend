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
    def __init__(self, host: str, username: str, password: str, port: int = 8728):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.sock = None
        self.connected = False

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)  # 10 second timeout
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
            word = self.read_word()
            if word == "":
                break
            sentence.append(word)
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

    def add_customer_bypass_mode(
        self, mac_address: str, username: str, password: str,
        time_limit: str, bandwidth_limit: str, comment: str,
        router_ip: str, router_username: str, router_password: str
    ) -> Dict[str, Any]:
        try:
            payload = {
                'mac_address': mac_address,
                'username': username,
                'password': password,
                'time_limit': time_limit,
                'bandwidth_limit': bandwidth_limit,
                'comment': comment,
                'router_ip': router_ip,
                'router_username': router_username,
                'router_password': router_password
            }
            logger.info(f"Sending the following payload to MikroTik: {json.dumps(payload, indent=2)}")

            # 1. Add or update hotspot user
            args = {
                "name": username,
                "password": password,
                "profile": "default",
                "limit-uptime": time_limit,
                "comment": comment
            }
            result = self.send_command("/ip/hotspot/user/add", args)
            if "error" in result:
                if "already have user with this name" in result["error"]:
                    # Update limit/comment if already exists
                    update_args = {
                        "numbers": username,
                        "limit-uptime": time_limit,
                        "comment": comment
                    }
                    update_result = self.send_command("/ip/hotspot/user/set", update_args)
                    logger.info(f"User {username} exists. Updated: {update_result}")
                else:
                    logger.error(f"Hotspot user add error: {result['error']}")
                    return {"error": result["error"]}

            # 2. IP binding (bypassed)
            binding_args = {
                "mac-address": mac_address,
                "type": "bypassed",
                "comment": f"Auto-registered (bypassed): {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            }
            binding_result = self.send_command("/ip/hotspot/ip-binding/add", binding_args)
            if "error" in binding_result:
                if "such client already exists" in binding_result["error"]:
                    logger.info(f"IP binding already exists for {mac_address}")
                else:
                    logger.error(f"IP binding error: {binding_result['error']}")
                    return {"error": binding_result["error"]}

            # 3. Bandwidth control (DHCP + queue)
            dhcp_lease_result = None
            queue_result = None
            assigned_ip = None
            if bandwidth_limit:
                mac_hash = int(hashlib.md5(mac_address.encode()).hexdigest()[:4], 16)
                assigned_ip = f"192.168.1.{100 + (mac_hash % 150)}"
                dhcp_lease_args = {
                    "mac-address": mac_address,
                    "address": assigned_ip,
                    "server": "defconf",
                    "comment": f"Auto-assigned for bandwidth control: {mac_address}"
                }
                dhcp_lease_result = self.send_command("/ip/dhcp-server/lease/add", dhcp_lease_args)
                if "error" in dhcp_lease_result:
                    if "already have" in dhcp_lease_result["error"]:
                        logger.info(f"DHCP lease already exists for {mac_address}")
                    else:
                        logger.error(f"DHCP lease error: {dhcp_lease_result['error']}")
                        return {"error": dhcp_lease_result["error"]}
                # Always try to set queue (idempotent)
                queue_args = {
                    "name": f"queue_{username}",
                    "target": f"{assigned_ip}/32",
                    "max-limit": bandwidth_limit,
                    "comment": f"Bandwidth limit for MAC: {mac_address} -> IP: {assigned_ip}"
                }
                queue_set_result = self.send_command("/queue/simple/set", queue_args)
                if "error" in queue_set_result and "no such item" in queue_set_result["error"]:
                    queue_result = self.send_command("/queue/simple/add", queue_args)
                else:
                    queue_result = queue_set_result

            return {
                "message": f"MAC address {mac_address} registered/updated successfully with bypassed authentication",
                "user_details": {
                    "username": username,
                    "mac_address": mac_address,
                    "time_limit": time_limit,
                    "bandwidth_limit": bandwidth_limit,
                    "assigned_ip": assigned_ip
                },
                "hotspot_user_result": result,
                "ip_binding_result": binding_result,
                "dhcp_lease_result": dhcp_lease_result,
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

            # 1. Remove IP binding
            bindings = self.send_command("/ip/hotspot/ip-binding/print")
            results["ip_binding_removed"] = False
            if bindings.get("success") and bindings.get("data"):
                for binding in bindings["data"]:
                    if binding.get("mac-address", "").upper() == normalized_mac.upper() and \
                    binding.get("type", "").lower() == "bypassed":
                        binding_id = binding.get(".id")
                        if binding_id:
                            self.send_command("/ip/hotspot/ip-binding/remove", {"numbers": binding_id})
                            results["ip_binding_removed"] = True

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

            # 3. Remove simple queue
            queues = self.send_command("/queue/simple/print")
            results["queue_removed"] = False
            if queues.get("success") and queues.get("data"):
                for queue in queues["data"]:
                    if queue.get("name") == f"queue_{username}":
                        queue_id = queue.get(".id")
                        if queue_id:
                            self.send_command("/queue/simple/remove", {"numbers": queue_id})
                            results["queue_removed"] = True

            # 4. Remove DHCP lease
            leases = self.send_command("/ip/dhcp-server/lease/print")
            results["dhcp_lease_removed"] = False
            if leases.get("success") and leases.get("data"):
                for lease in leases["data"]:
                    if lease.get("mac-address", "").upper() == normalized_mac.upper():
                        lease_id = lease.get(".id")
                        if lease_id:
                            self.send_command("/ip/dhcp-server/lease/remove", {"numbers": lease_id})
                            results["dhcp_lease_removed"] = True

            # 5. Disconnect active sessions
            active_sessions = self.send_command("/ip/hotspot/active/print")
            results["sessions_disconnected"] = 0
            if active_sessions.get("success") and active_sessions.get("data"):
                for session in active_sessions["data"]:
                    if session.get("user", "").upper() == username.upper():
                        session_id = session.get(".id")
                        if session_id:
                            self.send_command("/ip/hotspot/active/remove", {"numbers": session_id})
                            results["sessions_disconnected"] += 1

            return {"success": True, "details": results}
        except Exception as e:
            logger.error(f"Error removing bypassed user {mac_address}: {e}")
            return {"error": str(e)}
