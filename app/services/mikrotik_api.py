import socket
import struct
import re
import hashlib
import logging
import time
import ipaddress
from typing import Dict, Any, Optional, List
from datetime import datetime
import json  # Ensure you import json for serializing logs

# Initialize logger
logger = logging.getLogger("mikrotik_api")
logger.setLevel(logging.WARNING)  # Reduce noise, only warnings/errors

# Address-list and rule comments used to ensure queued clients are excluded from FastTrack.
QUEUE_FASTTRACK_BYPASS_LIST = "isp_queue_limited_clients"
QUEUE_FASTTRACK_BYPASS_SRC_COMMENT = "ISP_BILLING_QUEUE_BYPASS_SRC"
QUEUE_FASTTRACK_BYPASS_DST_COMMENT = "ISP_BILLING_QUEUE_BYPASS_DST"

DUAL_BRIDGE_NAME = "bridge-dual"
DUAL_BRIDGE_IP = "192.168.91.1/24"
DUAL_HOTSPOT_POOL_NAME = "dual-hotspot-pool"
DUAL_HOTSPOT_POOL_RANGE = "192.168.91.2-192.168.91.254"
DUAL_DHCP_SERVER_NAME = "dhcp-dual"
DUAL_HOTSPOT_PROFILE_NAME = "hsprof-dual"
DUAL_HOTSPOT_SERVER_NAME = "hotspot-dual"
DUAL_HOTSPOT_NAT_COMMENT = "NAT for dual hotspot clients"


def _router_error_is_duplicate(error: str) -> bool:
    """Return True when RouterOS is reporting an idempotent duplicate/existing object."""
    if not error:
        return False
    err = error.lower()
    duplicate_markers = (
        "already exists",
        "already have",
        "such name exists",
        "such address exists",
        "already added",
        "already have such address",
    )
    return any(marker in err for marker in duplicate_markers)

# ============================================================================
# CIRCUIT BREAKER: Track failed routers to avoid repeated blocking timeouts
# Only triggers on CONNECTION failures, not read timeouts during operations
# ============================================================================
_router_failures: Dict[str, Dict[str, Any]] = {}
CIRCUIT_BREAKER_THRESHOLD = 3  # Number of connection failures before circuit opens
CIRCUIT_BREAKER_RESET_TIME = 60  # Seconds to wait before retrying failed router

def _get_router_key(host: str, port: int) -> str:
    """Generate unique key for a router"""
    return f"{host}:{port}"

def _is_circuit_open(host: str, port: int) -> bool:
    """Check if circuit breaker is open (router should be skipped)"""
    key = _get_router_key(host, port)
    if key not in _router_failures:
        return False
    
    failure_info = _router_failures[key]
    # Check if enough time has passed to retry
    if time.time() - failure_info["last_failure"] > CIRCUIT_BREAKER_RESET_TIME:
        # Reset the circuit breaker - allow retry
        del _router_failures[key]
        logger.info(f"Circuit breaker reset for {host}:{port} - allowing retry")
        return False
    
    # Circuit is open if we've exceeded threshold
    return failure_info["count"] >= CIRCUIT_BREAKER_THRESHOLD

def _record_failure(host: str, port: int):
    """Record a connection failure for circuit breaker"""
    key = _get_router_key(host, port)
    if key not in _router_failures:
        _router_failures[key] = {"count": 0, "last_failure": 0}
    
    _router_failures[key]["count"] += 1
    _router_failures[key]["last_failure"] = time.time()
    
    count = _router_failures[key]["count"]
    if count >= CIRCUIT_BREAKER_THRESHOLD:
        logger.warning(f"Circuit breaker OPEN for {host}:{port} - will skip for {CIRCUIT_BREAKER_RESET_TIME}s")

def _record_success(host: str, port: int):
    """Record a successful connection - reset circuit breaker"""
    key = _get_router_key(host, port)
    if key in _router_failures:
        del _router_failures[key]
        logger.info(f"Circuit breaker cleared for {host}:{port} after successful connection")

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
    def __init__(self, host: str, username: str, password: str, port: int = 8728, 
                 timeout: int = 15, connect_timeout: int = 5):
        """
        Initialize MikroTik API connection.
        
        Args:
            host: Router IP address
            username: API username
            password: API password
            port: API port (default 8728)
            timeout: Read/write timeout in seconds (default 15s)
            connect_timeout: Initial connection timeout in seconds (default 5s)
        """
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.sock = None
        self.connected = False

    def connect(self) -> bool:
        """
        Connect to MikroTik router with circuit breaker protection.
        Uses short connect_timeout for initial connection, then switches to 
        regular timeout for operations.
        """
        # Check circuit breaker first - avoid blocking on known-bad routers
        if _is_circuit_open(self.host, self.port):
            logger.warning(f"Circuit breaker OPEN - skipping connection to {self.host}:{self.port}")
            return False
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Use short timeout for initial connection attempt
            self.sock.settimeout(self.connect_timeout)
            self.sock.connect((self.host, self.port))
            # Switch to regular timeout for read/write operations
            self.sock.settimeout(self.timeout)
            
            if self.login():
                _record_success(self.host, self.port)
                return True
            else:
                _record_failure(self.host, self.port)
                return False
        except socket.timeout:
            logger.error(f"Connection timed out to {self.host}:{self.port} (timeout: {self.connect_timeout}s)")
            _record_failure(self.host, self.port)
            self._cleanup_socket()
            return False
        except ConnectionRefusedError:
            logger.error(f"Connection refused by {self.host}:{self.port}")
            _record_failure(self.host, self.port)
            self._cleanup_socket()
            return False
        except OSError as e:
            logger.error(f"Network error connecting to {self.host}:{self.port}: {e}")
            _record_failure(self.host, self.port)
            self._cleanup_socket()
            return False
        except Exception as e:
            logger.error(f"Connection failed to {self.host}: {e}")
            _record_failure(self.host, self.port)
            self._cleanup_socket()
            return False
    
    def _cleanup_socket(self):
        """Clean up socket on error"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
        self.connected = False

    def disconnect(self):
        """Disconnect from router and clean up"""
        self._cleanup_socket()
        self.connected = False

    def _safe_int(self, value, default=0) -> int:
        """Safely convert a value to int, handling empty strings and None"""
        if value is None or value == "":
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

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
        c = struct.unpack('B', self._recv_all(1))[0]
        if (c & 0x80) == 0:
            return c
        elif (c & 0xC0) == 0x80:
            return ((c & ~0xC0) << 8) + struct.unpack('B', self._recv_all(1))[0]
        elif (c & 0xE0) == 0xC0:
            return ((c & ~0xE0) << 16) + struct.unpack('>H', self._recv_all(2))[0]
        elif (c & 0xF0) == 0xE0:
            return ((c & ~0xF0) << 24) + struct.unpack('>I', b'\x00' + self._recv_all(3))[0]
        elif (c & 0xF8) == 0xF0:
            return struct.unpack('>I', self._recv_all(4))[0]

    def send_word(self, word: str):
        encoded_word = word.encode('utf-8')
        self.sock.send(self.encode_length(len(encoded_word)) + encoded_word)

    def _recv_all(self, length: int) -> bytes:
        """Read exactly *length* bytes from the socket.
        TCP recv() may return fewer bytes than requested when data spans
        multiple segments; this loops until every byte is collected."""
        buf = bytearray()
        while len(buf) < length:
            chunk = self.sock.recv(length - len(buf))
            if not chunk:
                raise ConnectionError("Socket closed while reading")
            buf.extend(chunk)
        return bytes(buf)

    def read_word(self) -> str:
        length = self.decode_length()
        if length == 0:
            return ""
        return self._recv_all(length).decode('utf-8')

    def send_sentence(self, words: List[str]):
        for word in words:
            self.send_word(word)
        self.send_word("")

    def read_sentence(self) -> List[str]:
        """Read a complete sentence from MikroTik. Handles timeouts gracefully."""
        sentence = []
        while True:
            try:
                word = self.read_word()
                if word == "":
                    break
                sentence.append(word)
            except socket.timeout:
                logger.warning(f"Read timeout from {self.host} - connection stale, will reconnect")
                # Mark connection as stale - but DON'T trigger circuit breaker
                # Read timeouts during operation are transient, not connection failures
                self.connected = False
                break
            except Exception as e:
                logger.error(f"Error reading word in sentence: {e}")
                self.connected = False
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
            connection_lost = False
            error_msg = ""
            while True:
                sentence = self.read_sentence()
                logger.info(f"Raw sentence received for command {command}: {sentence}")  # Debug log
                if not sentence:
                    if not self.connected:
                        connection_lost = True
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
                    for item in sentence[1:]:
                        if item.startswith("=message="):
                            error_msg = item[9:]
                elif sentence[0] == "!fatal":
                    for item in sentence[1:]:
                        if item.startswith("=message="):
                            error_msg = item[9:]

            if connection_lost:
                return {"error": "Not connected"}
            if error_msg:
                return {"error": error_msg or "Command failed"}
            
            return {"success": True, "data": responses}
        except Exception as e:
            logger.error(f"Command execution error on {self.host}: {e}")
            return {"error": str(e)}

    def send_command_optimized(self, command: str, proplist: list = None, query: str = None) -> Dict[str, Any]:
        """
        Send command with optimization options for large datasets.
        
        Args:
            command: The MikroTik API command (e.g., "/ip/arp/print")
            proplist: List of properties to fetch (reduces data transfer significantly)
                      e.g., [".id", "mac-address", "address", "interface"]
            query: Optional query filter (e.g., "?interface=bridge" to filter server-side)
        
        Returns:
            Dict with success status and data
        
        Example:
            # Instead of fetching ALL ARP properties (slow):
            api.send_command("/ip/arp/print")
            
            # Fetch only what we need (fast):
            api.send_command_optimized("/ip/arp/print", 
                proplist=[".id", "mac-address", "address", "interface"])
        """
        if not self.connected:
            return {"error": "Not connected"}
        
        try:
            words = [command]
            
            # Add proplist to limit returned properties (major bandwidth saver)
            if proplist:
                words.append(f"=.proplist={','.join(proplist)}")
            
            # Add query filter if specified
            if query:
                words.append(query)
            
            self.send_sentence(words)
            
            responses = []
            connection_lost = False
            error_msg = ""
            while True:
                sentence = self.read_sentence()
                if not sentence:
                    if not self.connected:
                        connection_lost = True
                    break
                    
                if sentence[0] == "!done":
                    break
                elif sentence[0] == "!re":
                    data = {}
                    for item in sentence[1:]:
                        if item.startswith("="):
                            key_value = item[1:].split("=", 1)
                            if len(key_value) == 2:
                                data[key_value[0]] = key_value[1]
                    responses.append(data)
                elif sentence[0] == "!trap":
                    for item in sentence[1:]:
                        if item.startswith("=message="):
                            error_msg = item[9:]
                elif sentence[0] == "!fatal":
                    for item in sentence[1:]:
                        if item.startswith("=message="):
                            error_msg = item[9:]

            if connection_lost:
                return {"error": "Not connected"}
            if error_msg:
                return {"error": error_msg or "Command failed"}
            
            return {"success": True, "data": responses}
        except Exception as e:
            logger.error(f"Optimized command execution error on {self.host}: {e}")
            return {"error": str(e)}
    
    # Pre-defined optimized fetches for common operations
    def get_arp_minimal(self) -> Dict[str, Any]:
        """Fetch ARP table with only essential fields (fast)."""
        return self.send_command_optimized(
            "/ip/arp/print",
            proplist=[".id", "mac-address", "address", "interface", "complete"]
        )
    
    def get_dhcp_leases_minimal(self) -> Dict[str, Any]:
        """Fetch DHCP leases with only essential fields (fast)."""
        return self.send_command_optimized(
            "/ip/dhcp-server/lease/print",
            proplist=[".id", "mac-address", "address", "host-name", "server", "status"]
        )
    
    def get_hotspot_active_minimal(self) -> Dict[str, Any]:
        """Fetch active hotspot sessions with essential fields."""
        return self.send_command_optimized(
            "/ip/hotspot/active/print",
            proplist=[".id", "mac-address", "address", "user", "uptime", "bytes-in", "bytes-out"]
        )

    def get_hotspot_hosts_minimal(self) -> Dict[str, Any]:
        """Fetch hotspot hosts with essential fields (includes bypassed clients)."""
        return self.send_command_optimized(
            "/ip/hotspot/host/print",
            proplist=[".id", "mac-address", "address", "to-address", "authorized", "bypassed"]
        )
    
    def get_ip_bindings_minimal(self) -> Dict[str, Any]:
        """Fetch IP bindings with essential fields."""
        return self.send_command_optimized(
            "/ip/hotspot/ip-binding/print",
            proplist=[".id", "mac-address", "address", "type", "comment"]
        )
    
    def get_hotspot_users_minimal(self) -> Dict[str, Any]:
        """Fetch hotspot users with essential fields."""
        return self.send_command_optimized(
            "/ip/hotspot/user/print",
            proplist=[".id", "name", "profile", "comment"]
        )
    
    def get_simple_queues_minimal(self) -> Dict[str, Any]:
        """Fetch simple queues with essential fields."""
        return self.send_command_optimized(
            "/queue/simple/print",
            proplist=[".id", "name", "target", "max-limit", "disabled", "comment"]
        )

    def get_hotspot_user_by_name(self, username: str) -> Dict[str, Any]:
        """Fetch a single hotspot user by username."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.get_hotspot_users_minimal()
            if not result.get("success"):
                return {"error": result.get("error", "Failed to get hotspot users")}

            wanted = str(username or "").strip().lower()
            for user in result.get("data", []):
                if str(user.get("name", "")).strip().lower() == wanted:
                    return {"success": True, "found": True, "data": user}

            return {"success": True, "found": False, "data": None}
        except Exception as e:
            logger.error(f"Error getting hotspot user {username}: {e}")
            return {"error": str(e)}

    def get_ip_binding_by_mac(self, mac_address: str) -> Dict[str, Any]:
        """Fetch a single hotspot IP binding by MAC address."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.get_ip_bindings_minimal()
            if not result.get("success"):
                return {"error": result.get("error", "Failed to get hotspot IP bindings")}

            wanted = normalize_mac_address(mac_address)
            for binding in result.get("data", []):
                binding_mac = binding.get("mac-address", "")
                if binding_mac and normalize_mac_address(binding_mac) == wanted:
                    return {"success": True, "found": True, "data": binding}

            return {"success": True, "found": False, "data": None}
        except Exception as e:
            logger.error(f"Error getting IP binding for {mac_address}: {e}")
            return {"error": str(e)}

    def get_online_state_by_mac(self, mac_address: str) -> Dict[str, Any]:
        """
        Best-effort online state for a hotspot client.

        A client is considered online when:
        - an active hotspot session exists for the MAC, or
        - a hotspot host entry exists with authorized=true or bypassed=true.
        """
        if not self.connected:
            return {"error": "Not connected"}
        try:
            wanted = normalize_mac_address(mac_address)

            active_sessions = self.get_hotspot_active_minimal()
            if active_sessions.get("success"):
                for session in active_sessions.get("data", []):
                    session_mac = session.get("mac-address", "")
                    if session_mac and normalize_mac_address(session_mac) == wanted:
                        return {
                            "success": True,
                            "online": True,
                            "source": "active",
                            "details": session,
                        }
            elif active_sessions.get("error"):
                return {"error": active_sessions["error"]}

            hosts = self.get_hotspot_hosts_minimal()
            if hosts.get("success"):
                for host in hosts.get("data", []):
                    host_mac = host.get("mac-address", "")
                    if not host_mac or normalize_mac_address(host_mac) != wanted:
                        continue

                    authorized = str(host.get("authorized", "")).lower() == "true"
                    bypassed = str(host.get("bypassed", "")).lower() == "true"
                    if authorized or bypassed:
                        return {
                            "success": True,
                            "online": True,
                            "source": "host",
                            "details": host,
                        }

            elif hosts.get("error"):
                return {"error": hosts["error"]}

            return {"success": True, "online": False, "source": None, "details": None}
        except Exception as e:
            logger.error(f"Error getting hotspot online state for {mac_address}: {e}")
            return {"error": str(e)}

    def remove_hotspot_parent_queues(self) -> Dict[str, Any]:
        """
        Remove MikroTik's auto-generated hotspot parent simple queue(s).

        When the hotspot service (re)starts, MikroTik recreates a dynamic simple
        queue named ``hs-<hotspot-server-name>`` whose target is the hotspot
        bridge interface and whose max-limit defaults to ``unlimited/unlimited``.
        Because simple queues are matched top-down and this entry sits at
        position 0 on the bridge interface, it shadows every per-user
        ``plan_<username>`` queue we create for rate limiting - the net effect
        is that all hotspot users suddenly receive unlimited speeds.

        This helper deletes any simple queue whose name starts with ``hs-`` so
        the per-IP ``plan_<username>`` queues can match traffic again. It is
        safe to call repeatedly; MikroTik will regenerate the queue on hotspot
        service restart / router reboot, and the next provisioning or sync run
        will clean it up again.
        """
        if not self.connected:
            return {"error": "Not connected"}
        try:
            queues = self.send_command("/queue/simple/print")
            if not queues.get("success"):
                return {"error": queues.get("error", "Failed to read simple queues")}

            removed = 0
            errors: List[str] = []
            for q in queues.get("data", []) or []:
                name = str(q.get("name", ""))
                if not name.startswith("hs-"):
                    continue
                qid = q.get(".id")
                if not qid:
                    continue
                remove_result = self.send_command("/queue/simple/remove", {"numbers": qid})
                if remove_result.get("error"):
                    errors.append(f"{name}: {remove_result['error']}")
                    logger.warning(
                        "Failed to remove hotspot parent queue %s (id=%s): %s",
                        name, qid, remove_result["error"],
                    )
                else:
                    removed += 1
                    logger.warning(
                        "Removed auto-generated hotspot parent queue %s "
                        "(target=%s, max-limit=%s) - it was shadowing per-user plan queues",
                        name, q.get("target"), q.get("max-limit"),
                    )

            return {"success": True, "removed": removed, "errors": errors}
        except Exception as e:
            logger.error(f"Error removing hotspot parent queues: {e}")
            return {"error": str(e)}

    def ensure_queue_fasttrack_bypass(self, client_ips: List[str]) -> Dict[str, Any]:
        """
        Ensure queued client IPs are excluded from FastTrack so simple queues can enforce limits.
        Creates/updates:
        - Address list: `isp_queue_limited_clients`
        - Two forward accept rules (src + dst) placed before FastTrack
        """
        if not self.connected:
            return {"error": "Not connected"}

        try:
            normalized_ips = sorted({str(ip).strip() for ip in client_ips if ip and str(ip).strip()})
            if not normalized_ips:
                return {"success": True, "fasttrack_enabled": False, "ips_added": 0}

            filters_result = self.send_command_optimized(
                "/ip/firewall/filter/print",
                proplist=[
                    ".id",
                    "chain",
                    "action",
                    "disabled",
                    "comment",
                    "src-address-list",
                    "dst-address-list"
                ]
            )
            if not filters_result.get("success"):
                return {"error": "Failed to read firewall filter rules"}

            filter_rules = filters_result.get("data", [])
            fasttrack_rule = None
            for rule in filter_rules:
                if (
                    rule.get("chain") == "forward"
                    and rule.get("action") == "fasttrack-connection"
                    and str(rule.get("disabled", "false")).lower() != "true"
                ):
                    fasttrack_rule = rule
                    break

            if not fasttrack_rule:
                return {"success": True, "fasttrack_enabled": False, "ips_added": 0}

            address_list_result = self.send_command_optimized(
                "/ip/firewall/address-list/print",
                proplist=[".id", "list", "address", "comment"]
            )
            existing_ips = set()
            if address_list_result.get("success"):
                for entry in address_list_result.get("data", []):
                    if entry.get("list") == QUEUE_FASTTRACK_BYPASS_LIST and entry.get("address"):
                        existing_ips.add(entry["address"])

            ips_added = 0
            for ip in normalized_ips:
                if ip in existing_ips:
                    continue
                add_ip_result = self.send_command("/ip/firewall/address-list/add", {
                    "list": QUEUE_FASTTRACK_BYPASS_LIST,
                    "address": ip,
                    "comment": "Managed by ISP Billing queue sync"
                })
                if not add_ip_result.get("error"):
                    ips_added += 1

            for rule in filter_rules:
                if (
                    rule.get("chain") == "forward"
                    and rule.get("comment") in {
                        QUEUE_FASTTRACK_BYPASS_SRC_COMMENT,
                        QUEUE_FASTTRACK_BYPASS_DST_COMMENT
                    }
                    and rule.get(".id")
                ):
                    self.send_command("/ip/firewall/filter/remove", {"numbers": rule[".id"]})

            fasttrack_id = fasttrack_rule.get(".id")
            if fasttrack_id:
                self.send_command("/ip/firewall/filter/add", {
                    "chain": "forward",
                    "action": "accept",
                    "src-address-list": QUEUE_FASTTRACK_BYPASS_LIST,
                    "comment": QUEUE_FASTTRACK_BYPASS_SRC_COMMENT,
                    "place-before": fasttrack_id
                })
                self.send_command("/ip/firewall/filter/add", {
                    "chain": "forward",
                    "action": "accept",
                    "dst-address-list": QUEUE_FASTTRACK_BYPASS_LIST,
                    "comment": QUEUE_FASTTRACK_BYPASS_DST_COMMENT,
                    "place-before": fasttrack_id
                })

            return {
                "success": True,
                "fasttrack_enabled": True,
                "ips_added": ips_added,
                "list_name": QUEUE_FASTTRACK_BYPASS_LIST
            }
        except Exception as e:
            logger.error(f"Error ensuring FastTrack bypass for queued clients: {e}")
            return {"error": str(e)}

    def _parse_speed_to_mikrotik(self, speed: str) -> str:
        """
        Convert speed string (e.g., '2Mbps', '5 Mbps', '512Kbps') to MikroTik format (e.g., '2M/2M').
        Returns symmetric upload/download limit (uses download speed for both).
        """
        if not speed:
            return ""
        
        # If already in MikroTik format (contains /), make symmetric using download speed
        if "/" in speed:
            download = speed.split("/")[0].strip()
            return f"{download}/{download}"
        
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
        import time
        # Rate limiting: small delays between commands to prevent overwhelming MikroTik
        CMD_DELAY = 0.05  # 50ms between commands
        
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
            time.sleep(CMD_DELAY)  # Give router breathing room
            
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
                    existing_user = self.get_hotspot_user_by_name(username)
                    if existing_user.get("error"):
                        logger.error(f"Failed to read existing hotspot user {username}: {existing_user['error']}")
                        return {"error": existing_user["error"]}
                    if not existing_user.get("found") or not existing_user.get("data"):
                        return {"error": f"Hotspot user {username} already existed but could not be found for update"}

                    update_args = {
                        "numbers": existing_user["data"].get(".id") or username,
                        "profile": profile_name,
                        "limit-uptime": time_limit,
                        "comment": comment
                    }
                    update_result = self.send_command("/ip/hotspot/user/set", update_args)
                    logger.info(f"User {username} exists. Updated with profile {profile_name}: {update_result}")
                    if update_result.get("error"):
                        return {"error": update_result["error"]}
                    result = update_result
                else:
                    logger.error(f"Hotspot user add error: {result['error']}")
                    return {"error": result["error"]}
            time.sleep(CMD_DELAY)  # Give router breathing room

            # 3. IP binding (bypassed for seamless auto-access after payment)
            binding_args = {
                "mac-address": mac_address,
                "type": "bypassed",
                "comment": f"USER:{username}|EXPIRES:DB_MANAGED|{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            }
            binding_result = self.send_command("/ip/hotspot/ip-binding/add", binding_args)
            if "error" in binding_result:
                if "already exists" in binding_result.get("error", ""):
                    existing_binding = self.get_ip_binding_by_mac(mac_address)
                    if existing_binding.get("error"):
                        logger.error(f"Failed to read existing IP binding for {mac_address}: {existing_binding['error']}")
                        return {"error": existing_binding["error"]}
                    if not existing_binding.get("found") or not existing_binding.get("data"):
                        return {"error": f"IP binding for {mac_address} already existed but could not be found for update"}

                    time.sleep(CMD_DELAY)
                    binding_result = self.send_command("/ip/hotspot/ip-binding/set", {
                        "numbers": existing_binding["data"].get(".id"),
                        "type": "bypassed",
                        "comment": f"USER:{username}|EXPIRES:DB_MANAGED|{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    })
                    logger.info(f"Updated existing IP binding for {mac_address}: {binding_result}")
                    if binding_result.get("error"):
                        return {"error": binding_result["error"]}
                else:
                    logger.error(f"IP binding error: {binding_result['error']}")
                    return {"error": binding_result["error"]}
            time.sleep(CMD_DELAY)  # Give router breathing room

            # 4. Kick client from hotspot hosts/active sessions so the bypass
            #    binding takes effect immediately.  Without this, clients already
            #    sitting in the "unauthorized" state keep being redirected to the
            #    captive portal until they manually reconnect.
            kick_result = {"hosts_removed": 0, "sessions_removed": 0}
            normalized_kick = normalize_mac_address(mac_address)

            # 4a. Remove from hotspot active sessions
            try:
                active_sessions = self.send_command("/ip/hotspot/active/print")
                if active_sessions.get("success") and active_sessions.get("data"):
                    for session in active_sessions["data"]:
                        session_mac = session.get("mac-address", "")
                        if session_mac and normalize_mac_address(session_mac) == normalized_kick:
                            session_id = session.get(".id")
                            if session_id:
                                time.sleep(CMD_DELAY)
                                remove_result = self.send_command("/ip/hotspot/active/remove", {"numbers": session_id})
                                if remove_result.get("error"):
                                    kick_result.setdefault("session_errors", []).append(remove_result["error"])
                                else:
                                    kick_result["sessions_removed"] += 1
                                    logger.warning(
                                        "Removed active hotspot session for %s to apply bypass", mac_address
                                    )
            except Exception as kick_err:
                logger.warning("Non-fatal: failed to remove active sessions for %s: %s", mac_address, kick_err)

            time.sleep(CMD_DELAY)

            # 4b. Remove from hotspot hosts table (covers unauthorized/blocked clients)
            try:
                hosts = self.send_command("/ip/hotspot/host/print")
                if hosts.get("success") and hosts.get("data"):
                    for host in hosts["data"]:
                        host_mac = host.get("mac-address", "")
                        if host_mac and normalize_mac_address(host_mac) == normalized_kick:
                            host_id = host.get(".id")
                            if host_id:
                                time.sleep(CMD_DELAY)
                                remove_result = self.send_command("/ip/hotspot/host/remove", {"numbers": host_id})
                                if remove_result.get("error"):
                                    kick_result.setdefault("host_errors", []).append(remove_result["error"])
                                else:
                                    kick_result["hosts_removed"] += 1
                                    logger.warning(
                                        "Removed hotspot host entry for %s to force bypass re-evaluation", mac_address
                                    )
            except Exception as kick_err:
                logger.warning("Non-fatal: failed to remove host entries for %s: %s", mac_address, kick_err)

            time.sleep(CMD_DELAY)

            # 5. Create Simple Queue for rate limiting (most reliable method in MikroTik)
            # Simple queues work even with FastTrack and are the standard approach
            queue_result = {"skipped": True, "message": "No rate limit specified"}
            normalized = normalize_mac_address(mac_address)
            
            if rate_limit:
                # Single /queue/simple/print, reused for both tasks below.
                # We scan once for:
                #   - stale plan_<username> entries we must replace
                #   - auto-generated hs-<hotspot> parent queues that would
                #     shadow our new per-user queue (see remove_hotspot_parent_queues)
                # so we avoid paying for an extra list roundtrip per payment.
                stale_plan_ids: List[str] = []
                stale_hs_queues: List[Dict[str, Any]] = []
                queues = self.send_command("/queue/simple/print")
                if queues.get("success") and queues.get("data"):
                    for q in queues["data"]:
                        name = str(q.get("name", ""))
                        qid = q.get(".id")
                        if not qid:
                            continue
                        if name.startswith("hs-"):
                            stale_hs_queues.append(q)
                        elif name == f"plan_{username}" or f"MAC:{mac_address}" in q.get("comment", ""):
                            stale_plan_ids.append(qid)

                # Drop the previous plan_<username> entry (if any) so the add
                # below doesn't collide on the name.
                for qid in stale_plan_ids:
                    time.sleep(CMD_DELAY)
                    self.send_command("/queue/simple/remove", {"numbers": qid})
                    logger.info(f"Removed existing plan queue for {username}")

                time.sleep(CMD_DELAY)  # Give router breathing room

                # Find client's current IP
                client_ip = self.get_client_ip_by_mac(normalized)

                if client_ip:
                    time.sleep(CMD_DELAY)  # Give router breathing room
                    # Create simple queue targeting client IP (no interface = matches all).
                    # Done BEFORE cleaning up hs-* so the user-critical path
                    # finishes as fast as possible.
                    queue_result = self.send_command("/queue/simple/add", {
                        "name": f"plan_{username}",
                        "target": f"{client_ip}/32",
                        "max-limit": rate_limit,
                        "comment": f"MAC:{mac_address}|Plan rate limit"
                    })
                    if queue_result.get("success"):
                        bypass_result = self.ensure_queue_fasttrack_bypass([client_ip])
                        if bypass_result.get("error"):
                            logger.warning(
                                f"Queue created but FastTrack bypass setup failed for {client_ip}: {bypass_result.get('error')}"
                            )
                    logger.info(f"Created simple queue for {username} -> {client_ip} with limit {rate_limit}")
                else:
                    # Client not connected yet - will be created by sync job
                    logger.warning(f"Client {mac_address} not connected - queue will be created when they connect")
                    queue_result = {"pending": True, "message": "Client not connected, queue pending"}

                # Finally, prune MikroTik's auto-generated hotspot parent
                # queues (hs-<hotspot>, target=bridge, unlimited/unlimited).
                # They sit at position 0 and shadow every per-user plan queue,
                # so if they exist all hotspot users get unlimited internet.
                # We do this AFTER the user's plan queue is in place so the
                # payment-critical path (user + binding + plan queue) finishes
                # first; and we only hit the network here if we already saw an
                # hs-* entry in the single print above (zero-cost fast path
                # when the router is healthy).
                if stale_hs_queues:
                    removed_hs = 0
                    for q in stale_hs_queues:
                        time.sleep(CMD_DELAY)
                        remove_result = self.send_command(
                            "/queue/simple/remove", {"numbers": q[".id"]}
                        )
                        if remove_result.get("error"):
                            logger.warning(
                                "Failed to remove hotspot parent queue %s: %s",
                                q.get("name"), remove_result["error"],
                            )
                        else:
                            removed_hs += 1
                            logger.warning(
                                "Removed auto-generated hotspot parent queue %s "
                                "(target=%s, max-limit=%s) - was shadowing per-user plan queues",
                                q.get("name"), q.get("target"), q.get("max-limit"),
                            )
                    if removed_hs:
                        logger.warning(
                            "Healed %d stale hotspot parent queue(s) after provisioning %s",
                            removed_hs, username,
                        )

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
                "kick_result": kick_result,
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

            # 3. Remove simple queues - search by name OR MAC in comment
            queues = self.send_command("/queue/simple/print")
            results["queue_removed"] = 0
            if queues.get("success") and queues.get("data"):
                for queue in queues["data"]:
                    queue_name = queue.get("name", "")
                    queue_comment = queue.get("comment", "")
                    # Match by queue name (old or new format) OR by MAC address in comment
                    if (queue_name == f"queue_{username}" or 
                        queue_name == f"plan_{username}" or
                        f"MAC:{mac_address}" in queue_comment or
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
                        "cpu_count": self._safe_int(data.get("cpu-count"), 1),
                        "cpu_frequency": self._safe_int(data.get("cpu-frequency")),
                        "cpu_load": self._safe_int(data.get("cpu-load")),
                        "free_memory": self._safe_int(data.get("free-memory")),
                        "total_memory": self._safe_int(data.get("total-memory")),
                        "free_hdd_space": self._safe_int(data.get("free-hdd-space")),
                        "total_hdd_space": self._safe_int(data.get("total-hdd-space")),
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
                        "rx_byte": self._safe_int(iface.get("rx-byte")),
                        "tx_byte": self._safe_int(iface.get("tx-byte")),
                        "rx_packet": self._safe_int(iface.get("rx-packet")),
                        "tx_packet": self._safe_int(iface.get("tx-packet")),
                        "rx_error": self._safe_int(iface.get("rx-error")),
                        "tx_error": self._safe_int(iface.get("tx-error"))
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
                        "bytes_in": self._safe_int(session.get("bytes-in")),
                        "bytes_out": self._safe_int(session.get("bytes-out")),
                        "packets_in": self._safe_int(session.get("packets-in")),
                        "packets_out": self._safe_int(session.get("packets-out")),
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

    def get_arp_entries(self) -> Dict[str, Any]:
        """Get ARP table entries - shows all devices that have communicated with router"""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ip/arp/print")
            if result.get("success"):
                entries = []
                for entry in result.get("data", []):
                    # Skip incomplete entries (no MAC yet)
                    if entry.get("complete") == "false" or not entry.get("mac-address"):
                        continue
                    entries.append({
                        "ip_address": entry.get("address", ""),
                        "mac_address": entry.get("mac-address", ""),
                        "interface": entry.get("interface", ""),
                        "dynamic": entry.get("dynamic") == "true",
                        "complete": entry.get("complete") == "true"
                    })
                return {"success": True, "data": entries, "count": len(entries)}
            return {"error": "Failed to get ARP entries"}
        except Exception as e:
            logger.error(f"Error getting ARP entries: {e}")
            return {"error": str(e)}

    def get_dhcp_leases(self) -> Dict[str, Any]:
        """Get DHCP server leases - shows devices that received IP via DHCP"""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ip/dhcp-server/lease/print")
            if result.get("success"):
                leases = []
                active_count = 0
                for lease in result.get("data", []):
                    is_active = lease.get("status") == "bound"
                    if is_active:
                        active_count += 1
                    leases.append({
                        "ip_address": lease.get("address", ""),
                        "mac_address": lease.get("mac-address", ""),
                        "hostname": lease.get("host-name", ""),
                        "server": lease.get("server", ""),
                        "status": lease.get("status", ""),
                        "active": is_active,
                        "expires_after": lease.get("expires-after", ""),
                        "last_seen": lease.get("last-seen", "")
                    })
                return {"success": True, "data": leases, "total": len(leases), "active": active_count}
            return {"error": "Failed to get DHCP leases"}
        except Exception as e:
            logger.error(f"Error getting DHCP leases: {e}")
            return {"error": str(e)}

    def get_hotspot_hosts(self) -> Dict[str, Any]:
        """Get hotspot hosts - all devices seen by hotspot (including bypassed)"""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ip/hotspot/host/print")
            if result.get("success"):
                hosts = []
                authorized_count = 0
                bypassed_count = 0
                for host in result.get("data", []):
                    is_authorized = host.get("authorized") == "true"
                    is_bypassed = host.get("bypassed") == "true"
                    if is_authorized:
                        authorized_count += 1
                    if is_bypassed:
                        bypassed_count += 1
                    hosts.append({
                        "ip_address": host.get("address", ""),
                        "mac_address": host.get("mac-address", ""),
                        "to_address": host.get("to-address", ""),
                        "authorized": is_authorized,
                        "bypassed": is_bypassed,
                        "bytes_in": self._safe_int(host.get("bytes-in")),
                        "bytes_out": self._safe_int(host.get("bytes-out")),
                        "idle_time": host.get("idle-time", ""),
                        "uptime": host.get("uptime", "")
                    })
                return {
                    "success": True, 
                    "data": hosts, 
                    "total": len(hosts),
                    "authorized": authorized_count,
                    "bypassed": bypassed_count
                }
            return {"error": "Failed to get hotspot hosts"}
        except Exception as e:
            logger.error(f"Error getting hotspot hosts: {e}")
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
        """Get client's current IP by MAC from hotspot sessions/hosts, ARP, or DHCP."""
        if not self.connected:
            return None
        try:
            normalized_mac = normalize_mac_address(mac_address)

            # Hotspot active sessions (best source for currently authenticated clients)
            active_sessions = self.send_command("/ip/hotspot/active/print")
            if active_sessions.get("success") and active_sessions.get("data"):
                for session in active_sessions["data"]:
                    session_mac = session.get("mac-address", "")
                    if session_mac and normalize_mac_address(session_mac) == normalized_mac:
                        session_ip = session.get("address")
                        if session_ip:
                            return session_ip

            # Hotspot hosts (includes bypassed users, even if not in active sessions)
            hosts = self.send_command("/ip/hotspot/host/print")
            if hosts.get("success") and hosts.get("data"):
                for host in hosts["data"]:
                    host_mac = host.get("mac-address", "")
                    if host_mac and normalize_mac_address(host_mac) == normalized_mac:
                        host_ip = host.get("address") or host.get("to-address")
                        if host_ip:
                            return host_ip
            
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

    def _parse_rate_to_bps(self, rate_str: str) -> int:
        """Parse MikroTik rate string (e.g., '1.5M', '512k', '100') to bits per second"""
        if not rate_str:
            return 0
        rate_str = rate_str.strip().upper()
        match = re.match(r'^(\d+(?:\.\d+)?)\s*([KMG])?(?:BPS)?$', rate_str)
        if match:
            value = float(match.group(1))
            unit = match.group(2)
            if unit == 'K':
                return int(value * 1000)
            elif unit == 'M':
                return int(value * 1000000)
            elif unit == 'G':
                return int(value * 1000000000)
            return int(value)
        return 0

    def get_queue_speed_stats(self) -> Dict[str, Any]:
        """Get simple queue statistics with current rates for speed analytics"""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/queue/simple/print", {"stats": ""})
            if result.get("success"):
                queues = []
                total_download_bps = 0
                total_upload_bps = 0
                active_queues = 0
                
                for q in result.get("data", []):
                    # Rate is in format "upload/download" e.g., "1.5M/2.3M"
                    rate = q.get("rate", "0/0")
                    rate_parts = rate.split("/")
                    upload_rate = rate_parts[0] if len(rate_parts) > 0 else "0"
                    download_rate = rate_parts[1] if len(rate_parts) > 1 else "0"
                    
                    upload_bps = self._parse_rate_to_bps(upload_rate)
                    download_bps = self._parse_rate_to_bps(download_rate)
                    
                    # Max-limit format: "upload/download"
                    max_limit = q.get("max-limit", "0/0")
                    max_parts = max_limit.split("/")
                    max_upload = self._parse_rate_to_bps(max_parts[0] if len(max_parts) > 0 else "0")
                    max_download = self._parse_rate_to_bps(max_parts[1] if len(max_parts) > 1 else "0")
                    
                    # Parse bytes safely (format: "upload/download")
                    bytes_str = q.get("bytes", "0/0")
                    bytes_parts = bytes_str.split("/") if "/" in bytes_str else ["0", "0"]
                    bytes_in = self._safe_int(bytes_parts[0]) if len(bytes_parts) > 0 else 0
                    bytes_out = self._safe_int(bytes_parts[1]) if len(bytes_parts) > 1 else 0
                    
                    queue_data = {
                        "name": q.get("name", ""),
                        "target": q.get("target", ""),
                        "upload_rate_bps": upload_bps,
                        "download_rate_bps": download_bps,
                        "max_upload_bps": max_upload,
                        "max_download_bps": max_download,
                        "bytes_in": bytes_in,
                        "bytes_out": bytes_out,
                        "disabled": q.get("disabled") == "true"
                    }
                    queues.append(queue_data)
                    
                    if not queue_data["disabled"] and (upload_bps > 0 or download_bps > 0):
                        total_upload_bps += upload_bps
                        total_download_bps += download_bps
                        active_queues += 1
                
                avg_upload = total_upload_bps / active_queues if active_queues > 0 else 0
                avg_download = total_download_bps / active_queues if active_queues > 0 else 0
                
                return {
                    "success": True,
                    "data": {
                        "queues": queues,
                        "total_queues": len(queues),
                        "active_queues": active_queues,
                        "total_upload_bps": total_upload_bps,
                        "total_download_bps": total_download_bps,
                        "avg_upload_bps": round(avg_upload, 2),
                        "avg_download_bps": round(avg_download, 2),
                        "total_upload_mbps": round(total_upload_bps / 1000000, 2),
                        "total_download_mbps": round(total_download_bps / 1000000, 2),
                        "avg_upload_mbps": round(avg_upload / 1000000, 2),
                        "avg_download_mbps": round(avg_download / 1000000, 2)
                    }
                }
            return {"error": "Failed to get queue stats"}
        except Exception as e:
            logger.error(f"Error getting queue speed stats: {e}")
            return {"error": str(e)}

    # =========================================================================
    # WALLED GARDEN MANAGEMENT
    # =========================================================================

    def get_walled_garden(self) -> Dict[str, Any]:
        """Get all walled garden entries (both domain and IP-based)."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            domain_entries = self.send_command("/ip/hotspot/walled-garden/print")
            ip_entries = self.send_command("/ip/hotspot/walled-garden/ip/print")
            return {
                "success": True,
                "domain_entries": domain_entries.get("data", []) if domain_entries.get("success") else [],
                "ip_entries": ip_entries.get("data", []) if ip_entries.get("success") else []
            }
        except Exception as e:
            logger.error(f"Error getting walled garden: {e}")
            return {"error": str(e)}

    def add_walled_garden_ip(self, dst_address: str, action: str = "accept",
                              comment: str = "") -> Dict[str, Any]:
        """Add an IP-based walled garden entry (e.g., allow traffic to a specific IP)."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            if "/" not in dst_address:
                dst_address = f"{dst_address}/32"

            existing = self.send_command("/ip/hotspot/walled-garden/ip/print")
            if existing.get("success") and existing.get("data"):
                for entry in existing["data"]:
                    if entry.get("dst-address") == dst_address:
                        return {"success": True, "action": "already_exists", "id": entry.get(".id")}

            params = {"dst-address": dst_address, "action": action}
            if comment:
                params["comment"] = comment

            result = self.send_command("/ip/hotspot/walled-garden/ip/add", params)
            if result.get("error"):
                return {"error": result["error"]}
            return {"success": True, "action": "created", "dst_address": dst_address}
        except Exception as e:
            logger.error(f"Error adding walled garden IP {dst_address}: {e}")
            return {"error": str(e)}

    def add_walled_garden_domain(self, dst_host: str, action: str = "allow",
                                  comment: str = "") -> Dict[str, Any]:
        """Add a domain-based walled garden entry (e.g., allow access to a domain)."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            existing = self.send_command("/ip/hotspot/walled-garden/print")
            if existing.get("success") and existing.get("data"):
                for entry in existing["data"]:
                    if entry.get("dst-host") == dst_host:
                        return {"success": True, "action": "already_exists", "id": entry.get(".id")}

            params = {"dst-host": dst_host, "action": action}
            if comment:
                params["comment"] = comment

            result = self.send_command("/ip/hotspot/walled-garden/add", params)
            if result.get("error"):
                return {"error": result["error"]}
            return {"success": True, "action": "created", "dst_host": dst_host}
        except Exception as e:
            logger.error(f"Error adding walled garden domain {dst_host}: {e}")
            return {"error": str(e)}

    def remove_walled_garden_ip(self, entry_id: str) -> Dict[str, Any]:
        """Remove an IP-based walled garden entry by its .id."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ip/hotspot/walled-garden/ip/remove", {"numbers": entry_id})
            if result.get("error"):
                return {"error": result["error"]}
            return {"success": True, "action": "removed"}
        except Exception as e:
            logger.error(f"Error removing walled garden IP entry {entry_id}: {e}")
            return {"error": str(e)}

    def remove_walled_garden_domain(self, entry_id: str) -> Dict[str, Any]:
        """Remove a domain-based walled garden entry by its .id."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ip/hotspot/walled-garden/remove", {"numbers": entry_id})
            if result.get("error"):
                return {"error": result["error"]}
            return {"success": True, "action": "removed"}
        except Exception as e:
            logger.error(f"Error removing walled garden domain entry {entry_id}: {e}")
            return {"error": str(e)}

    def update_wireguard_endpoint(self, new_endpoint: str, interface_name: str = "wg-aws") -> Dict[str, Any]:
        """Update the WireGuard peer endpoint address (useful when server IP changes)."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            peers = self.send_command("/interface/wireguard/peers/print")
            if not peers.get("success") or not peers.get("data"):
                return {"error": "No WireGuard peers found"}

            target_peer = None
            for peer in peers["data"]:
                if peer.get("interface") == interface_name:
                    target_peer = peer
                    break

            if not target_peer:
                return {"error": f"No peer found for interface {interface_name}"}

            old_endpoint = target_peer.get("endpoint-address", "unknown")
            result = self.send_command("/interface/wireguard/peers/set", {
                "numbers": target_peer[".id"],
                "endpoint-address": new_endpoint
            })
            if result.get("error"):
                return {"error": result["error"]}
            return {
                "success": True,
                "old_endpoint": old_endpoint,
                "new_endpoint": new_endpoint,
                "interface": interface_name
            }
        except Exception as e:
            logger.error(f"Error updating WireGuard endpoint: {e}")
            return {"error": str(e)}

    # =========================================================================
    # PPPoE MANAGEMENT
    # =========================================================================

    def ensure_pppoe_profile(
        self,
        profile_name: str,
        rate_limit: str,
        local_address: str = "",
        pool_name: str = "",
        dns_server: str = "",
        change_tcp_mss: str = "",
    ) -> Dict[str, Any]:
        """
        Ensure a PPPoE profile exists with the specified rate limit.
        Creates or updates /ppp/profile.
        """
        if not self.connected:
            return {"error": "Not connected"}
        try:
            profiles = self.send_command("/ppp/profile/print")
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
                "rate-limit": rate_limit,
            }
            if local_address:
                profile_args["local-address"] = local_address
            if pool_name:
                profile_args["remote-address"] = pool_name
            if dns_server:
                profile_args["dns-server"] = dns_server
            if change_tcp_mss:
                profile_args["change-tcp-mss"] = change_tcp_mss

            if profile_exists:
                profile_args["numbers"] = profile_id
                result = self.send_command("/ppp/profile/set", profile_args)
                logger.info(f"Updated PPPoE profile '{profile_name}' with rate-limit {rate_limit}")
            else:
                result = self.send_command("/ppp/profile/add", profile_args)
                if result.get("error"):
                    err_lower = result.get("error", "").lower()
                    if "already exists" in err_lower or "already have" in err_lower:
                        refresh = self.send_command("/ppp/profile/print")
                        if refresh.get("success"):
                            for profile in refresh.get("data", []):
                                if profile.get("name") == profile_name:
                                    profile_id = profile.get(".id")
                                    if profile_id:
                                        profile_args["numbers"] = profile_id
                                        result = self.send_command("/ppp/profile/set", profile_args)
                                        break
                logger.info(f"Created PPPoE profile '{profile_name}' with rate-limit {rate_limit}")

            return result
        except Exception as e:
            logger.error(f"Error ensuring PPPoE profile '{profile_name}': {e}")
            return {"error": str(e)}

    def get_ppp_profile_detail(self, profile_name: str) -> Dict[str, Any]:
        """Return a single PPP profile by name with fields relevant to PPPoE."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ppp/profile/print")
            if not result.get("success"):
                return result

            for profile in result.get("data", []):
                if profile.get("name") == profile_name:
                    return {
                        "success": True,
                        "found": True,
                        "data": {
                            "name": profile.get("name", ""),
                            "local_address": profile.get("local-address", ""),
                            "remote_address": profile.get("remote-address", ""),
                            "dns_server": profile.get("dns-server", ""),
                            "change_tcp_mss": profile.get("change-tcp-mss", ""),
                            "rate_limit": profile.get("rate-limit", ""),
                        },
                    }

            return {"success": True, "found": False, "data": None}
        except Exception as e:
            logger.error(f"Error getting PPP profile detail for {profile_name}: {e}")
            return {"error": str(e)}

    def get_active_pppoe_profile(self, bridge_name: str = "bridge-pppoe") -> Dict[str, Any]:
        """Resolve the active PPPoE server profile for a bridge and return its detail."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            servers = self.get_pppoe_server_status()
            if servers.get("error"):
                return servers

            enabled_servers = [
                s for s in servers.get("data", [])
                if not s.get("disabled", False)
            ]
            server = next(
                (s for s in enabled_servers if s.get("interface") == bridge_name),
                enabled_servers[0] if enabled_servers else None,
            )
            if not server:
                return {"success": True, "found": False, "data": None}

            profile_name = server.get("default_profile") or "default-pppoe"
            profile = self.get_ppp_profile_detail(profile_name)
            if profile.get("error"):
                return profile
            if profile.get("found"):
                profile["server_interface"] = server.get("interface", "")
                profile["server_name"] = server.get("service_name", "")
                return profile

            return {"success": True, "found": False, "data": None}
        except Exception as e:
            logger.error(f"Error getting active PPPoE profile: {e}")
            return {"error": str(e)}

    def _pool_ranges_to_cidrs(self, ranges_str: str) -> List[str]:
        """Convert MikroTik pool ranges into CIDR blocks for firewall matching."""
        cidrs: List[str] = []
        seen = set()

        for part in (ranges_str or "").split(","):
            part = part.strip()
            if not part:
                continue
            try:
                if "-" in part:
                    start_str, end_str = [p.strip() for p in part.split("-", 1)]
                    start_ip = ipaddress.ip_address(start_str)
                    end_ip = ipaddress.ip_address(end_str)
                    networks = ipaddress.summarize_address_range(start_ip, end_ip)
                elif "/" in part:
                    networks = [ipaddress.ip_network(part, strict=False)]
                else:
                    ip_obj = ipaddress.ip_address(part)
                    networks = [ipaddress.ip_network(f"{ip_obj}/32", strict=False)]

                for network in networks:
                    cidr = str(network)
                    if cidr not in seen:
                        seen.add(cidr)
                        cidrs.append(cidr)
            except ValueError:
                logger.warning(f"Could not parse PPPoE pool range '{part}' into CIDR blocks")

        return cidrs

    def ensure_pppoe_fasttrack_bypass(
        self,
        bridge_name: str = "bridge-pppoe",
        pool_name: str = "",
        fallback_pool_ranges: str = "",
    ) -> Dict[str, Any]:
        """
        Ensure FastTrack bypass rules exist for the active PPPoE address pool.
        PPP profile rate-limit creates dynamic simple queues, and FastTrack skips them.
        """
        if not self.connected:
            return {"error": "Not connected"}
        try:
            effective_pool = pool_name
            if not effective_pool:
                active_profile = self.get_active_pppoe_profile(bridge_name=bridge_name)
                if active_profile.get("error"):
                    return active_profile
                if active_profile.get("found") and active_profile.get("data", {}).get("remote_address"):
                    effective_pool = active_profile["data"]["remote_address"]

            cidrs: List[str] = []
            if effective_pool:
                pool_data = self.get_ip_pool_status(effective_pool)
                if pool_data.get("error"):
                    return {"error": f"Could not read PPPoE pool '{effective_pool}': {pool_data['error']}"}
                pool_ranges = ""
                pools = pool_data.get("pools", [])
                if pools:
                    pool_ranges = pools[0].get("ranges", "")
                cidrs = self._pool_ranges_to_cidrs(pool_ranges)

            if not cidrs and fallback_pool_ranges:
                cidrs = self._pool_ranges_to_cidrs(fallback_pool_ranges)

            if not cidrs:
                return {"error": "Could not determine PPPoE pool subnet for FastTrack bypass"}

            filters_result = self.send_command_optimized(
                "/ip/firewall/filter/print",
                proplist=[".id", "chain", "action", "comment", "src-address", "dst-address", "disabled"]
            )
            filter_rules = filters_result.get("data", []) if filters_result.get("success") else []

            fasttrack_rule = None
            for rule in filter_rules:
                if (
                    rule.get("chain") == "forward"
                    and rule.get("action") == "fasttrack-connection"
                    and str(rule.get("disabled", "false")).lower() != "true"
                ):
                    fasttrack_rule = rule
                    break

            if not fasttrack_rule:
                return {
                    "success": True,
                    "fasttrack_enabled": False,
                    "pool_name": effective_pool,
                    "cidrs": cidrs,
                    "rules_added": 0,
                }

            ft_id = fasttrack_rule.get(".id")
            rules_added = 0
            for cidr in cidrs:
                src_comment = f"PPPoE bypass FastTrack (src) {cidr}"
                dst_comment = f"PPPoE bypass FastTrack (dst) {cidr}"

                src_exists = any(
                    r.get("comment") == src_comment
                    and r.get("src-address") == cidr
                    and str(r.get("disabled", "false")).lower() != "true"
                    for r in filter_rules
                )
                dst_exists = any(
                    r.get("comment") == dst_comment
                    and r.get("dst-address") == cidr
                    and str(r.get("disabled", "false")).lower() != "true"
                    for r in filter_rules
                )

                if not src_exists and ft_id:
                    result = self.send_command("/ip/firewall/filter/add", {
                        "chain": "forward",
                        "src-address": cidr,
                        "action": "accept",
                        "comment": src_comment,
                        "place-before": ft_id,
                    })
                    if result.get("error"):
                        return {"error": f"FastTrack bypass (src {cidr}): {result['error']}"}
                    rules_added += 1

                if not dst_exists and ft_id:
                    result = self.send_command("/ip/firewall/filter/add", {
                        "chain": "forward",
                        "dst-address": cidr,
                        "action": "accept",
                        "comment": dst_comment,
                        "place-before": ft_id,
                    })
                    if result.get("error"):
                        return {"error": f"FastTrack bypass (dst {cidr}): {result['error']}"}
                    rules_added += 1

            return {
                "success": True,
                "fasttrack_enabled": True,
                "pool_name": effective_pool,
                "cidrs": cidrs,
                "rules_added": rules_added,
            }
        except Exception as e:
            logger.error(f"Error ensuring PPPoE FastTrack bypass: {e}")
            return {"error": str(e)}

    def add_pppoe_secret(self, username: str, password: str, profile: str,
                         service: str = "pppoe", comment: str = "") -> Dict[str, Any]:
        """
        Add a PPPoE secret (customer credentials) on the router.
        If the secret already exists, update it instead.
        """
        if not self.connected:
            return {"error": "Not connected"}
        try:
            args = {
                "name": username,
                "password": password,
                "profile": profile,
                "service": service,
            }
            if comment:
                args["comment"] = comment

            result = self.send_command("/ppp/secret/add", args)
            if "error" in result:
                if "already have" in result.get("error", ""):
                    update_args = {
                        "numbers": username,
                        "password": password,
                        "profile": profile,
                    }
                    if comment:
                        update_args["comment"] = comment
                    result = self.send_command("/ppp/secret/set", update_args)
                    logger.info(f"Updated existing PPPoE secret for '{username}'")
                else:
                    logger.error(f"PPPoE secret add error: {result['error']}")
                    return result
            else:
                logger.info(f"Created PPPoE secret for '{username}' with profile '{profile}'")

            return result
        except Exception as e:
            logger.error(f"Error adding PPPoE secret for '{username}': {e}")
            return {"error": str(e)}

    def remove_pppoe_secret(self, username: str) -> Dict[str, Any]:
        """Remove a PPPoE secret by username."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            secrets = self.send_command("/ppp/secret/print")
            if secrets.get("success") and secrets.get("data"):
                for secret in secrets["data"]:
                    if secret.get("name") == username:
                        secret_id = secret.get(".id")
                        if secret_id:
                            result = self.send_command("/ppp/secret/remove", {"numbers": secret_id})
                            logger.info(f"Removed PPPoE secret for '{username}'")
                            return {"success": True, "action": "removed"}

            return {"success": True, "action": "not_found"}
        except Exception as e:
            logger.error(f"Error removing PPPoE secret for '{username}': {e}")
            return {"error": str(e)}

    def disconnect_pppoe_session(self, username: str) -> Dict[str, Any]:
        """Disconnect an active PPPoE session by username."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            active = self.send_command("/ppp/active/print")
            disconnected = 0
            if active.get("success") and active.get("data"):
                for session in active["data"]:
                    if session.get("name") == username:
                        session_id = session.get(".id")
                        if session_id:
                            self.send_command("/ppp/active/remove", {"numbers": session_id})
                            disconnected += 1
                            logger.info(f"Disconnected PPPoE session for '{username}'")

            return {"success": True, "disconnected": disconnected}
        except Exception as e:
            logger.error(f"Error disconnecting PPPoE session for '{username}': {e}")
            return {"error": str(e)}

    def get_active_pppoe_sessions(self) -> Dict[str, Any]:
        """Get all active PPPoE sessions with traffic stats."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ppp/active/print")
            if result.get("success"):
                sessions = []
                for session in result.get("data", []):
                    sessions.append({
                        "user": session.get("name", ""),
                        "service": session.get("service", ""),
                        "caller_id": session.get("caller-id", ""),
                        "address": session.get("address", ""),
                        "uptime": session.get("uptime", ""),
                        "encoding": session.get("encoding", ""),
                        "session_id": session.get("session-id", ""),
                    })
                return {"success": True, "data": sessions, "count": len(sessions)}
            return {"error": "Failed to get active PPPoE sessions"}
        except Exception as e:
            logger.error(f"Error getting active PPPoE sessions: {e}")
            return {"error": str(e)}

    def get_pppoe_sessions_with_bandwidth(self) -> Dict[str, Any]:
        """Get active PPPoE sessions enriched with per-user bandwidth from dynamic queues.

        MikroTik creates dynamic simple queues named ``<pppoe-USERNAME>`` for
        each PPPoE user whose PPP profile has a rate-limit set.  This method
        joins ``/ppp/active/print`` with ``/queue/simple/print`` to return
        live upload/download byte counters and current rate for every online
        PPPoE user.
        """
        if not self.connected:
            return {"error": "Not connected"}
        try:
            active = self.send_command("/ppp/active/print")
            if not active.get("success"):
                return active

            queue_result = self.send_command_optimized(
                "/queue/simple/print",
                proplist=[".id", "name", "target", "max-limit", "rate", "bytes",
                          "queued-bytes", "dynamic", "disabled"],
            )
            queue_map: Dict[str, dict] = {}
            for q in queue_result.get("data", []) if queue_result.get("success") else []:
                qname = q.get("name", "")
                if qname.startswith("<pppoe-") and qname.endswith(">"):
                    username = qname[7:-1]
                    queue_map[username] = q

            sessions = []
            for session in active.get("data", []):
                user = session.get("name", "")
                q = queue_map.get(user, {})

                bytes_str = q.get("bytes", "0/0")
                parts = bytes_str.split("/")
                upload_bytes = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
                download_bytes = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

                rate_str = q.get("rate", "0/0")
                rate_parts = rate_str.split("/")
                upload_rate = rate_parts[0] if len(rate_parts) > 0 else "0"
                download_rate = rate_parts[1] if len(rate_parts) > 1 else "0"

                sessions.append({
                    "user": user,
                    "service": session.get("service", ""),
                    "caller_id": session.get("caller-id", ""),
                    "address": session.get("address", ""),
                    "uptime": session.get("uptime", ""),
                    "encoding": session.get("encoding", ""),
                    "session_id": session.get("session-id", ""),
                    "upload_bytes": upload_bytes,
                    "download_bytes": download_bytes,
                    "upload_rate": upload_rate,
                    "download_rate": download_rate,
                    "max_limit": q.get("max-limit", ""),
                    "has_queue": bool(q),
                })
            return {"success": True, "data": sessions, "count": len(sessions)}
        except Exception as e:
            logger.error(f"Error getting PPPoE sessions with bandwidth: {e}")
            return {"error": str(e)}

    def get_pppoe_secrets_minimal(self) -> Dict[str, Any]:
        """Fetch PPPoE secrets with essential fields."""
        return self.send_command_optimized(
            "/ppp/secret/print",
            proplist=[".id", "name", "profile", "service", "disabled", "comment"]
        )

    # =========================================================================
    # PPPoE PORT / BRIDGE MANAGEMENT
    # =========================================================================

    def get_ethernet_interfaces(self) -> Dict[str, Any]:
        """Get all ethernet interfaces excluding ether1 (WAN)."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/interface/print")
            if not result.get("success"):
                return result
            interfaces = []
            for iface in result.get("data", []):
                if iface.get("type") != "ether":
                    continue
                name = iface.get("name", "")
                if name == "ether1":
                    continue
                interfaces.append({
                    "name": name,
                    "type": iface.get("type", ""),
                    "running": iface.get("running") == "true",
                    "disabled": iface.get("disabled") == "true",
                })
            return {"success": True, "data": interfaces}
        except Exception as e:
            logger.error(f"Error getting ethernet interfaces: {e}")
            return {"error": str(e)}

    def _get_bridge_port_entry(self, interface: str) -> Dict[str, Any]:
        """Find the bridge port entry for an interface.
        Returns {"found": True, "id": ..., "bridge": ...} or {"found": False}."""
        ports = self.send_command_optimized(
            "/interface/bridge/port/print",
            proplist=[".id", "interface", "bridge", "hw", "hw-offload"],
            query=f"?interface={interface}",
        )
        if not ports.get("success"):
            ports = self.send_command("/interface/bridge/port/print")
        if not ports.get("success"):
            return {"error": ports.get("error", "Failed to read bridge ports")}
        for port in ports.get("data", []):
            if port.get("interface") == interface:
                return {
                    "found": True,
                    "id": port.get(".id"),
                    "bridge": port.get("bridge", ""),
                    "hw": port.get("hw", ""),
                    "hw-offload": port.get("hw-offload", ""),
                }
        return {"found": False}

    def remove_bridge_port(self, interface: str, verify: bool = True) -> Dict[str, Any]:
        """Remove an interface from whatever bridge it belongs to.
        Returns the original bridge name in 'original_bridge' on success."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            entry = self._get_bridge_port_entry(interface)
            if entry.get("error"):
                return {"error": entry["error"]}

            if not entry.get("found"):
                entry = self._find_bridge_port_filtered(interface)
                if entry.get("error"):
                    return {"error": entry["error"]}

            if not entry.get("found"):
                logger.warning(
                    f"{interface} not visible in bridge/port print. "
                    f"Trying router-side remove with [find]."
                )
                result = self.send_command(
                    "/interface/bridge/port/remove",
                    {"numbers": f"[find interface={interface}]"},
                )
                if result.get("error"):
                    if "no such item" in result.get("error", "").lower():
                        logger.info(
                            f"{interface} is not present in any bridge port entry; "
                            "treating it as already detached"
                        )
                        return {"success": True, "action": "not_found", "original_bridge": None}
                    return {"error": f"Failed to remove {interface} from bridge: {result['error']}"}

                if not verify:
                    return {"success": True, "action": "removed-via-find", "original_bridge": None}

                time.sleep(0.5)
                verify = self._find_bridge_port_filtered(interface)
                if verify.get("error"):
                    return {"error": verify["error"]}
                if verify.get("found"):
                    return {
                        "error": (
                            f"Router accepted remove for {interface} but it is still in "
                            f"bridge '{verify.get('bridge', '(unknown)')}'"
                        )
                    }
                return {"success": True, "action": "removed-via-find", "original_bridge": None}

            port_id = entry["id"]
            original_bridge = entry["bridge"]
            if port_id:
                result = self.send_command("/interface/bridge/port/remove", {"numbers": port_id})
                if result.get("error"):
                    logger.error(f"Failed to remove {interface} from bridge: {result['error']}")
                    return {"error": f"Failed to remove {interface} from bridge: {result['error']}"}

                if not verify:
                    logger.info(f"Removed {interface} from bridge '{original_bridge}' without inline verification")
                    return {"success": True, "action": "removed", "original_bridge": original_bridge}

                time.sleep(0.5)
                verify = self._find_bridge_port_filtered(interface)
                if verify.get("error"):
                    return {"error": verify["error"]}
                if verify.get("found"):
                    logger.error(
                        f"Router accepted remove for {interface} but it is still in "
                        f"bridge '{verify.get('bridge', '(unknown)')}'"
                    )
                    return {
                        "error": (
                            f"Router did not detach {interface} from bridge "
                            f"'{verify.get('bridge', '(unknown)')}'"
                        )
                    }

                logger.info(f"Removed {interface} from bridge '{original_bridge}'")
                return {"success": True, "action": "removed", "original_bridge": original_bridge}
            return {"success": True, "action": "not_found", "original_bridge": None}
        except Exception as e:
            logger.error(f"Error removing bridge port {interface}: {e}")
            return {"error": str(e)}

    def _find_bridge_port_filtered(self, interface: str) -> Dict[str, Any]:
        """Find a bridge port entry using a filtered query.
        Catches switch-chip-managed ports that unfiltered print may miss."""
        result = self.send_command_optimized(
            "/interface/bridge/port/print",
            proplist=[".id", "interface", "bridge", "hw", "hw-offload"],
            query=f"?interface={interface}",
        )
        if result.get("error"):
            return {"error": result["error"]}
        entries = result.get("data", [])
        if entries:
            e = entries[0]
            return {
                "found": True,
                "id": e.get(".id"),
                "bridge": e.get("bridge", ""),
                "hw": e.get("hw", ""),
                "hw-offload": e.get("hw-offload", ""),
            }
        return {"found": False}

    def _set_bridge_port_in_place(self, interface: str, bridge: str) -> Dict[str, Any]:
        """Change the bridge of an existing bridge port entry in-place.
        Strategy (ordered by reliability):
          1. Re-read bridge ports (now that recv is fixed) to find the .id.
          2. Use filtered query to find the .id.
          3. Fall back to router-side /set with [find interface=<iface>].
        In-place /set avoids remove+add which the switch chip can fight."""

        # Strategy 1: re-read with the (now fixed) full recv
        entry = self._get_bridge_port_entry(interface)
        if entry.get("found") and entry.get("id"):
            port_id = entry["id"]
            logger.info(f"Found {interface} via re-read (id {port_id}), setting bridge to {bridge}")
            r = self.send_command("/interface/bridge/port/set", {
                "numbers": port_id,
                "bridge": bridge,
            })
            if r.get("error"):
                return {"error": f"set bridge failed for {interface}: {r['error']}"}
            return {"success": True, "method": "re-read"}

        # Strategy 2: filtered query
        entry = self._find_bridge_port_filtered(interface)
        if entry.get("found") and entry.get("id"):
            port_id = entry["id"]
            logger.info(f"Found {interface} via filtered query (id {port_id}), setting bridge to {bridge}")
            r = self.send_command("/interface/bridge/port/set", {
                "numbers": port_id,
                "bridge": bridge,
            })
            if r.get("error"):
                return {"error": f"set bridge failed for {interface}: {r['error']}"}
            return {"success": True, "method": "filtered-query"}

        # Strategy 3: let the router find it
        logger.warning(
            f"Neither re-read nor filtered query found {interface}. "
            f"Trying router-side /set with [find]."
        )
        r = self.send_command("/interface/bridge/port/set", {
            "numbers": f"[find interface={interface}]",
            "bridge": bridge,
        })
        if r.get("error"):
            logger.error(f"Router-side set failed for {interface}: {r['error']}")
            return {"error": f"Failed to set {interface} to bridge {bridge}: {r['error']}"}
        return {"success": True, "method": "router-find"}

    def add_bridge_port(self, interface: str, bridge: str, verify: bool = True) -> Dict[str, Any]:
        """Move an interface to a specific bridge.
        Uses in-place 'set' when the port already has a bridge entry (avoids
        remove+add which can silently fail on hardware-offloaded switch chips).
        Falls back to 'add' when no entry exists.
        Handles switch-chip-managed ports that may be invisible to unfiltered
        bridge/port/print but still block /add with 'already added'."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            entry = self._get_bridge_port_entry(interface)
            if entry.get("error"):
                return {"error": entry["error"]}

            if entry.get("found"):
                current_bridge = entry["bridge"]
                port_id = entry["id"]

                if current_bridge == bridge:
                    logger.info(f"{interface} already in bridge {bridge}")
                    return {"success": True}

                # In-place change: set the bridge on the existing entry
                logger.info(
                    f"Moving {interface} from '{current_bridge}' to '{bridge}' "
                    f"via /set (entry {port_id})"
                )
                result = self.send_command("/interface/bridge/port/set", {
                    "numbers": port_id,
                    "bridge": bridge,
                })
                if result.get("error"):
                    logger.error(f"set bridge failed for {interface}: {result['error']}")
                    return {
                        "error": (
                            f"Failed to move {interface} from '{current_bridge}' "
                            f"to '{bridge}': {result['error']}"
                        )
                    }
            else:
                # No existing entry -- create one
                logger.info(f"Adding {interface} to bridge {bridge} via /add (no prior entry)")
                result = self.send_command("/interface/bridge/port/add", {
                    "interface": interface,
                    "bridge": bridge,
                })
                if result.get("error"):
                    err_lower = result["error"].lower()
                    if "already" in err_lower and "bridge port" in err_lower:
                        logger.warning(
                            f"{interface} invisible to unfiltered print but router "
                            f"says 'already added'. Switching to in-place /set."
                        )
                        set_r = self._set_bridge_port_in_place(interface, bridge)
                        if set_r.get("error"):
                            logger.error(f"In-place set fallback failed for {interface}: {set_r['error']}")
                            return {"error": f"Failed to move {interface} to bridge {bridge}: {set_r['error']}"}
                        logger.info(f"In-place set succeeded for {interface} via {set_r.get('method')}")
                        result = set_r
                    else:
                        logger.error(f"add bridge port failed for {interface}: {result['error']}")
                        return {"error": f"Failed to add {interface} to bridge {bridge}: {result['error']}"}

            if not verify:
                logger.info(f"Moved {interface} to bridge {bridge} without inline verification")
                return {"success": True}

            # Verify the port actually landed in the target bridge
            time.sleep(0.5)
            verify = self.verify_port_bridges({interface: bridge}, retries=8, delay=0.5)
            if verify.get("error"):
                failed = verify.get("failed_ports", [])
                actual = failed[0]["actual_bridge"] if failed else "unknown"
                logger.error(
                    f"Port {interface} did not end up in {bridge} after command. "
                    f"Actual: {actual}. Raw set/add result: {result}"
                )
                # Try to restore to original bridge if we know it
                original = entry.get("bridge") if entry.get("found") else None
                if original and original != bridge:
                    self._restore_bridge_port(interface, original)

                return {
                    "error": (
                        f"Router did not move {interface} to '{bridge}' "
                        f"(it is in '{actual}'). "
                        f"Check for hardware offloading (hw-offload) or "
                        f"switch chip grouping on this port."
                    )
                }

            logger.info(f"Verified {interface} is now in bridge {bridge}")
            return {"success": True}
        except Exception as e:
            logger.error(f"Error moving {interface} to bridge {bridge}: {e}")
            return {"error": str(e)}

    def _restore_bridge_port(self, interface: str, original_bridge: str) -> None:
        """Best-effort restore of a port to its original bridge after a failed move."""
        if not original_bridge:
            return
        try:
            logger.info(f"Restoring {interface} to original bridge '{original_bridge}'")
            entry = self._get_bridge_port_entry(interface)
            if entry.get("found"):
                result = self.send_command("/interface/bridge/port/set", {
                    "numbers": entry["id"],
                    "bridge": original_bridge,
                })
            else:
                result = self.send_command("/interface/bridge/port/add", {
                    "interface": interface,
                    "bridge": original_bridge,
                })
            if result.get("error"):
                logger.error(f"Failed to restore {interface} to {original_bridge}: {result['error']}")
            else:
                logger.info(f"Restored {interface} to bridge '{original_bridge}'")
        except Exception as e:
            logger.error(f"Exception restoring {interface} to {original_bridge}: {e}")

    def verify_port_bridges(
        self,
        expected: Dict[str, str],
        retries: int = 1,
        delay: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Re-read bridge port assignments from the router and verify each port
        is in the expected bridge.

        Args:
            expected: {interface_name: expected_bridge_name}  e.g. {"ether2": "bridge-pppoe"}
            retries: Total verification attempts before failing.
            delay: Seconds to wait between failed verification attempts.

        Returns:
            {"success": True} when all ports match, or
            {"error": "...", "failed_ports": [...]} with details per port.
        """
        if not self.connected:
            return {"error": "Not connected"}
        attempts = max(1, retries)
        last_result: Dict[str, Any] = {"error": "Verification did not run"}

        for attempt in range(1, attempts + 1):
            try:
                ports_result = self.send_command("/interface/bridge/port/print")
                if ports_result.get("error"):
                    last_result = {
                        "error": (
                            f"Could not read bridge ports for verification: "
                            f"{ports_result['error']}"
                        )
                    }
                else:
                    actual_map: Dict[str, str] = {}
                    for p in ports_result.get("data", []):
                        actual_map[p.get("interface", "")] = p.get("bridge", "")

                    failed = []
                    for iface, want_bridge in expected.items():
                        got_bridge = actual_map.get(iface)
                        if got_bridge != want_bridge:
                            # Fallback: try filtered query for switch-chip-managed ports
                            filtered = self._find_bridge_port_filtered(iface)
                            if filtered.get("found") and filtered.get("bridge") == want_bridge:
                                logger.info(
                                    f"Verification: {iface} not in unfiltered print but "
                                    f"filtered query confirms it is in '{want_bridge}'"
                                )
                                continue

                            if filtered.get("found"):
                                got_bridge = filtered["bridge"]
                            failed.append({
                                "port": iface,
                                "expected_bridge": want_bridge,
                                "actual_bridge": got_bridge or "(none)",
                            })

                    if not failed:
                        if attempt > 1:
                            logger.info(
                                f"Verification passed on attempt {attempt}/{attempts}: "
                                f"all ports in expected bridges"
                            )
                        else:
                            logger.info("Verification passed: all ports in expected bridges")
                        return {"success": True}

                    summary = "; ".join(
                        f"{f['port']} is in {f['actual_bridge']} instead of {f['expected_bridge']}"
                        for f in failed
                    )
                    last_result = {
                        "error": f"Port move verification failed: {summary}",
                        "failed_ports": failed,
                    }
            except Exception as e:
                last_result = {"error": f"Verification error: {str(e)}"}

            if attempt < attempts:
                logger.warning(
                    f"Bridge verification attempt {attempt}/{attempts} did not match "
                    f"expected state for {', '.join(expected.keys())}. "
                    f"Retrying in {delay:.1f}s."
                )
                if delay > 0:
                    time.sleep(delay)

        for failed_port in last_result.get("failed_ports", []):
            logger.error(
                f"Verification failed: {failed_port['port']} expected in "
                f"'{failed_port['expected_bridge']}' but found in "
                f"'{failed_port['actual_bridge']}'"
            )
        if last_result.get("error"):
            logger.error(last_result["error"])
        return last_result

    def get_pppoe_access_state(
        self,
        legacy_bridge_name: str = "bridge-pppoe",
        dual_bridge_name: str = DUAL_BRIDGE_NAME,
    ) -> Dict[str, Any]:
        """
        Discover how PPPoE access is attached on the router.

        Supported layouts:
        - direct: PPPoE server bound directly to physical interfaces
        - legacy_bridge: PPPoE server bound to a bridge such as bridge-pppoe
        - dual: PPPoE server bound to a dedicated dual bridge (both services coexist)
        - mixed: a combination of direct and bridge-bound
        """
        if not self.connected:
            return {"error": "Not connected"}
        try:
            servers_result = self.get_pppoe_server_status()
            if servers_result.get("error"):
                return servers_result

            bridge_data = self.get_bridge_ports_status()
            bridges = bridge_data.get("bridges", {}) if bridge_data.get("success") else {}
            bridge_ports = bridge_data.get("ports", []) if bridge_data.get("success") else []
            bridge_names = set(bridges.keys())

            bridge_ports_by_name: Dict[str, List[str]] = {}
            bridge_map: Dict[str, str] = {}
            for port in bridge_ports:
                bridge = port.get("bridge", "")
                interface = port.get("interface", "")
                if bridge and interface:
                    bridge_ports_by_name.setdefault(bridge, []).append(interface)
                    bridge_map[interface] = bridge

            enabled_servers = [
                server for server in servers_result.get("data", [])
                if not server.get("disabled", False)
            ]

            direct_ports = set()
            bridge_ports_set = set()
            dual_bridge_ports = set()
            direct_servers = []
            bridge_servers = []
            dual_servers = []
            attachment_map: Dict[str, Dict[str, Any]] = {}

            for server in enabled_servers:
                interface = server.get("interface", "")
                if not interface:
                    continue

                is_dual_bridge = interface == dual_bridge_name
                is_bridge_server = (
                    interface in bridge_names
                    or interface == legacy_bridge_name
                    or interface.startswith("bridge")
                )

                if is_dual_bridge:
                    member_ports = bridge_ports_by_name.get(interface)
                    if member_ports is None:
                        member_result = self.get_ports_in_bridge(interface)
                        member_ports = [] if member_result.get("error") else member_result.get("ports", [])

                    dual_servers.append({
                        **server,
                        "ports": sorted(member_ports),
                    })
                    for port in member_ports:
                        dual_bridge_ports.add(port)
                        attachment_map[port] = {
                            "mode": "dual",
                            "server_interface": interface,
                            "bridge": interface,
                        }
                    continue

                if is_bridge_server:
                    member_ports = bridge_ports_by_name.get(interface)
                    if member_ports is None:
                        member_result = self.get_ports_in_bridge(interface)
                        member_ports = [] if member_result.get("error") else member_result.get("ports", [])

                    bridge_servers.append({
                        **server,
                        "ports": sorted(member_ports),
                    })
                    for port in member_ports:
                        bridge_ports_set.add(port)
                        attachment_map[port] = {
                            "mode": "legacy_bridge",
                            "server_interface": interface,
                            "bridge": interface,
                        }
                    continue

                direct_ports.add(interface)
                direct_servers.append(server)
                attachment_map[interface] = {
                    "mode": "direct",
                    "server_interface": interface,
                    "bridge": "",
                }

            has_direct = bool(direct_ports)
            has_legacy = bool(bridge_ports_set)
            has_dual = bool(dual_servers)

            if has_direct and has_legacy:
                mode = "mixed"
            elif has_direct:
                mode = "direct"
            elif has_legacy:
                mode = "legacy_bridge"
            elif has_dual:
                mode = "dual"
            else:
                mode = "none"

            return {
                "success": True,
                "mode": mode,
                "ports": sorted(direct_ports | bridge_ports_set),
                "direct_ports": sorted(direct_ports),
                "bridge_ports": sorted(bridge_ports_set),
                "dual_bridge_ports": sorted(dual_bridge_ports),
                "direct_servers": direct_servers,
                "bridge_servers": bridge_servers,
                "dual_servers": dual_servers,
                "has_dual": has_dual,
                "attachment_map": attachment_map,
                "enabled_servers": enabled_servers,
                "bridge_map": bridge_map,
                "legacy_bridge_members": sorted(bridge_ports_by_name.get(legacy_bridge_name, [])),
            }
        except Exception as e:
            logger.error(f"Error getting PPPoE access state: {e}")
            return {"error": str(e)}

    def ensure_pppoe_server_on_interface(
        self,
        interface: str,
        profile_name: str = "default-pppoe",
        service_name_prefix: str = "pppoe-server",
        verify: bool = True,
    ) -> Dict[str, Any]:
        """Ensure a PPPoE server exists and is enabled on a specific interface."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            desired_service_name = f"{service_name_prefix}-{interface}".replace("/", "-")
            servers = self.send_command_optimized(
                "/interface/pppoe-server/server/print",
                proplist=[".id", "interface", "disabled", "service-name", "default-profile"],
                query=f"?interface={interface}",
            )
            if servers.get("error"):
                return {"error": f"Could not read PPPoE servers: {servers['error']}"}

            matches = [
                server for server in servers.get("data", [])
                if server.get("interface") == interface
            ]

            if matches:
                primary = matches[0]
                server_id = primary.get(".id")
                if not server_id:
                    return {"error": f"PPPoE server on {interface} has no identifier"}

                result = self.send_command("/interface/pppoe-server/server/set", {
                    "numbers": server_id,
                    "service-name": desired_service_name,
                    "interface": interface,
                    "default-profile": profile_name,
                    "disabled": "no",
                })
                if result.get("error"):
                    return {"error": f"Failed to update PPPoE server on {interface}: {result['error']}"}

                for duplicate in matches[1:]:
                    duplicate_id = duplicate.get(".id")
                    if duplicate_id:
                        duplicate_remove = self.send_command(
                            "/interface/pppoe-server/server/remove",
                            {"numbers": duplicate_id},
                        )
                        if duplicate_remove.get("error"):
                            logger.warning(
                                f"Failed to remove duplicate PPPoE server on {interface}: "
                                f"{duplicate_remove['error']}"
                            )

                if verify:
                    verify_result = self.get_pppoe_server_status()
                    verified = [
                        server for server in verify_result.get("data", [])
                        if server.get("interface") == interface and not server.get("disabled", False)
                    ] if verify_result.get("success") else []
                    if not verified:
                        return {
                            "error": (
                                f"Router accepted PPPoE server update on {interface} but no enabled "
                                f"server was found afterward"
                            )
                        }

                return {"success": True, "action": "updated", "interface": interface}

            result = self.send_command("/interface/pppoe-server/server/add", {
                "service-name": desired_service_name,
                "interface": interface,
                "default-profile": profile_name,
                "disabled": "no",
            })
            if result.get("error"):
                return {"error": f"Failed to create PPPoE server on {interface}: {result['error']}"}

            if verify:
                verify_result = self.get_pppoe_server_status()
                verified = [
                    server for server in verify_result.get("data", [])
                    if server.get("interface") == interface and not server.get("disabled", False)
                ] if verify_result.get("success") else []
                if not verified:
                    return {
                        "error": (
                            f"Router accepted PPPoE server create on {interface} but no enabled "
                            f"server was found afterward"
                        )
                    }

            return {"success": True, "action": "created", "interface": interface}
        except Exception as e:
            logger.error(f"Error ensuring PPPoE server on {interface}: {e}")
            return {"error": str(e)}

    def ensure_dhcp_server_on_interface(
        self,
        name: str,
        interface: str,
        address_pool: str,
        verify: bool = True,
    ) -> Dict[str, Any]:
        """Ensure a DHCP server exists and is enabled on the requested interface."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command_optimized(
                "/ip/dhcp-server/print",
                proplist=[".id", "name", "interface", "address-pool", "disabled"],
            )
            if result.get("error"):
                return {"error": f"Could not read DHCP servers: {result['error']}"}

            matches = [
                server for server in result.get("data", [])
                if server.get("name") == name
            ]

            if matches:
                primary = matches[0]
                server_id = primary.get(".id")
                if not server_id:
                    return {"error": f"DHCP server '{name}' has no identifier"}

                update = self.send_command("/ip/dhcp-server/set", {
                    "numbers": server_id,
                    "name": name,
                    "interface": interface,
                    "address-pool": address_pool,
                    "disabled": "no",
                })
                if update.get("error"):
                    return {"error": f"Failed to update DHCP server '{name}': {update['error']}"}

                for duplicate in matches[1:]:
                    duplicate_id = duplicate.get(".id")
                    if duplicate_id:
                        duplicate_remove = self.send_command(
                            "/ip/dhcp-server/remove",
                            {"numbers": duplicate_id},
                        )
                        if duplicate_remove.get("error"):
                            logger.warning(
                                "Failed to remove duplicate DHCP server '%s': %s",
                                name,
                                duplicate_remove["error"],
                            )
            else:
                create = self.send_command("/ip/dhcp-server/add", {
                    "name": name,
                    "interface": interface,
                    "address-pool": address_pool,
                    "disabled": "no",
                })
                if create.get("error"):
                    return {"error": f"Failed to create DHCP server '{name}': {create['error']}"}

            if verify:
                verify_result = self.get_dhcp_server_status()
                verified = [
                    server for server in verify_result.get("data", [])
                    if server.get("name") == name
                    and server.get("interface") == interface
                    and not server.get("disabled", False)
                ] if verify_result.get("success") else []
                if not verified:
                    return {"error": f"DHCP server '{name}' was not active on {interface} after apply"}

            return {"success": True, "name": name, "interface": interface}
        except Exception as e:
            logger.error("Error ensuring DHCP server %s: %s", name, e)
            return {"error": str(e)}

    def _resolve_hotspot_html_dir(self) -> str:
        """Pick a persistent hotspot html-directory path for this device.

        RouterBOARD devices (hEX, hEX S, hEX lite, hEX PoE, CCR, etc.) have
        a split filesystem: the root /file tree is RAM-backed (tmpfs) and
        only the `flash/` folder is NAND-persistent. Files written to a
        root-level `hotspot/` directory therefore disappear on reboot and
        RouterOS falls back to the built-in default login page, which is
        why clients end up on the stock MikroTik hotspot login instead of
        our captive portal. CHR / x86 have no `flash/` folder and their
        whole filesystem is already persistent, so plain `hotspot` is fine.

        We detect the platform via `/system/resource` `board-name`, which
        returns "CHR" on Cloud Hosted, "x86" on x86 installs, and a real
        model string (e.g. "hEX S", "CCR2004-...") on every RouterBOARD
        device. A denylist of just CHR + x86 stays valid forever since
        those are the only two non-persistent-root platforms MikroTik
        ships. Works identically on RouterOS v6 and v7.
        """
        try:
            result = self.send_command("/system/resource/print")
            if result.get("success"):
                data_list = result.get("data") or []
                data = data_list[0] if data_list else {}
                board = (data.get("board-name") or "").strip()
                if board and board.lower() not in {"chr", "x86"}:
                    return "flash/hotspot"
        except Exception as exc:
            logger.debug("Could not probe system resource for board-name: %s", exc)
        return "hotspot"

    def reset_hotspot_profile_html_directory(self, profile_name: str) -> Dict[str, Any]:
        """Regenerate the RouterOS default hotspot HTML file set for a profile.

        Invokes `/ip/hotspot/profile/reset-html-directory` which materialises
        `login.html`, `rlogin.html`, `alogin.html`, `logout.html`, `status.html`,
        `error.html`, `errors.txt`, `md5.js`, `radvert.html`, `redirect.html`,
        and the `img/` folder into the profile's configured `html-directory`.
        Safe to re-run; idempotent. Command exists in RouterOS v6 and v7.
        """
        if not self.connected:
            return {"error": "Not connected"}
        try:
            profiles = self.send_command("/ip/hotspot/profile/print")
            if profiles.get("error"):
                return {"error": f"Could not read hotspot profiles: {profiles['error']}"}

            profile_id = None
            for profile in profiles.get("data", []) or []:
                if profile.get("name") == profile_name:
                    profile_id = profile.get(".id")
                    break
            if not profile_id:
                return {"error": f"Hotspot profile '{profile_name}' not found"}

            result = self.send_command(
                "/ip/hotspot/profile/reset-html-directory",
                {"numbers": profile_id},
            )
            if result.get("error"):
                return {"error": f"reset-html-directory failed: {result['error']}"}
            return {"success": True, "profile": profile_name}
        except Exception as exc:
            logger.error("Error resetting hotspot html directory for %s: %s", profile_name, exc)
            return {"error": str(exc)}

    def ensure_hotspot_server_profile(
        self,
        profile_name: str,
        hotspot_address: str,
        dns_name: str = "",
        html_directory: Optional[str] = None,
        login_by: str = "http-chap,http-pap",
        reset_html: bool = True,
    ) -> Dict[str, Any]:
        """Ensure a hotspot server profile exists with the expected gateway address.

        When `html_directory` is None (the recommended default), we auto-detect
        the right path for the device: `flash/hotspot` on RouterBOARD boards
        that have a NAND `flash/` partition, `hotspot` everywhere else. This
        prevents the hEX-series regression where uploaded captive-portal HTML
        was silently written to volatile RAM and wiped on reboot.

        If `reset_html` is True (default), we also invoke RouterOS's
        `reset-html-directory` after create/update so the profile's
        html-directory is populated with the complete supporting file set
        before any subsequent login.html upload / fetch step runs.
        """
        if not self.connected:
            return {"error": "Not connected"}
        try:
            resolved_html_dir = html_directory or self._resolve_hotspot_html_dir()

            result = self.send_command("/ip/hotspot/profile/print")
            if result.get("error"):
                return {"error": f"Could not read hotspot profiles: {result['error']}"}

            existing = None
            for profile in result.get("data", []):
                if profile.get("name") == profile_name:
                    existing = profile
                    break

            args = {
                "name": profile_name,
                "hotspot-address": hotspot_address,
                "dns-name": dns_name,
                "login-by": login_by,
                "html-directory": resolved_html_dir,
            }

            if existing:
                profile_id = existing.get(".id")
                if not profile_id:
                    return {"error": f"Hotspot profile '{profile_name}' has no identifier"}
                args["numbers"] = profile_id
                update = self.send_command("/ip/hotspot/profile/set", args)
                if update.get("error"):
                    return {"error": f"Failed to update hotspot profile '{profile_name}': {update['error']}"}
            else:
                create = self.send_command("/ip/hotspot/profile/add", args)
                if create.get("error"):
                    return {"error": f"Failed to create hotspot profile '{profile_name}': {create['error']}"}

            if reset_html:
                reset_result = self.reset_hotspot_profile_html_directory(profile_name)
                if reset_result.get("error"):
                    logger.warning(
                        "reset-html-directory failed for %s (continuing): %s",
                        profile_name, reset_result["error"],
                    )

            return {
                "success": True,
                "name": profile_name,
                "html_directory": resolved_html_dir,
            }
        except Exception as e:
            logger.error("Error ensuring hotspot profile %s: %s", profile_name, e)
            return {"error": str(e)}

    def ensure_hotspot_server_on_interface(
        self,
        interface: str,
        server_name: str,
        profile_name: str,
        address_pool: str,
        verify: bool = True,
    ) -> Dict[str, Any]:
        """Ensure a hotspot server exists and is enabled on the requested interface."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ip/hotspot/print")
            if result.get("error"):
                return {"error": f"Could not read hotspot servers: {result['error']}"}

            matches = [
                server for server in result.get("data", [])
                if server.get("name") == server_name or server.get("interface") == interface
            ]

            if matches:
                primary = matches[0]
                server_id = primary.get(".id")
                if not server_id:
                    return {"error": f"Hotspot server '{server_name}' has no identifier"}

                update = self.send_command("/ip/hotspot/set", {
                    "numbers": server_id,
                    "name": server_name,
                    "interface": interface,
                    "address-pool": address_pool,
                    "profile": profile_name,
                    "disabled": "no",
                })
                if update.get("error"):
                    return {"error": f"Failed to update hotspot server '{server_name}': {update['error']}"}

                for duplicate in matches[1:]:
                    duplicate_id = duplicate.get(".id")
                    if duplicate_id:
                        duplicate_remove = self.send_command("/ip/hotspot/remove", {"numbers": duplicate_id})
                        if duplicate_remove.get("error"):
                            logger.warning(
                                "Failed to remove duplicate hotspot server '%s': %s",
                                server_name,
                                duplicate_remove["error"],
                            )
            else:
                create = self.send_command("/ip/hotspot/add", {
                    "name": server_name,
                    "interface": interface,
                    "address-pool": address_pool,
                    "profile": profile_name,
                    "disabled": "no",
                })
                if create.get("error"):
                    return {"error": f"Failed to create hotspot server '{server_name}': {create['error']}"}

            if verify:
                verify_result = self.get_hotspot_server_status()
                verified = [
                    server for server in verify_result.get("data", [])
                    if server.get("name") == server_name
                    and server.get("interface") == interface
                    and not server.get("disabled", False)
                ] if verify_result.get("success") else []
                if not verified:
                    return {"error": f"Hotspot server '{server_name}' was not active on {interface} after apply"}

            return {"success": True, "name": server_name, "interface": interface}
        except Exception as e:
            logger.error("Error ensuring hotspot server %s on %s: %s", server_name, interface, e)
            return {"error": str(e)}

    def remove_pppoe_servers(self, interfaces: Optional[List[str]] = None) -> Dict[str, Any]:
        """Remove PPPoE server entries, optionally filtering by interface."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            interface_filter = {iface for iface in (interfaces or []) if iface}
            servers = self.send_command_optimized(
                "/interface/pppoe-server/server/print",
                proplist=[".id", "interface", "service-name"],
            )
            if servers.get("error"):
                return {"error": f"Could not read PPPoE servers: {servers['error']}"}

            removed = []
            for server in servers.get("data", []):
                interface = server.get("interface", "")
                if interface_filter and interface not in interface_filter:
                    continue

                server_id = server.get(".id")
                if not server_id:
                    continue

                result = self.send_command("/interface/pppoe-server/server/remove", {"numbers": server_id})
                if result.get("error"):
                    return {"error": f"Failed to remove PPPoE server on {interface}: {result['error']}"}

                removed.append({
                    "interface": interface,
                    "service_name": server.get("service-name", ""),
                })

            return {"success": True, "removed": removed, "count": len(removed)}
        except Exception as e:
            logger.error(f"Error removing PPPoE servers: {e}")
            return {"error": str(e)}

    def restore_ports_from_pppoe(
        self,
        ports: List[str],
        hotspot_bridge: str = "bridge",
        current_state: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Remove PPPoE access from ports and return them to the hotspot bridge."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            unique_ports = list(dict.fromkeys(ports or []))
            if not unique_ports:
                return {"success": True}

            current_state = current_state or self.get_pppoe_access_state()
            if current_state.get("error"):
                return current_state

            current_direct_ports = set(current_state.get("direct_ports", []))
            current_bridge_map = current_state.get("bridge_map", {})
            servers_to_remove = [port for port in unique_ports if port in current_direct_ports]

            if servers_to_remove:
                remove_result = self.remove_pppoe_servers(servers_to_remove)
                if remove_result.get("error"):
                    return remove_result

            errors = []
            for port in unique_ports:
                if current_bridge_map.get(port) == hotspot_bridge:
                    logger.info(f"{port} already in hotspot bridge {hotspot_bridge}; skipping restore")
                    continue
                restore = self.add_bridge_port(port, hotspot_bridge, verify=False)
                if restore.get("error"):
                    errors.append(f"{port}: {restore['error']}")

            if errors:
                return {"error": "Failed to restore PPPoE ports: " + "; ".join(errors)}

            return {"success": True, "ports": unique_ports}
        except Exception as e:
            logger.error(f"Error restoring PPPoE ports: {e}")
            return {"error": str(e)}

    def cleanup_legacy_pppoe_server(self, bridge_name: str = "bridge-pppoe") -> Dict[str, Any]:
        """Remove the old bridge-bound PPPoE server while keeping shared infra intact."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            cleanup = self.remove_pppoe_servers([bridge_name])
            if cleanup.get("error"):
                return cleanup
            return {"success": True, "removed": cleanup.get("removed", [])}
        except Exception as e:
            logger.error(f"Error cleaning up legacy PPPoE server on {bridge_name}: {e}")
            return {"error": str(e)}

    def setup_pppoe_infrastructure(
        self,
        pppoe_ports: List[str],
        hotspot_bridge: str = "bridge",
        bridge_name: str = "bridge-pppoe",
        bridge_ip: str = "192.168.89.1/24",
        pool_name: str = "pppoe-pool",
        pool_range: str = "192.168.89.2-192.168.89.254",
        service_name: str = "pppoe-server1",
        current_state: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Set up full PPPoE infrastructure on the router:
        1. Ensure shared PPPoE infrastructure exists
        2. Remove selected ports from the hotspot/legacy bridge
        3. Bind PPPoE directly to each selected interface
        4. Remove any legacy bridge-bound PPPoE server
        5. Bypass FastTrack for PPPoE subnet (so PPP rate-limits are enforced)
        """
        current_state = current_state or self.get_pppoe_access_state(legacy_bridge_name=bridge_name)
        if current_state.get("error"):
            return current_state

        current_mode = current_state.get("mode", "none")
        bridge_members = set(current_state.get("legacy_bridge_members", []))
        if current_mode in {"legacy_bridge", "mixed"} or bridge_members.intersection(pppoe_ports or []):
            logger.warning(
                f"Router currently uses {current_mode} PPPoE access or still has "
                f"ports in {bridge_name}; "
                f"continuing in legacy bridge mode for compatibility"
            )
            return self._setup_pppoe_infrastructure_legacy(
                pppoe_ports=pppoe_ports,
                hotspot_bridge=hotspot_bridge,
                bridge_name=bridge_name,
                bridge_ip=bridge_ip,
                pool_name=pool_name,
                pool_range=pool_range,
                service_name=service_name,
            )

        direct_result = self._setup_pppoe_infrastructure_direct(
            pppoe_ports=pppoe_ports,
            hotspot_bridge=hotspot_bridge,
            bridge_name=bridge_name,
            bridge_ip=bridge_ip,
            pool_name=pool_name,
            pool_range=pool_range,
            service_name=service_name,
            current_state=current_state,
        )
        if not direct_result.get("error"):
            return direct_result

        logger.warning(
            "Direct PPPoE setup failed; falling back to legacy bridge mode. "
            f"Reason: {direct_result.get('error')}"
        )
        cleanup = self.remove_pppoe_servers(list(dict.fromkeys(pppoe_ports or [])))
        if cleanup.get("error"):
            logger.warning(f"Direct PPPoE cleanup before fallback failed: {cleanup['error']}")

        legacy_result = self._setup_pppoe_infrastructure_legacy(
            pppoe_ports=pppoe_ports,
            hotspot_bridge=hotspot_bridge,
            bridge_name=bridge_name,
            bridge_ip=bridge_ip,
            pool_name=pool_name,
            pool_range=pool_range,
            service_name=service_name,
        )
        if not legacy_result.get("error"):
            warnings = legacy_result.get("warnings", [])
            warnings.append(
                "Direct PPPoE mode was not supported cleanly on this router, so legacy bridge mode was used"
            )
            if direct_result.get("partial_errors"):
                warnings.extend(direct_result.get("partial_errors", []))
            legacy_result["warnings"] = warnings
        return legacy_result

    def _setup_pppoe_infrastructure_direct(
        self,
        pppoe_ports: List[str],
        hotspot_bridge: str = "bridge",
        bridge_name: str = "bridge-pppoe",
        bridge_ip: str = "192.168.89.1/24",
        pool_name: str = "pppoe-pool",
        pool_range: str = "192.168.89.2-192.168.89.254",
        service_name: str = "pppoe-server1",
        current_state: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self.connected:
            return {"error": "Not connected"}
        errors = []
        try:
            target_ports = list(dict.fromkeys(pppoe_ports or []))
            current_state = current_state or self.get_pppoe_access_state(legacy_bridge_name=bridge_name)
            if current_state.get("error"):
                return current_state

            current_direct_ports = set(current_state.get("direct_ports", []))
            current_bridge_map = current_state.get("bridge_map", {})
            current_bridge_servers = current_state.get("bridge_servers", [])
            direct_mode_established = (
                current_state.get("mode") == "direct"
                and bool(current_direct_ports)
                and not current_bridge_servers
            )

            if direct_mode_established:
                logger.info("Existing direct PPPoE infrastructure detected; skipping shared infra re-ensure")
            else:
                # 1. Create bridge-pppoe (ignore error if already exists)
                result = self.send_command("/interface/bridge/add", {"name": bridge_name})
                if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                    errors.append(f"Bridge create: {result['error']}")
                logger.info(f"PPPoE infrastructure: bridge '{bridge_name}' ready")

                # 2. Add IP address on bridge-pppoe (ignore if already exists).
                # The bridge remains as shared PPPoE infra, but access ports no longer
                # forward subscriber traffic through it.
                result = self.send_command("/ip/address/add", {
                    "address": bridge_ip,
                    "interface": bridge_name,
                    "comment": "PPPoE bridge address",
                })
                if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                    errors.append(f"IP address: {result['error']}")

                # 4. Create IP pool (ignore if already exists)
                result = self.send_command("/ip/pool/add", {
                    "name": pool_name,
                    "ranges": pool_range,
                })
                if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                    errors.append(f"Pool: {result['error']}")

                profile_result = self.ensure_pppoe_profile(
                    profile_name="default-pppoe",
                    rate_limit="0/0",
                    local_address=bridge_ip.split("/")[0],
                    pool_name=pool_name,
                )
                if profile_result.get("error"):
                    return {"error": f"PPPoE profile: {profile_result['error']}"}

            # 5. Remove selected ports from any bridge and bind PPPoE directly.
            port_setup_errors = []
            detached_ports = []
            ports_to_bind = []

            for port in target_ports:
                current_bridge = current_bridge_map.get(port, "")
                already_direct = port in current_direct_ports and not current_bridge

                if already_direct:
                    logger.info(f"{port} already directly bound for PPPoE; skipping reconfiguration")
                    continue

                if current_bridge:
                    remove_result = self.remove_bridge_port(port, verify=False)
                    if remove_result.get("error"):
                        port_setup_errors.append(f"Port {port}: {remove_result['error']}")
                        continue
                    detached_ports.append(port)

                ports_to_bind.append(port)

            for port in ports_to_bind:
                bind_result = self.ensure_pppoe_server_on_interface(
                    port,
                    profile_name="default-pppoe",
                    service_name_prefix=service_name,
                    verify=False,
                )
                if bind_result.get("error"):
                    port_setup_errors.append(f"Port {port}: {bind_result['error']}")

            if not direct_mode_established:
                # 6. Add NAT masquerade for PPPoE subnet (ignore if already exists)
                pppoe_subnet = pool_range.split("-")[0].rsplit(".", 1)[0] + ".0/24"
                result = self.send_command("/ip/firewall/nat/add", {
                    "chain": "srcnat",
                    "src-address": pppoe_subnet,
                    "out-interface": "ether1",
                    "action": "masquerade",
                    "comment": "NAT for PPPoE clients",
                })
                if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                    errors.append(f"NAT: {result['error']}")

            # 7. Verify the selected ports are directly attached to PPPoE.
            access_state = self.get_pppoe_access_state(legacy_bridge_name=bridge_name)
            if access_state.get("error"):
                return {
                    "error": f"Port conversion failed on the router: {access_state['error']}",
                    "partial_errors": port_setup_errors,
                }

            actual_direct_ports = set(access_state.get("direct_ports", []))
            failed_ports = []
            for port in target_ports:
                if port not in actual_direct_ports:
                    attachment = access_state.get("attachment_map", {}).get(port, {})
                    failed_ports.append({
                        "port": port,
                        "expected_mode": "direct",
                        "actual_mode": attachment.get("mode", "none"),
                        "server_interface": attachment.get("server_interface", ""),
                    })

            if port_setup_errors or failed_ports:
                if port_setup_errors:
                    logger.error(
                        "PPPoE direct-interface setup had port errors: "
                        + "; ".join(port_setup_errors)
                    )
                return {
                    "error": "Port conversion failed on the router: one or more PPPoE ports are not directly bound",
                    "failed_ports": failed_ports,
                    "partial_errors": port_setup_errors,
                }

            # 8. Remove the old bridge-bound server if this router is being migrated.
            if current_bridge_servers:
                cleanup = self.cleanup_legacy_pppoe_server(bridge_name=bridge_name)
                if cleanup.get("error"):
                    errors.append(f"Legacy PPPoE server cleanup: {cleanup['error']}")

            if not direct_mode_established:
                # 9. Bypass FastTrack for the active PPPoE pool so PPP profile
                #    rate-limits are enforced even when the router already had
                #    custom PPPoE infrastructure.
                bypass_result = self.ensure_pppoe_fasttrack_bypass(
                    bridge_name=bridge_name,
                    pool_name=pool_name,
                    fallback_pool_ranges=pool_range,
                )
                if bypass_result.get("error"):
                    errors.append(f"FastTrack bypass: {bypass_result['error']}")
                elif bypass_result.get("fasttrack_enabled"):
                    logger.info(
                        f"PPPoE FastTrack bypass rules ensured for "
                        f"{', '.join(bypass_result.get('cidrs', []))}"
                    )
                else:
                    logger.info("No FastTrack rule found -- PPPoE rate-limits will work without bypass")

            if errors:
                logger.warning(f"PPPoE infrastructure setup completed with warnings: {errors}")
                return {
                    "success": True,
                    "warnings": errors,
                    "mode": "direct",
                    "access_state": access_state,
                }
            logger.info("PPPoE infrastructure setup completed successfully")
            return {"success": True, "mode": "direct", "access_state": access_state}
        except Exception as e:
            logger.error(f"Error setting up PPPoE infrastructure: {e}")
            return {"error": str(e), "partial_errors": errors}

    def _setup_pppoe_infrastructure_legacy(
        self,
        pppoe_ports: List[str],
        hotspot_bridge: str = "bridge",
        bridge_name: str = "bridge-pppoe",
        bridge_ip: str = "192.168.89.1/24",
        pool_name: str = "pppoe-pool",
        pool_range: str = "192.168.89.2-192.168.89.254",
        service_name: str = "pppoe-server1",
    ) -> Dict[str, Any]:
        if not self.connected:
            return {"error": "Not connected"}
        errors = []
        try:
            target_ports = list(dict.fromkeys(pppoe_ports or []))

            result = self.send_command("/interface/bridge/add", {"name": bridge_name})
            if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                errors.append(f"Bridge create: {result['error']}")

            direct_cleanup = self.remove_pppoe_servers(target_ports)
            if direct_cleanup.get("error"):
                errors.append(f"Direct PPPoE cleanup: {direct_cleanup['error']}")

            port_move_errors = []
            for port in target_ports:
                move_result = self.add_bridge_port(port, bridge_name, verify=False)
                if move_result.get("error"):
                    port_move_errors.append(f"Port {port}: {move_result['error']}")

            result = self.send_command("/ip/address/add", {
                "address": bridge_ip,
                "interface": bridge_name,
                "comment": "PPPoE bridge address",
            })
            if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                errors.append(f"IP address: {result['error']}")

            result = self.send_command("/ip/pool/add", {
                "name": pool_name,
                "ranges": pool_range,
            })
            if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                errors.append(f"Pool: {result['error']}")

            profile_result = self.ensure_pppoe_profile(
                profile_name="default-pppoe",
                rate_limit="0/0",
                local_address=bridge_ip.split("/")[0],
                pool_name=pool_name,
            )
            if profile_result.get("error"):
                return {"error": f"PPPoE profile: {profile_result['error']}"}

            server_result = self.ensure_pppoe_server_on_interface(
                bridge_name,
                profile_name="default-pppoe",
                service_name_prefix=service_name,
                verify=False,
            )
            if server_result.get("error"):
                return {"error": f"PPPoE server: {server_result['error']}"}

            result = self.send_command("/ip/firewall/nat/add", {
                "chain": "srcnat",
                "src-address": pool_range.split("-")[0].rsplit(".", 1)[0] + ".0/24",
                "out-interface": "ether1",
                "action": "masquerade",
                "comment": "NAT for PPPoE clients",
            })
            if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                errors.append(f"NAT: {result['error']}")

            bypass_result = self.ensure_pppoe_fasttrack_bypass(
                bridge_name=bridge_name,
                pool_name=pool_name,
                fallback_pool_ranges=pool_range,
            )
            if bypass_result.get("error"):
                errors.append(f"FastTrack bypass: {bypass_result['error']}")

            if port_move_errors:
                errors.extend(port_move_errors)

            if errors:
                logger.warning(f"Legacy PPPoE infrastructure setup completed with warnings: {errors}")
                return {"success": True, "warnings": errors, "mode": "legacy_bridge"}

            return {"success": True, "mode": "legacy_bridge"}
        except Exception as e:
            logger.error(f"Error setting up legacy PPPoE infrastructure: {e}")
            return {"error": str(e), "partial_errors": errors}

    def teardown_pppoe_infrastructure(
        self,
        ports_to_restore: List[str],
        hotspot_bridge: str = "bridge",
        bridge_name: str = "bridge-pppoe",
        pool_name: str = "pppoe-pool",
        service_name: str = "pppoe-server1",
    ) -> Dict[str, Any]:
        """
        Tear down PPPoE infrastructure and move ports back to hotspot bridge:
        1. Remove direct PPPoE servers and any legacy bridge-bound PPPoE server
        2. Move ports back to hotspot bridge
        3. Remove bridge-pppoe IP address
        4. Remove bridge-pppoe
        5. Remove PPPoE IP pool
        6. Remove NAT rule for PPPoE
        """
        if not self.connected:
            return {"error": "Not connected"}
        errors = []
        try:
            # 1. Remove direct PPPoE servers on the managed ports and any legacy bridge server.
            remove_interfaces = list(dict.fromkeys((ports_to_restore or []) + [bridge_name]))
            remove_result = self.remove_pppoe_servers(remove_interfaces)
            if remove_result.get("error"):
                errors.append(remove_result["error"])

            # 2. Move ports back to hotspot bridge
            for port in ports_to_restore:
                r = self.add_bridge_port(port, hotspot_bridge, verify=False)
                if r.get("error"):
                    errors.append(f"Restore port {port}: {r['error']}")

            # 3. Remove IP addresses on bridge-pppoe
            addrs = self.send_command("/ip/address/print")
            if addrs.get("success") and addrs.get("data"):
                for addr in addrs["data"]:
                    if addr.get("interface") == bridge_name:
                        aid = addr.get(".id")
                        if aid:
                            self.send_command("/ip/address/remove", {"numbers": aid})

            # 4. Remove bridge-pppoe
            bridges = self.send_command("/interface/bridge/print")
            if bridges.get("success") and bridges.get("data"):
                for br in bridges["data"]:
                    if br.get("name") == bridge_name:
                        bid = br.get(".id")
                        if bid:
                            self.send_command("/interface/bridge/remove", {"numbers": bid})
                            logger.info(f"Removed bridge '{bridge_name}'")

            # 5. Remove PPPoE pool
            pools = self.send_command("/ip/pool/print")
            if pools.get("success") and pools.get("data"):
                for pool in pools["data"]:
                    if pool.get("name") == pool_name:
                        pid = pool.get(".id")
                        if pid:
                            self.send_command("/ip/pool/remove", {"numbers": pid})
                            logger.info(f"Removed IP pool '{pool_name}'")

            # 6. Remove NAT rule for PPPoE
            nats = self.send_command("/ip/firewall/nat/print")
            if nats.get("success") and nats.get("data"):
                for nat in nats["data"]:
                    if nat.get("comment") == "NAT for PPPoE clients":
                        nid = nat.get(".id")
                        if nid:
                            self.send_command("/ip/firewall/nat/remove", {"numbers": nid})
                            logger.info("Removed PPPoE NAT rule")

            if errors:
                return {"success": True, "warnings": errors}
            return {"success": True}
        except Exception as e:
            logger.error(f"Error tearing down PPPoE infrastructure: {e}")
            return {"error": str(e), "partial_errors": errors}

    # =========================================================================
    # DUAL-MODE (PPPoE + HOTSPOT) PORT INFRASTRUCTURE
    # =========================================================================

    def setup_dual_infrastructure(
        self,
        dual_ports: List[str],
        hotspot_bridge: str = "bridge",
        dual_bridge_name: str = DUAL_BRIDGE_NAME,
        dual_bridge_ip: str = DUAL_BRIDGE_IP,
        dual_pool_name: str = DUAL_HOTSPOT_POOL_NAME,
        dual_pool_range: str = DUAL_HOTSPOT_POOL_RANGE,
        dual_dhcp_server_name: str = DUAL_DHCP_SERVER_NAME,
        dual_hotspot_profile_name: str = DUAL_HOTSPOT_PROFILE_NAME,
        dual_hotspot_server_name: str = DUAL_HOTSPOT_SERVER_NAME,
        dual_nat_comment: str = DUAL_HOTSPOT_NAT_COMMENT,
        pppoe_pool_name: str = "pppoe-pool",
        pppoe_pool_range: str = "192.168.89.2-192.168.89.254",
        pppoe_local_address: str = "192.168.89.1/24",
    ) -> Dict[str, Any]:
        """
        Set up dual-mode (PPPoE + Hotspot) on a dedicated access bridge.

        The shared infrastructure is constant-cost; only changed ports are moved.
        """
        if not self.connected:
            return {"error": "Not connected"}
        errors = []
        try:
            target_ports = list(dict.fromkeys(dual_ports or []))
            if not target_ports:
                return {"success": True, "message": "No dual ports requested"}

            bridge_data = self.get_bridge_ports_status()
            port_bridge_map = {
                p["interface"]: p["bridge"]
                for p in bridge_data.get("ports", [])
            } if bridge_data.get("success") else {}
            current_dual_ports = sorted(
                port for port, bridge in port_bridge_map.items()
                if bridge == dual_bridge_name
            )
            ports_to_restore = [
                port for port in current_dual_ports
                if port not in target_ports
            ]

            result = self.send_command("/interface/bridge/add", {"name": dual_bridge_name})
            if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                return {"error": f"Dual bridge create: {result['error']}"}

            dual_gateway = dual_bridge_ip.split("/")[0]
            dual_subnet = dual_pool_range.split("-")[0].rsplit(".", 1)[0] + ".0/24"

            result = self.send_command("/ip/address/add", {
                "address": dual_bridge_ip,
                "interface": dual_bridge_name,
                "comment": "Dual bridge address",
            })
            if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                errors.append(f"Dual bridge address: {result['error']}")

            result = self.send_command("/ip/pool/add", {
                "name": dual_pool_name,
                "ranges": dual_pool_range,
            })
            if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                errors.append(f"Dual hotspot pool: {result['error']}")

            dhcp_result = self.ensure_dhcp_server_on_interface(
                name=dual_dhcp_server_name,
                interface=dual_bridge_name,
                address_pool=dual_pool_name,
                verify=True,
            )
            if dhcp_result.get("error"):
                return {"error": f"Dual DHCP: {dhcp_result['error']}"}

            result = self.send_command("/ip/dhcp-server/network/add", {
                "address": dual_subnet,
                "gateway": dual_gateway,
                "dns-server": "8.8.8.8,8.8.4.4",
            })
            if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                errors.append(f"Dual DHCP network: {result['error']}")

            hotspot_profile = self.ensure_hotspot_server_profile(
                profile_name=dual_hotspot_profile_name,
                hotspot_address=dual_gateway,
            )
            if hotspot_profile.get("error"):
                return {"error": f"Dual hotspot profile: {hotspot_profile['error']}"}

            hotspot_server = self.ensure_hotspot_server_on_interface(
                interface=dual_bridge_name,
                server_name=dual_hotspot_server_name,
                profile_name=dual_hotspot_profile_name,
                address_pool=dual_pool_name,
                verify=True,
            )
            if hotspot_server.get("error"):
                return {"error": f"Dual hotspot server: {hotspot_server['error']}"}

            result = self.send_command("/ip/firewall/nat/add", {
                "chain": "srcnat",
                "src-address": dual_subnet,
                "out-interface": "ether1",
                "action": "masquerade",
                "comment": dual_nat_comment,
            })
            if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                errors.append(f"Dual hotspot NAT: {result['error']}")

            result = self.send_command("/ip/pool/add", {
                "name": pppoe_pool_name,
                "ranges": pppoe_pool_range,
            })
            if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                errors.append(f"PPPoE pool: {result['error']}")

            profile_result = self.ensure_pppoe_profile(
                profile_name="default-pppoe",
                rate_limit="0/0",
                local_address=pppoe_local_address.split("/")[0],
                pool_name=pppoe_pool_name,
            )
            if profile_result.get("error"):
                return {"error": f"PPPoE profile: {profile_result['error']}"}

            bind_result = self.ensure_pppoe_server_on_interface(
                dual_bridge_name,
                profile_name="default-pppoe",
                service_name_prefix="pppoe-dual",
                verify=True,
            )
            if bind_result.get("error"):
                return {"error": f"PPPoE server on {dual_bridge_name}: {bind_result['error']}"}

            pppoe_subnet = pppoe_pool_range.split("-")[0].rsplit(".", 1)[0] + ".0/24"
            result = self.send_command("/ip/firewall/nat/add", {
                "chain": "srcnat",
                "src-address": pppoe_subnet,
                "out-interface": "ether1",
                "action": "masquerade",
                "comment": "NAT for PPPoE clients",
            })
            if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                errors.append(f"NAT: {result['error']}")

            bypass_result = self.ensure_pppoe_fasttrack_bypass(
                bridge_name=dual_bridge_name,
                pool_name=pppoe_pool_name,
                fallback_pool_ranges=pppoe_pool_range,
            )
            if bypass_result.get("error"):
                errors.append(f"FastTrack bypass: {bypass_result['error']}")

            for port in ports_to_restore:
                restore_result = self.add_bridge_port(port, hotspot_bridge, verify=False)
                if restore_result.get("error"):
                    errors.append(f"Restore {port} to {hotspot_bridge}: {restore_result['error']}")

            for port in target_ports:
                if port_bridge_map.get(port) == dual_bridge_name:
                    continue
                move_result = self.add_bridge_port(port, dual_bridge_name, verify=False)
                if move_result.get("error"):
                    errors.append(f"Move {port} to {dual_bridge_name}: {move_result['error']}")

            expected = {port: dual_bridge_name for port in target_ports}
            if ports_to_restore:
                expected.update({port: hotspot_bridge for port in ports_to_restore})
            verify = self.verify_port_bridges(expected, retries=3, delay=0.3)
            if verify.get("error"):
                failed = verify.get("failed_ports", [])
                details = "; ".join(
                    f"{item['port']} is in '{item['actual_bridge']}' (expected '{item['expected_bridge']}')"
                    for item in failed
                ) if failed else verify["error"]
                return {
                    "error": f"Dual bridge layout does not match the request: {details}",
                    "failed_ports": failed,
                    "partial_errors": errors,
                }

            access_state = self.get_pppoe_access_state(
                legacy_bridge_name="bridge-pppoe",
                dual_bridge_name=dual_bridge_name,
            )
            if access_state.get("error"):
                return {
                    "error": f"Could not verify dual PPPoE state: {access_state['error']}",
                    "partial_errors": errors,
                }

            actual_dual_ports = set(access_state.get("dual_bridge_ports", []))
            missing_dual = [port for port in target_ports if port not in actual_dual_ports]
            if missing_dual:
                return {
                    "error": f"Dual PPPoE was not active on: {', '.join(missing_dual)}",
                    "failed_ports": [{"port": port, "expected_mode": "dual"} for port in missing_dual],
                    "partial_errors": errors,
                }

            if errors:
                logger.warning(f"Dual infrastructure setup completed with warnings: {errors}")
                return {"success": True, "warnings": errors, "ports": target_ports}

            logger.info("Dual-mode infrastructure setup completed successfully")
            return {"success": True, "ports": target_ports}
        except Exception as e:
            logger.error(f"Error setting up dual infrastructure: {e}")
            return {"error": str(e), "partial_errors": errors}

    def restore_ports_from_dual(
        self,
        ports: List[str],
        hotspot_bridge: str = "bridge",
        dual_bridge_name: str = DUAL_BRIDGE_NAME,
    ) -> Dict[str, Any]:
        """Move specific ports from the dual bridge back to the main hotspot bridge."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            unique_ports = list(dict.fromkeys(ports or []))
            if not unique_ports:
                return {"success": True}

            bridge_map = {}
            bridge_data = self.get_bridge_ports_status()
            if bridge_data.get("success"):
                bridge_map = {
                    p.get("interface", ""): p.get("bridge", "")
                    for p in bridge_data.get("ports", [])
                }

            errors = []
            for port in unique_ports:
                current_bridge = bridge_map.get(port, "")
                if current_bridge == hotspot_bridge:
                    logger.info("%s already in hotspot bridge '%s'; skipping restore", port, hotspot_bridge)
                    continue
                restore = self.add_bridge_port(port, hotspot_bridge, verify=False)
                if restore.get("error"):
                    errors.append(f"{port}: {restore['error']}")

            if errors:
                return {"error": "Failed to restore dual ports: " + "; ".join(errors)}
            return {"success": True, "ports": unique_ports}
        except Exception as e:
            logger.error(f"Error restoring dual ports: {e}")
            return {"error": str(e)}

    def teardown_dual_infrastructure(
        self,
        hotspot_bridge: str = "bridge",
        dual_bridge_name: str = DUAL_BRIDGE_NAME,
        dual_bridge_ip: str = DUAL_BRIDGE_IP,
        dual_pool_name: str = DUAL_HOTSPOT_POOL_NAME,
        dual_dhcp_server_name: str = DUAL_DHCP_SERVER_NAME,
        dual_hotspot_profile_name: str = DUAL_HOTSPOT_PROFILE_NAME,
        dual_hotspot_server_name: str = DUAL_HOTSPOT_SERVER_NAME,
        dual_nat_comment: str = DUAL_HOTSPOT_NAT_COMMENT,
        ports_to_restore: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Remove the dual bridge infrastructure and optionally restore its ports."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            warnings = []

            for port in (ports_to_restore or []):
                restore = self.add_bridge_port(port, hotspot_bridge, verify=False)
                if restore.get("error"):
                    warnings.append(f"Restore {port}: {restore['error']}")

            remove_result = self.remove_pppoe_servers([dual_bridge_name])
            if remove_result.get("error"):
                warnings.append(remove_result["error"])

            hotspot_servers = self.send_command("/ip/hotspot/print")
            if hotspot_servers.get("success"):
                for server in hotspot_servers.get("data", []):
                    if (
                        server.get("name") == dual_hotspot_server_name
                        or server.get("interface") == dual_bridge_name
                    ):
                        server_id = server.get(".id")
                        if server_id:
                            remove = self.send_command("/ip/hotspot/remove", {"numbers": server_id})
                            if remove.get("error"):
                                warnings.append(f"Remove hotspot server: {remove['error']}")

            dhcp_servers = self.send_command("/ip/dhcp-server/print")
            if dhcp_servers.get("success"):
                for server in dhcp_servers.get("data", []):
                    if (
                        server.get("name") == dual_dhcp_server_name
                        or server.get("interface") == dual_bridge_name
                    ):
                        server_id = server.get(".id")
                        if server_id:
                            remove = self.send_command("/ip/dhcp-server/remove", {"numbers": server_id})
                            if remove.get("error"):
                                warnings.append(f"Remove DHCP server: {remove['error']}")

            dhcp_networks = self.send_command("/ip/dhcp-server/network/print")
            if dhcp_networks.get("success"):
                dual_gateway = dual_bridge_ip.split("/")[0]
                for network in dhcp_networks.get("data", []):
                    if network.get("gateway") == dual_gateway:
                        network_id = network.get(".id")
                        if network_id:
                            remove = self.send_command("/ip/dhcp-server/network/remove", {"numbers": network_id})
                            if remove.get("error"):
                                warnings.append(f"Remove dual DHCP network: {remove['error']}")

            addresses = self.send_command("/ip/address/print")
            if addresses.get("success"):
                for address in addresses.get("data", []):
                    if address.get("interface") == dual_bridge_name:
                        address_id = address.get(".id")
                        if address_id:
                            remove = self.send_command("/ip/address/remove", {"numbers": address_id})
                            if remove.get("error"):
                                warnings.append(f"Remove dual bridge address: {remove['error']}")

            pools = self.send_command("/ip/pool/print")
            if pools.get("success"):
                for pool in pools.get("data", []):
                    if pool.get("name") == dual_pool_name:
                        pool_id = pool.get(".id")
                        if pool_id:
                            remove = self.send_command("/ip/pool/remove", {"numbers": pool_id})
                            if remove.get("error"):
                                warnings.append(f"Remove dual hotspot pool: {remove['error']}")

            nats = self.send_command("/ip/firewall/nat/print")
            if nats.get("success"):
                for nat in nats.get("data", []):
                    if nat.get("comment") == dual_nat_comment:
                        nat_id = nat.get(".id")
                        if nat_id:
                            remove = self.send_command("/ip/firewall/nat/remove", {"numbers": nat_id})
                            if remove.get("error"):
                                warnings.append(f"Remove dual hotspot NAT: {remove['error']}")

            hotspot_profiles = self.send_command("/ip/hotspot/profile/print")
            if hotspot_profiles.get("success"):
                for profile in hotspot_profiles.get("data", []):
                    if profile.get("name") == dual_hotspot_profile_name:
                        profile_id = profile.get(".id")
                        if profile_id:
                            remove = self.send_command("/ip/hotspot/profile/remove", {"numbers": profile_id})
                            if remove.get("error"):
                                warnings.append(f"Remove dual hotspot profile: {remove['error']}")

            bridges = self.send_command("/interface/bridge/print")
            if bridges.get("success"):
                for bridge in bridges.get("data", []):
                    if bridge.get("name") == dual_bridge_name:
                        bridge_id = bridge.get(".id")
                        if bridge_id:
                            remove = self.send_command("/interface/bridge/remove", {"numbers": bridge_id})
                            if remove.get("error"):
                                warnings.append(f"Remove dual bridge: {remove['error']}")

            logger.info(f"Removed dual infrastructure on '{dual_bridge_name}'")
            if warnings:
                return {"success": True, "warnings": warnings}
            return {"success": True}
        except Exception as e:
            logger.error(f"Error tearing down dual infrastructure: {e}")
            return {"error": str(e)}

    # =========================================================================
    # PLAIN (NO-AUTH) PORT INFRASTRUCTURE
    # =========================================================================

    def setup_plain_infrastructure(
        self,
        plain_ports: List[str],
        hotspot_bridge: str = "bridge",
        bridge_name: str = "bridge-plain",
        bridge_ip: str = "192.168.90.1/24",
        pool_name: str = "plain-pool",
        pool_range: str = "192.168.90.2-192.168.90.254",
    ) -> Dict[str, Any]:
        """
        Set up plain (no-auth) infrastructure on the router:
        1. Create bridge-plain if it doesn't exist
        2. Assign IP address to bridge-plain
        3. Create DHCP pool, server, and network for bridge-plain
        4. Add masquerade NAT for the plain subnet
        5. Move selected ports from their current bridge into bridge-plain
        """
        if not self.connected:
            return {"error": "Not connected"}
        errors = []
        try:
            target_ports = list(dict.fromkeys(plain_ports or []))
            if not target_ports:
                return {"success": True}

            bridge_map = {}
            bp_result = self.send_command("/interface/bridge/port/print")
            if bp_result.get("success"):
                for bp in bp_result.get("data", []):
                    bridge_map[bp.get("interface", "")] = bp.get("bridge", "")

            # Try to create bridge; if it already exists the duplicate error is harmless.
            br_result = self.send_command("/interface/bridge/add", {"name": bridge_name})
            already_setup = bool(
                br_result.get("error") and _router_error_is_duplicate(br_result.get("error", ""))
            )
            if br_result.get("error") and not already_setup:
                return {"error": f"Failed to create bridge '{bridge_name}': {br_result['error']}"}

            if already_setup:
                logger.info(f"Plain infrastructure: bridge '{bridge_name}' already exists")
            else:
                logger.info(f"Plain infrastructure: created bridge '{bridge_name}'")

            if not already_setup:
                plain_subnet = pool_range.split("-")[0].rsplit(".", 1)[0] + ".0/24"
                infra_cmds = [
                    ("/ip/address/add", {
                        "address": bridge_ip, "interface": bridge_name,
                        "comment": "Plain bridge address",
                    }, "IP address"),
                    ("/ip/pool/add", {"name": pool_name, "ranges": pool_range}, "Pool"),
                    ("/ip/dhcp-server/add", {
                        "name": "dhcp-plain", "interface": bridge_name,
                        "address-pool": pool_name, "disabled": "no",
                    }, "DHCP server"),
                    ("/ip/dhcp-server/network/add", {
                        "address": plain_subnet,
                        "gateway": bridge_ip.split("/")[0],
                        "dns-server": "8.8.8.8,8.8.4.4",
                    }, "DHCP network"),
                    ("/ip/firewall/nat/add", {
                        "chain": "srcnat", "src-address": plain_subnet,
                        "out-interface": "ether1", "action": "masquerade",
                        "comment": "NAT for plain clients",
                    }, "NAT"),
                ]
                for cmd, args, label in infra_cmds:
                    result = self.send_command(cmd, args)
                    if result.get("error") and not _router_error_is_duplicate(result.get("error", "")):
                        errors.append(f"{label}: {result['error']}")

            port_errors = []
            for port in target_ports:
                current_bridge = bridge_map.get(port, "")
                if current_bridge == bridge_name:
                    logger.info(f"{port} already in '{bridge_name}'; skipping")
                    continue

                if current_bridge:
                    remove_result = self.remove_bridge_port(port, verify=False)
                    if remove_result.get("error"):
                        port_errors.append(f"{port}: remove from {current_bridge}: {remove_result['error']}")
                        continue

                add_result = self.add_bridge_port(port, bridge_name, verify=False)
                if add_result.get("error"):
                    port_errors.append(f"{port}: add to {bridge_name}: {add_result['error']}")

            if port_errors:
                return {
                    "error": "Some ports failed during plain infrastructure setup",
                    "partial_errors": port_errors + errors,
                }

            if errors:
                logger.warning(f"Plain infrastructure setup completed with warnings: {errors}")
                return {"success": True, "warnings": errors}
            logger.info("Plain infrastructure setup completed successfully")
            return {"success": True}
        except Exception as e:
            logger.error(f"Error setting up plain infrastructure: {e}")
            return {"error": str(e), "partial_errors": errors}

    def teardown_plain_infrastructure(
        self,
        ports_to_restore: List[str],
        hotspot_bridge: str = "bridge",
        bridge_name: str = "bridge-plain",
        pool_name: str = "plain-pool",
    ) -> Dict[str, Any]:
        """
        Tear down plain infrastructure and move ports back to hotspot bridge:
        1. Move ports back to hotspot bridge
        2. Remove DHCP server and network for bridge-plain
        3. Remove IP address on bridge-plain
        4. Remove bridge-plain
        5. Remove plain IP pool
        6. Remove NAT rule for plain clients
        """
        if not self.connected:
            return {"error": "Not connected"}
        errors = []
        try:
            for port in (ports_to_restore or []):
                r = self.add_bridge_port(port, hotspot_bridge, verify=False)
                if r.get("error"):
                    errors.append(f"Restore port {port}: {r['error']}")

            dhcp_servers = self.send_command("/ip/dhcp-server/print")
            if dhcp_servers.get("success") and dhcp_servers.get("data"):
                for srv in dhcp_servers["data"]:
                    if srv.get("name") == "dhcp-plain":
                        sid = srv.get(".id")
                        if sid:
                            self.send_command("/ip/dhcp-server/remove", {"numbers": sid})
                            logger.info("Removed DHCP server 'dhcp-plain'")

            dhcp_networks = self.send_command("/ip/dhcp-server/network/print")
            if dhcp_networks.get("success") and dhcp_networks.get("data"):
                for net in dhcp_networks["data"]:
                    if net.get("gateway") == "192.168.90.1":
                        nid = net.get(".id")
                        if nid:
                            self.send_command("/ip/dhcp-server/network/remove", {"numbers": nid})
                            logger.info("Removed DHCP network for plain bridge")

            addrs = self.send_command("/ip/address/print")
            if addrs.get("success") and addrs.get("data"):
                for addr in addrs["data"]:
                    if addr.get("interface") == bridge_name:
                        aid = addr.get(".id")
                        if aid:
                            self.send_command("/ip/address/remove", {"numbers": aid})

            bridges = self.send_command("/interface/bridge/print")
            if bridges.get("success") and bridges.get("data"):
                for br in bridges["data"]:
                    if br.get("name") == bridge_name:
                        bid = br.get(".id")
                        if bid:
                            self.send_command("/interface/bridge/remove", {"numbers": bid})
                            logger.info(f"Removed bridge '{bridge_name}'")

            pools = self.send_command("/ip/pool/print")
            if pools.get("success") and pools.get("data"):
                for pool in pools["data"]:
                    if pool.get("name") == pool_name:
                        pid = pool.get(".id")
                        if pid:
                            self.send_command("/ip/pool/remove", {"numbers": pid})
                            logger.info(f"Removed IP pool '{pool_name}'")

            nats = self.send_command("/ip/firewall/nat/print")
            if nats.get("success") and nats.get("data"):
                for nat in nats["data"]:
                    if nat.get("comment") == "NAT for plain clients":
                        nid = nat.get(".id")
                        if nid:
                            self.send_command("/ip/firewall/nat/remove", {"numbers": nid})
                            logger.info("Removed plain NAT rule")

            if errors:
                return {"success": True, "warnings": errors}
            return {"success": True}
        except Exception as e:
            logger.error(f"Error tearing down plain infrastructure: {e}")
            return {"error": str(e), "partial_errors": errors}

    def restore_ports_from_plain(
        self,
        ports: List[str],
        hotspot_bridge: str = "bridge",
        bridge_name: str = "bridge-plain",
    ) -> Dict[str, Any]:
        """Move specific ports from bridge-plain back to the hotspot bridge
        without destroying the shared plain infrastructure."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            unique_ports = list(dict.fromkeys(ports or []))
            if not unique_ports:
                return {"success": True}

            bridge_map = {}
            bp_result = self.send_command("/interface/bridge/port/print")
            if bp_result.get("success"):
                for bp in bp_result.get("data", []):
                    bridge_map[bp.get("interface", "")] = bp.get("bridge", "")

            errors = []
            for port in unique_ports:
                current = bridge_map.get(port, "")
                if current == hotspot_bridge:
                    logger.info(f"{port} already in hotspot bridge '{hotspot_bridge}'; skipping restore")
                    continue
                restore = self.add_bridge_port(port, hotspot_bridge, verify=False)
                if restore.get("error"):
                    errors.append(f"{port}: {restore['error']}")

            if errors:
                return {"error": "Failed to restore plain ports: " + "; ".join(errors)}
            return {"success": True, "ports": unique_ports}
        except Exception as e:
            logger.error(f"Error restoring plain ports: {e}")
            return {"error": str(e)}

    # =========================================================================
    # MONITORING & DIAGNOSTICS
    # =========================================================================

    def get_bridge_ports_status(self) -> Dict[str, Any]:
        """Get all bridge port assignments and bridge interface statuses."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            bridges_result = self.send_command_optimized(
                "/interface/bridge/print",
                proplist=["name", "running", "disabled", "mac-address"],
            )
            bridges = {}
            if bridges_result.get("success"):
                for br in bridges_result.get("data", []):
                    bridges[br.get("name", "")] = {
                        "name": br.get("name", ""),
                        "running": br.get("running") == "true",
                        "disabled": br.get("disabled") == "true",
                        "mac_address": br.get("mac-address", ""),
                    }

            ports_result = self.send_command_optimized(
                "/interface/bridge/port/print",
                proplist=["interface", "bridge", "disabled", "status"],
            )
            ports = []
            if ports_result.get("success"):
                for p in ports_result.get("data", []):
                    ports.append({
                        "interface": p.get("interface", ""),
                        "bridge": p.get("bridge", ""),
                        "disabled": p.get("disabled") == "true",
                        "status": p.get("status", ""),
                    })

            return {"success": True, "bridges": bridges, "ports": ports}
        except Exception as e:
            logger.error(f"Error getting bridge ports status: {e}")
            return {"error": str(e)}

    def get_ports_in_bridge(self, bridge_name: str) -> Dict[str, Any]:
        """Return interface names currently assigned to a bridge."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            # Filtered queries are more reliable on some switch-chip-managed ports
            # than a full unfiltered print.
            filtered = self.send_command_optimized(
                "/interface/bridge/port/print",
                proplist=["interface", "bridge"],
                query=f"?bridge={bridge_name}",
            )
            if filtered.get("success"):
                ports = sorted(
                    p.get("interface", "")
                    for p in filtered.get("data", [])
                    if p.get("bridge") == bridge_name and p.get("interface")
                )
                return {"success": True, "bridge": bridge_name, "ports": ports}

            ports_result = self.send_command("/interface/bridge/port/print")
            if ports_result.get("error"):
                return {"error": f"Could not read bridge ports: {ports_result['error']}"}

            ports = sorted(
                p.get("interface", "")
                for p in ports_result.get("data", [])
                if p.get("bridge") == bridge_name and p.get("interface")
            )
            return {"success": True, "bridge": bridge_name, "ports": ports}
        except Exception as e:
            logger.error(f"Error reading ports in bridge {bridge_name}: {e}")
            return {"error": str(e)}

    def get_all_interfaces_detail(self) -> Dict[str, Any]:
        """Get detailed info for all interfaces (link, speed, errors, type)."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/interface/print")
            if not result.get("success"):
                return result
            interfaces = []
            for iface in result.get("data", []):
                interfaces.append({
                    "name": iface.get("name", ""),
                    "type": iface.get("type", ""),
                    "running": iface.get("running") == "true",
                    "disabled": iface.get("disabled") == "true",
                    "rx_byte": self._safe_int(iface.get("rx-byte")),
                    "tx_byte": self._safe_int(iface.get("tx-byte")),
                    "rx_error": self._safe_int(iface.get("rx-error")),
                    "tx_error": self._safe_int(iface.get("tx-error")),
                    "rx_drop": self._safe_int(iface.get("rx-drop")),
                    "tx_drop": self._safe_int(iface.get("tx-drop")),
                    "link_downs": self._safe_int(iface.get("link-downs")),
                    "last_link_up_time": iface.get("last-link-up-time", ""),
                    "actual_mtu": self._safe_int(iface.get("actual-mtu")),
                })
            return {"success": True, "data": interfaces}
        except Exception as e:
            logger.error(f"Error getting all interfaces detail: {e}")
            return {"error": str(e)}

    def get_router_logs(self, topics: str = "", limit: int = 50) -> Dict[str, Any]:
        """
        Get recent log entries, optionally filtered by topic substring.
        Uses .proplist to minimize data transfer from router.
        """
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command_optimized(
                "/log/print",
                proplist=["time", "topics", "message"],
            )
            if not result.get("success"):
                return result
            entries = []
            topic_filters = [t.strip().lower() for t in topics.split(",") if t.strip()] if topics else []
            for entry in result.get("data", []):
                entry_topics = entry.get("topics", "").lower()
                if topic_filters and not any(tf in entry_topics for tf in topic_filters):
                    continue
                entries.append({
                    "time": entry.get("time", ""),
                    "topics": entry.get("topics", ""),
                    "message": entry.get("message", ""),
                })
            entries = entries[-limit:]
            return {"success": True, "data": entries, "count": len(entries)}
        except Exception as e:
            logger.error(f"Error getting router logs: {e}")
            return {"error": str(e)}

    def get_ip_pool_status(self, pool_name: str = "") -> Dict[str, Any]:
        """Get IP pool config and usage. If pool_name given, filter to that pool."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            pools_result = self.send_command("/ip/pool/print")
            pools = []
            if pools_result.get("success"):
                for p in pools_result.get("data", []):
                    if pool_name and p.get("name", "") != pool_name:
                        continue
                    pools.append({
                        "name": p.get("name", ""),
                        "ranges": p.get("ranges", ""),
                    })

            used_result = self.send_command("/ip/pool/used/print")
            used = []
            if used_result.get("success"):
                for u in used_result.get("data", []):
                    if pool_name and u.get("pool", "") != pool_name:
                        continue
                    used.append({
                        "pool": u.get("pool", ""),
                        "address": u.get("address", ""),
                        "info": u.get("info", ""),
                    })

            for pool in pools:
                pool_used = [u for u in used if u["pool"] == pool["name"]]
                pool["used_count"] = len(pool_used)
                ranges_str = pool["ranges"]
                total = 0
                for r in ranges_str.split(","):
                    r = r.strip()
                    if "-" in r:
                        parts = r.split("-")
                        try:
                            start_parts = parts[0].strip().split(".")
                            end_parts = parts[1].strip().split(".")
                            start_last = int(start_parts[-1])
                            end_last = int(end_parts[-1])
                            total += end_last - start_last + 1
                        except (ValueError, IndexError):
                            pass
                    elif r:
                        total += 1
                pool["total_addresses"] = total
                pool["available"] = total - len(pool_used)
                pool["exhausted"] = pool["available"] <= 0

            return {"success": True, "pools": pools, "used": used}
        except Exception as e:
            logger.error(f"Error getting IP pool status: {e}")
            return {"error": str(e)}

    def get_nat_rules(self) -> Dict[str, Any]:
        """Get all NAT rules (to verify masquerade exists)."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ip/firewall/nat/print")
            if not result.get("success"):
                return result
            rules = []
            for r in result.get("data", []):
                rules.append({
                    "chain": r.get("chain", ""),
                    "action": r.get("action", ""),
                    "src_address": r.get("src-address", ""),
                    "out_interface": r.get("out-interface", ""),
                    "disabled": r.get("disabled") == "true",
                    "comment": r.get("comment", ""),
                })
            return {"success": True, "data": rules}
        except Exception as e:
            logger.error(f"Error getting NAT rules: {e}")
            return {"error": str(e)}

    # -- PPPoE-specific monitoring --

    def get_pppoe_server_status(self) -> Dict[str, Any]:
        """Get PPPoE server(s) status from /interface/pppoe-server/server/print."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command_optimized(
                "/interface/pppoe-server/server/print",
                proplist=[
                    ".id",
                    "service-name",
                    "interface",
                    "disabled",
                    "default-profile",
                    "max-sessions",
                    "max-mtu",
                    "max-mru",
                ],
            )
            if not result.get("success"):
                return result
            servers = []
            for s in result.get("data", []):
                servers.append({
                    "id": s.get(".id", ""),
                    "service_name": s.get("service-name", ""),
                    "interface": s.get("interface", ""),
                    "disabled": s.get("disabled") == "true",
                    "default_profile": s.get("default-profile", ""),
                    "max_sessions": self._safe_int(s.get("max-sessions")),
                    "max_mtu": self._safe_int(s.get("max-mtu")),
                    "max_mru": self._safe_int(s.get("max-mru")),
                })
            return {"success": True, "data": servers}
        except Exception as e:
            logger.error(f"Error getting PPPoE server status: {e}")
            return {"error": str(e)}

    def get_pppoe_secret_detail(self, username: str) -> Dict[str, Any]:
        """Get full detail for a single PPP secret by username."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ppp/secret/print")
            if not result.get("success"):
                return result
            for s in result.get("data", []):
                if s.get("name") == username:
                    return {
                        "success": True,
                        "found": True,
                        "data": {
                            "name": s.get("name", ""),
                            "service": s.get("service", ""),
                            "profile": s.get("profile", ""),
                            "disabled": s.get("disabled") == "true",
                            "comment": s.get("comment", ""),
                            "last_logged_out": s.get("last-logged-out", ""),
                            "last_disconnect_reason": s.get("last-disconnect-reason", ""),
                            "last_caller_id": s.get("last-caller-id", ""),
                        },
                    }
            return {"success": True, "found": False, "data": None}
        except Exception as e:
            logger.error(f"Error getting PPPoE secret detail for {username}: {e}")
            return {"error": str(e)}

    def get_ppp_profiles(self) -> Dict[str, Any]:
        """Get all PPP profiles with rate limits and pool assignments."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ppp/profile/print")
            if not result.get("success"):
                return result
            profiles = []
            for p in result.get("data", []):
                profiles.append({
                    "name": p.get("name", ""),
                    "local_address": p.get("local-address", ""),
                    "remote_address": p.get("remote-address", ""),
                    "rate_limit": p.get("rate-limit", ""),
                    "dns_server": p.get("dns-server", ""),
                })
            return {"success": True, "data": profiles}
        except Exception as e:
            logger.error(f"Error getting PPP profiles: {e}")
            return {"error": str(e)}

    def get_ppp_secrets_full(self) -> Dict[str, Any]:
        """Get all PPP secrets with full detail (for secrets listing endpoint)."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ppp/secret/print")
            if not result.get("success"):
                return result
            secrets = []
            for s in result.get("data", []):
                secrets.append({
                    "name": s.get("name", ""),
                    "service": s.get("service", ""),
                    "profile": s.get("profile", ""),
                    "disabled": s.get("disabled") == "true",
                    "comment": s.get("comment", ""),
                    "last_logged_out": s.get("last-logged-out", ""),
                    "last_disconnect_reason": s.get("last-disconnect-reason", ""),
                    "last_caller_id": s.get("last-caller-id", ""),
                })
            return {"success": True, "data": secrets}
        except Exception as e:
            logger.error(f"Error getting all PPP secrets: {e}")
            return {"error": str(e)}

    # -- Hotspot-specific monitoring --

    def get_hotspot_server_status(self) -> Dict[str, Any]:
        """Get hotspot server(s) status from /ip/hotspot/print."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ip/hotspot/print")
            if not result.get("success"):
                return result
            servers = []
            for s in result.get("data", []):
                servers.append({
                    "name": s.get("name", ""),
                    "interface": s.get("interface", ""),
                    "disabled": s.get("disabled") == "true",
                    "profile": s.get("profile", ""),
                    "address_pool": s.get("address-pool", ""),
                    "idle_timeout": s.get("idle-timeout", ""),
                    "addresses_per_mac": s.get("addresses-per-mac", ""),
                })
            return {"success": True, "data": servers}
        except Exception as e:
            logger.error(f"Error getting hotspot server status: {e}")
            return {"error": str(e)}

    def get_hotspot_profiles_detail(self) -> Dict[str, Any]:
        """Get hotspot server profiles from /ip/hotspot/profile/print."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ip/hotspot/profile/print")
            if not result.get("success"):
                return result
            profiles = []
            for p in result.get("data", []):
                profiles.append({
                    "name": p.get("name", ""),
                    "hotspot_address": p.get("hotspot-address", ""),
                    "dns_name": p.get("dns-name", ""),
                    "html_directory": p.get("html-directory", ""),
                    "login_by": p.get("login-by", ""),
                    "rate_limit": p.get("rate-limit", ""),
                })
            return {"success": True, "data": profiles}
        except Exception as e:
            logger.error(f"Error getting hotspot profiles: {e}")
            return {"error": str(e)}

    def get_dhcp_server_status(self) -> Dict[str, Any]:
        """Get DHCP server(s) status, interface, pool, and lease count."""
        if not self.connected:
            return {"error": "Not connected"}
        try:
            result = self.send_command("/ip/dhcp-server/print")
            if not result.get("success"):
                return result
            servers = []
            for s in result.get("data", []):
                servers.append({
                    "name": s.get("name", ""),
                    "interface": s.get("interface", ""),
                    "address_pool": s.get("address-pool", ""),
                    "disabled": s.get("disabled") == "true",
                    "lease_count": self._safe_int(s.get("lease-count")),
                    "dynamic_count": self._safe_int(s.get("dynamic-count")),
                })
            return {"success": True, "data": servers}
        except Exception as e:
            logger.error(f"Error getting DHCP server status: {e}")
            return {"error": str(e)}
