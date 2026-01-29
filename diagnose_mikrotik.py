#!/usr/bin/env python3
"""
MikroTik Slow Internet Diagnostic Script
Checks common causes of slow internet through a MikroTik router
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.services.mikrotik_api import MikroTikAPI
from dotenv import load_dotenv

load_dotenv()

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠ WARNING: {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}✗ PROBLEM: {text}{Colors.END}")

def print_ok(text):
    print(f"{Colors.GREEN}✓ OK: {text}{Colors.END}")

def print_info(text):
    print(f"{Colors.BLUE}ℹ INFO: {text}{Colors.END}")

def format_bytes(bytes_val):
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.2f} PB"

def diagnose_router():
    host = os.getenv('MIKROTIK_HOST', '10.0.0.2')
    port = int(os.getenv('MIKROTIK_PORT', 8728))
    username = os.getenv('MIKROTIK_USERNAME', 'admin')
    password = os.getenv('MIKROTIK_PASSWORD', '')
    
    print_header("MikroTik Slow Internet Diagnostics")
    print(f"Connecting to {host}:{port} as {username}...")
    
    api = MikroTikAPI(host, username, password, port, timeout=30)
    
    if not api.connect():
        print_error(f"Failed to connect to MikroTik at {host}:{port}")
        return
    
    print_ok("Connected to MikroTik router")
    issues_found = []
    
    # ============================================================
    # 1. CHECK SYSTEM RESOURCES (CPU, Memory)
    # ============================================================
    print_header("1. System Resources")
    
    resources = api.get_system_resources()
    if resources.get("success"):
        data = resources["data"]
        print(f"   Router: {data.get('board_name', 'Unknown')} ({data.get('architecture_name', '')})")
        print(f"   Version: {data.get('version', 'Unknown')}")
        print(f"   Uptime: {data.get('uptime', 'Unknown')}")
        print(f"   CPU: {data.get('cpu', 'Unknown')} x{data.get('cpu_count', 1)} @ {data.get('cpu_frequency', 0)} MHz")
        
        cpu_load = data.get('cpu_load', 0)
        total_mem = data.get('total_memory', 1)
        free_mem = data.get('free_memory', 0)
        mem_usage = ((total_mem - free_mem) / total_mem) * 100 if total_mem > 0 else 0
        
        print(f"\n   CPU Load: {cpu_load}%")
        if cpu_load > 80:
            print_error(f"CPU load is very high ({cpu_load}%). This will cause slow internet!")
            issues_found.append("HIGH_CPU")
        elif cpu_load > 50:
            print_warning(f"CPU load is moderate ({cpu_load}%). May affect performance.")
        else:
            print_ok(f"CPU load is normal ({cpu_load}%)")
        
        print(f"\n   Memory: {format_bytes(total_mem - free_mem)} / {format_bytes(total_mem)} ({mem_usage:.1f}% used)")
        if mem_usage > 90:
            print_error(f"Memory usage is critically high ({mem_usage:.1f}%)!")
            issues_found.append("HIGH_MEMORY")
        elif mem_usage > 70:
            print_warning(f"Memory usage is elevated ({mem_usage:.1f}%)")
        else:
            print_ok(f"Memory usage is normal ({mem_usage:.1f}%)")
    else:
        print_error(f"Could not get system resources: {resources.get('error')}")
    
    # ============================================================
    # 2. CHECK CONNECTION TRACKING
    # ============================================================
    print_header("2. Connection Tracking")
    
    conntrack = api.send_command("/ip/firewall/connection/print", {"count-only": ""})
    conntrack_settings = api.send_command("/ip/firewall/connection/tracking/print")
    
    if conntrack_settings.get("success") and conntrack_settings.get("data"):
        settings = conntrack_settings["data"][0] if conntrack_settings["data"] else {}
        enabled = settings.get("enabled", "no")
        max_entries = int(settings.get("max-entries", 0))
        total_entries = int(settings.get("total-entries", 0))
        
        print(f"   Connection Tracking: {'Enabled' if enabled == 'yes' else 'Disabled'}")
        print(f"   Active Connections: {total_entries:,}")
        print(f"   Max Connections: {max_entries:,}")
        
        if max_entries > 0:
            usage = (total_entries / max_entries) * 100
            print(f"   Usage: {usage:.1f}%")
            
            if usage > 90:
                print_error(f"Connection tracking table is almost full ({usage:.1f}%)! This WILL cause slowness!")
                issues_found.append("CONNTRACK_FULL")
            elif usage > 70:
                print_warning(f"Connection tracking usage is high ({usage:.1f}%)")
            else:
                print_ok(f"Connection tracking usage is normal ({usage:.1f}%)")
    
    # ============================================================
    # 3. CHECK FASTTRACK STATUS
    # ============================================================
    print_header("3. FastTrack Configuration")
    
    filter_rules = api.send_command("/ip/firewall/filter/print")
    fasttrack_enabled = False
    fasttrack_counter = 0
    
    if filter_rules.get("success") and filter_rules.get("data"):
        for rule in filter_rules["data"]:
            action = rule.get("action", "")
            if action == "fasttrack-connection":
                fasttrack_enabled = True
                fasttrack_counter = int(rule.get("bytes", 0))
                print(f"   FastTrack rule found: {rule.get('comment', 'No comment')}")
                print(f"   FastTrack bytes processed: {format_bytes(fasttrack_counter)}")
                break
    
    if fasttrack_enabled:
        if fasttrack_counter > 0:
            print_ok("FastTrack is enabled and actively processing traffic")
        else:
            print_warning("FastTrack rule exists but has 0 bytes - may not be matching traffic")
            issues_found.append("FASTTRACK_NOT_MATCHING")
    else:
        print_error("FastTrack is NOT enabled! This causes all traffic to go through CPU.")
        print_info("FastTrack allows the router to skip firewall for established connections.")
        issues_found.append("NO_FASTTRACK")
    
    # ============================================================
    # 4. CHECK SIMPLE QUEUES
    # ============================================================
    print_header("4. Simple Queues (Bandwidth Limits)")
    
    queues = api.send_command("/queue/simple/print")
    restrictive_queues = []
    
    if queues.get("success") and queues.get("data"):
        print(f"   Total queues: {len(queues['data'])}")
        
        for q in queues["data"]:
            name = q.get("name", "Unknown")
            target = q.get("target", "")
            max_limit = q.get("max-limit", "0/0")
            disabled = q.get("disabled", "false") == "true"
            
            if disabled:
                continue
            
            # Parse max-limit (format: upload/download)
            limits = max_limit.split("/")
            upload_limit = limits[0] if len(limits) > 0 else "0"
            download_limit = limits[1] if len(limits) > 1 else "0"
            
            # Check if queue is global (targets 0.0.0.0/0 or all clients)
            is_global = target in ["0.0.0.0/0", ""] or "0.0.0.0" in target
            
            print(f"\n   Queue: {name}")
            print(f"   Target: {target}")
            print(f"   Max Limit: ↑{upload_limit} / ↓{download_limit}")
            
            # Check for very restrictive limits
            def parse_speed(s):
                s = s.upper().replace(" ", "")
                if "M" in s:
                    return float(s.replace("M", "")) * 1000000
                elif "K" in s:
                    return float(s.replace("K", "")) * 1000
                return float(s) if s.isdigit() else 0
            
            dl_bps = parse_speed(download_limit)
            if dl_bps > 0 and dl_bps < 2000000:  # Less than 2Mbps
                print_warning(f"Queue '{name}' has very restrictive limit: {download_limit}")
                restrictive_queues.append(name)
                
            if is_global and dl_bps > 0:
                print_error(f"GLOBAL queue '{name}' is limiting ALL traffic to {download_limit}!")
                issues_found.append("GLOBAL_QUEUE_LIMIT")
    else:
        print_ok("No simple queues configured (no artificial bandwidth limits)")
    
    if restrictive_queues:
        issues_found.append("RESTRICTIVE_QUEUES")
    
    # ============================================================
    # 5. CHECK INTERFACE ERRORS
    # ============================================================
    print_header("5. Interface Status and Errors")
    
    interfaces = api.get_interface_traffic()
    if interfaces.get("success") and interfaces.get("data"):
        for iface in interfaces["data"]:
            if not iface.get("running"):
                continue
            
            name = iface.get("name", "")
            rx_errors = iface.get("rx_error", 0)
            tx_errors = iface.get("tx_error", 0)
            rx_bytes = iface.get("rx_byte", 0)
            tx_bytes = iface.get("tx_byte", 0)
            
            # Skip interfaces with no traffic
            if rx_bytes == 0 and tx_bytes == 0:
                continue
            
            print(f"\n   Interface: {name} ({iface.get('type', '')})")
            print(f"   RX: {format_bytes(rx_bytes)} | TX: {format_bytes(tx_bytes)}")
            print(f"   Errors - RX: {rx_errors} | TX: {tx_errors}")
            
            if rx_errors > 1000 or tx_errors > 1000:
                print_error(f"High error count on {name}! Cable/hardware issue possible.")
                issues_found.append(f"INTERFACE_ERRORS_{name}")
            elif rx_errors > 100 or tx_errors > 100:
                print_warning(f"Some errors on {name}")
    
    # ============================================================
    # 6. CHECK FIREWALL RULES COUNT
    # ============================================================
    print_header("6. Firewall Rules Analysis")
    
    filter_count = len(filter_rules.get("data", [])) if filter_rules.get("success") else 0
    nat_rules = api.send_command("/ip/firewall/nat/print")
    nat_count = len(nat_rules.get("data", [])) if nat_rules.get("success") else 0
    mangle_rules = api.send_command("/ip/firewall/mangle/print")
    mangle_count = len(mangle_rules.get("data", [])) if mangle_rules.get("success") else 0
    
    print(f"   Filter rules: {filter_count}")
    print(f"   NAT rules: {nat_count}")
    print(f"   Mangle rules: {mangle_count}")
    
    total_rules = filter_count + nat_count + mangle_count
    if total_rules > 100:
        print_warning(f"High number of firewall rules ({total_rules}). May impact performance without FastTrack.")
    else:
        print_ok(f"Firewall rule count is reasonable ({total_rules})")
    
    # ============================================================
    # 7. CHECK HOTSPOT CONFIGURATION
    # ============================================================
    print_header("7. Hotspot Configuration")
    
    hotspot_servers = api.send_command("/ip/hotspot/print")
    if hotspot_servers.get("success") and hotspot_servers.get("data"):
        print(f"   Active Hotspot Servers: {len(hotspot_servers['data'])}")
        for hs in hotspot_servers["data"]:
            name = hs.get("name", "Unknown")
            interface = hs.get("interface", "")
            disabled = hs.get("disabled", "false") == "true"
            print(f"   - {name} on {interface} {'(DISABLED)' if disabled else '(ACTIVE)'}")
        
        print_info("Hotspot adds processing overhead. Consider using Simple Queues only for bandwidth control.")
    else:
        print_info("No hotspot servers configured")
    
    # Check active hotspot sessions
    active = api.get_active_hotspot_users()
    if active.get("success"):
        sessions = active.get("data", [])
        print(f"\n   Active Hotspot Sessions: {len(sessions)}")
        if len(sessions) > 50:
            print_warning(f"High number of active sessions ({len(sessions)}) may impact CPU")
    
    # ============================================================
    # 8. CHECK DNS SETTINGS
    # ============================================================
    print_header("8. DNS Configuration")
    
    dns = api.send_command("/ip/dns/print")
    if dns.get("success") and dns.get("data"):
        dns_data = dns["data"][0] if dns["data"] else {}
        servers = dns_data.get("servers", "")
        allow_remote = dns_data.get("allow-remote-requests", "no")
        cache_size = dns_data.get("cache-size", "0")
        cache_used = dns_data.get("cache-used", "0")
        
        print(f"   DNS Servers: {servers}")
        print(f"   Allow Remote Requests: {allow_remote}")
        print(f"   Cache Size: {cache_size} (Used: {cache_used})")
        
        if not servers:
            print_warning("No DNS servers configured! This will cause very slow page loading.")
            issues_found.append("NO_DNS")
        
        if allow_remote == "yes":
            print_info("Router is acting as DNS server for clients")
    
    # ============================================================
    # 9. CHECK MTU SETTINGS
    # ============================================================
    print_header("9. MTU Configuration")
    
    wan_interfaces = ["ether1", "pppoe-out1", "lte1", "wlan1"]
    for wan in wan_interfaces:
        iface_detail = api.send_command("/interface/print", {"where": f"name={wan}"})
        if iface_detail.get("success") and iface_detail.get("data"):
            iface = iface_detail["data"][0]
            mtu = iface.get("mtu", "")
            actual_mtu = iface.get("actual-mtu", mtu)
            print(f"   {wan}: MTU={mtu}, Actual MTU={actual_mtu}")
            
            if actual_mtu and int(actual_mtu) < 1400:
                print_warning(f"Low MTU on {wan} ({actual_mtu}). May cause fragmentation.")
    
    # ============================================================
    # 10. CHECK FOR PPPoE (adds overhead)
    # ============================================================
    print_header("10. PPPoE Check")
    
    pppoe = api.send_command("/interface/pppoe-client/print")
    if pppoe.get("success") and pppoe.get("data"):
        for p in pppoe["data"]:
            name = p.get("name", "")
            status = p.get("running", "false")
            print(f"   PPPoE Client: {name} - {'Running' if status == 'true' else 'Not Running'}")
        print_info("PPPoE adds ~8 bytes overhead per packet, reducing effective MTU")
    else:
        print_info("No PPPoE client configured")
    
    # ============================================================
    # SUMMARY AND RECOMMENDATIONS
    # ============================================================
    print_header("DIAGNOSTIC SUMMARY")
    
    if not issues_found:
        print_ok("No obvious issues found! The problem may be:")
        print("   - ISP throttling")
        print("   - WAN interface issue")
        print("   - WiFi interference (if using wireless)")
        print("   - Specific website/service issues")
    else:
        print(f"\n{Colors.RED}Found {len(issues_found)} potential issues:{Colors.END}\n")
        
        for issue in issues_found:
            if issue == "HIGH_CPU":
                print_error("HIGH CPU LOAD")
                print("   Fix: Check for bandwidth test tools running, reduce firewall complexity,")
                print("        or upgrade router hardware")
                print("   Command: /tool/profile to see what's using CPU")
                
            elif issue == "HIGH_MEMORY":
                print_error("HIGH MEMORY USAGE")
                print("   Fix: Reboot router, reduce connection tracking limit, or upgrade hardware")
                
            elif issue == "CONNTRACK_FULL":
                print_error("CONNECTION TRACKING TABLE FULL")
                print("   Fix: Increase max-entries or reduce TCP timeout values")
                print("   Command: /ip/firewall/connection/tracking/set max-entries=65536")
                
            elif issue == "NO_FASTTRACK":
                print_error("FASTTRACK NOT ENABLED")
                print("   Fix: Add FastTrack rule to dramatically reduce CPU usage:")
                print("   Command:")
                print('   /ip/firewall/filter/add chain=forward action=fasttrack-connection connection-state=established,related')
                print('   /ip/firewall/filter/add chain=forward action=accept connection-state=established,related')
                
            elif issue == "FASTTRACK_NOT_MATCHING":
                print_warning("FASTTRACK NOT MATCHING TRAFFIC")
                print("   Fix: Check FastTrack rule position (should be at top of filter rules)")
                print("   Command: /ip/firewall/filter/move [find action=fasttrack-connection] 0")
                
            elif issue == "GLOBAL_QUEUE_LIMIT":
                print_error("GLOBAL BANDWIDTH LIMIT ACTIVE")
                print("   Fix: Remove or disable the global queue limiting all traffic")
                print("   Command: /queue/simple/print then /queue/simple/remove [find name=...]")
                
            elif issue == "RESTRICTIVE_QUEUES":
                print_warning("RESTRICTIVE BANDWIDTH QUEUES")
                print("   Fix: Check queue targets - ensure your device isn't limited")
                
            elif issue == "NO_DNS":
                print_error("NO DNS SERVERS CONFIGURED")
                print("   Fix: Add DNS servers (Google 8.8.8.8, Cloudflare 1.1.1.1)")
                print("   Command: /ip/dns/set servers=8.8.8.8,1.1.1.1")
                
            elif "INTERFACE_ERRORS" in issue:
                iface_name = issue.replace("INTERFACE_ERRORS_", "")
                print_error(f"INTERFACE ERRORS ON {iface_name}")
                print("   Fix: Check cables, replace if necessary, or check for interference")
            
            print()
    
    # Quick commands to check manually
    print_header("QUICK DIAGNOSTIC COMMANDS FOR WINBOX/TERMINAL")
    print("""
   Run these in MikroTik terminal for more details:
   
   # Check CPU usage details
   /tool/profile
   
   # Check what connections exist
   /ip/firewall/connection/print count-only
   
   # Check current bandwidth usage  
   /interface/monitor-traffic ether1
   
   # Check for packet loss
   /tool/ping 8.8.8.8 count=20
   
   # Test bandwidth to internet
   /tool/bandwidth-test address=speedtest.tele2.net direction=receive
   
   # Check if any queue is limiting
   /queue/simple/print stats
    """)
    
    api.disconnect()
    print_ok("Disconnected from router")

if __name__ == "__main__":
    diagnose_router()
