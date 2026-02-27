PROTECTED_SPECIFIC_IPS = [
    "10.0.0.1",       # AWS WireGuard VPN endpoint
    "10.0.0.2",       # MikroTik WireGuard VPN endpoint  
    "10.0.0.3",       # Alternative MikroTik VPN IP
    "192.168.88.1",   # MikroTik router management IP
    "127.0.0.1",      # Localhost
]

PROTECTED_INTERFACES = [
    "wg-aws",       # WireGuard VPN interface
    "wg0",          # Alternative WireGuard name
    "ether1",       # Usually WAN interface (uplink to ISP)
    "pppoe-out",    # PPPoE WAN connection
    "lte1",         # LTE WAN
    "sfp1",         # SFP WAN port
]

PROTECTED_HOSTNAMES = [
    "aws-server",
    "billing-server", 
    "api-server",
    "mikrotik",
    "router",
]


def is_protected_device(ip_address: str = None, interface: str = None, hostname: str = None) -> bool:
    """
    Check if a device should be protected from being flagged as illegal.
    
    Returns True if the device is:
    - A specific infrastructure IP (router, VPN endpoints)
    - Connected via a WAN/uplink interface (NOT bridge/customer interfaces)
    - Has a protected hostname
    
    NOTE: We do NOT protect entire IP ranges like 192.168.88.x because
    those are customer DHCP pools, not infrastructure!
    """
    if ip_address:
        if ip_address in PROTECTED_SPECIFIC_IPS:
            return True
    
    if interface:
        interface_lower = interface.lower()
        if "bridge" in interface_lower:
            return False
        for protected in PROTECTED_INTERFACES:
            if protected.lower() in interface_lower:
                return True
    
    if hostname:
        hostname_lower = hostname.lower()
        for protected in PROTECTED_HOSTNAMES:
            if protected.lower() in hostname_lower:
                return True
    
    return False
