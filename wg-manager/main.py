from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
import subprocess
import os
import logging
import shlex
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="WireGuard Peer Manager")

API_SECRET = os.environ.get("WG_MANAGER_SECRET", "change-me-wg-secret")
WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
SERVER_PUBLIC_KEY_PATH = os.environ.get("WG_SERVER_PUBKEY_PATH", "/etc/wireguard/server_public.key")
L2TP_CHAP_SECRETS_PATH = os.environ.get("L2TP_CHAP_SECRETS_PATH", "/etc/ppp/chap-secrets")
L2TP_SERVER_NAME = "l2tp-server"
WG_RECENT_HANDSHAKE_SECONDS = int(os.environ.get("WG_RECENT_HANDSHAKE_SECONDS", "180"))


def _listening_udp_ports(paths=None):
    """Return UDP ports bound in this network namespace from procfs."""
    paths = paths or ("/proc/net/udp", "/proc/net/udp6")
    ports = set()
    for path in paths:
        try:
            with open(path) as proc_file:
                next(proc_file, None)
                for line in proc_file:
                    fields = line.split()
                    if len(fields) < 2 or ":" not in fields[1]:
                        continue
                    try:
                        ports.add(int(fields[1].rsplit(":", 1)[1], 16))
                    except ValueError:
                        continue
        except OSError:
            continue
    return ports


def _configured_l2tp_peers(path=L2TP_CHAP_SECRETS_PATH):
    usernames = set()
    try:
        with open(path) as secrets_file:
            for line in secrets_file:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                try:
                    fields = shlex.split(stripped)
                except ValueError:
                    continue
                if len(fields) < 2 or fields[1] not in {L2TP_SERVER_NAME, "*"}:
                    continue
                usernames.add(fields[0])
    except OSError:
        return 0
    return len(usernames)


def _active_ppp_sessions(path="/sys/class/net"):
    try:
        return sum(
            1 for name in os.listdir(path)
            if name.startswith("ppp") and name[3:].isdigit()
        )
    except OSError:
        return 0


def _wireguard_health():
    try:
        result = subprocess.run(
            ["wg", "show", WG_INTERFACE, "dump"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {
            "available": False,
            "interface": WG_INTERFACE,
            "listening_port": None,
            "configured_peers": 0,
            "recent_handshakes": 0,
            "stale_handshakes": 0,
            "never_handshaken": 0,
        }

    if result.returncode != 0:
        return {
            "available": False,
            "interface": WG_INTERFACE,
            "listening_port": None,
            "configured_peers": 0,
            "recent_handshakes": 0,
            "stale_handshakes": 0,
            "never_handshaken": 0,
        }

    lines = [line for line in result.stdout.splitlines() if line.strip()]
    interface_fields = lines[0].split("\t") if lines else []
    peers = [line.split("\t") for line in lines[1:]]
    now = int(time.time())
    handshakes = []
    for peer in peers:
        try:
            handshakes.append(int(peer[4]))
        except (IndexError, ValueError):
            handshakes.append(0)

    recent = sum(1 for handshake in handshakes if 0 < now - handshake <= WG_RECENT_HANDSHAKE_SECONDS)
    stale = sum(1 for handshake in handshakes if handshake > 0 and now - handshake > WG_RECENT_HANDSHAKE_SECONDS)
    never = sum(1 for handshake in handshakes if handshake <= 0)
    try:
        listening_port = int(interface_fields[2])
    except (IndexError, ValueError):
        listening_port = None

    return {
        "available": True,
        "interface": WG_INTERFACE,
        "listening_port": listening_port,
        "configured_peers": len(peers),
        "recent_handshakes": recent,
        "stale_handshakes": stale,
        "never_handshaken": never,
        "recent_window_seconds": WG_RECENT_HANDSHAKE_SECONDS,
    }


def _l2tp_health():
    ports = _listening_udp_ports()
    configured_peers = _configured_l2tp_peers()
    l2tp_listener = 1701 in ports
    ipsec_ports = {port: port in ports for port in (500, 4500)}
    ipsec_available = all(ipsec_ports.values())
    required = configured_peers > 0
    return {
        "available": l2tp_listener and ipsec_available,
        "required": required,
        "listener_available": l2tp_listener,
        "ipsec_available": ipsec_available,
        "listening_port": 1701,
        "ipsec_ports": ipsec_ports,
        "configured_peers": configured_peers,
        "active_sessions": _active_ppp_sessions(),
    }


def verify_secret(x_api_key: str = Header(...)):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return True


class AddPeerRequest(BaseModel):
    public_key: str
    allowed_ips: str


class RemovePeerRequest(BaseModel):
    public_key: str


class AddL2tpPeerRequest(BaseModel):
    username: str
    password: str
    ip: str


class RemoveL2tpPeerRequest(BaseModel):
    username: str


@app.post("/add-l2tp-peer")
def add_l2tp_peer(req: AddL2tpPeerRequest, _=Depends(verify_secret)):
    """Append a user line to /etc/ppp/chap-secrets for L2TP authentication."""
    try:
        line = f'{req.username}    {L2TP_SERVER_NAME}    "{req.password}"    {req.ip}\n'
        existing = ""
        if os.path.exists(L2TP_CHAP_SECRETS_PATH):
            with open(L2TP_CHAP_SECRETS_PATH, "r") as f:
                existing = f.read()
        for existing_line in existing.splitlines():
            if existing_line.strip() and existing_line.split()[0] == req.username:
                logger.info(f"L2TP peer {req.username} already exists, updating")
                lines = [l for l in existing.splitlines(True) if not l.strip() or l.split()[0] != req.username]
                lines.append(line)
                with open(L2TP_CHAP_SECRETS_PATH, "w") as f:
                    f.writelines(lines)
                return {"status": "ok", "message": "L2TP peer updated", "username": req.username, "ip": req.ip}
        with open(L2TP_CHAP_SECRETS_PATH, "a") as f:
            f.write(line)
        logger.info(f"Added L2TP peer {req.username} with IP {req.ip}")
        return {"status": "ok", "message": "L2TP peer added", "username": req.username, "ip": req.ip}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add L2TP peer: {e}")


@app.delete("/remove-l2tp-peer")
def remove_l2tp_peer(req: RemoveL2tpPeerRequest, _=Depends(verify_secret)):
    """Remove a user line from /etc/ppp/chap-secrets."""
    try:
        if not os.path.exists(L2TP_CHAP_SECRETS_PATH):
            raise HTTPException(status_code=404, detail="chap-secrets file not found")
        with open(L2TP_CHAP_SECRETS_PATH, "r") as f:
            lines = f.readlines()
        new_lines = [l for l in lines if not l.strip() or l.split()[0] != req.username]
        if len(new_lines) == len(lines):
            raise HTTPException(status_code=404, detail=f"L2TP peer {req.username} not found")
        with open(L2TP_CHAP_SECRETS_PATH, "w") as f:
            f.writelines(new_lines)
        logger.info(f"Removed L2TP peer {req.username}")
        return {"status": "ok", "message": "L2TP peer removed"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove L2TP peer: {e}")


@app.post("/add-peer")
def add_peer(req: AddPeerRequest, _=Depends(verify_secret)):
    try:
        result = subprocess.run(
            ["wg", "set", WG_INTERFACE, "peer", req.public_key,
             "allowed-ips", req.allowed_ips, "persistent-keepalive", "25"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"wg set failed: {result.stderr}")
        logger.info(f"Added peer {req.public_key[:20]}... with allowed-ips {req.allowed_ips}")
        return {"status": "ok", "message": "Peer added", "allowed_ips": req.allowed_ips}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="wg command timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="wg command not found — is wireguard-tools installed?")


@app.delete("/remove-peer")
def remove_peer(req: RemovePeerRequest, _=Depends(verify_secret)):
    try:
        result = subprocess.run(
            ["wg", "set", WG_INTERFACE, "peer", req.public_key, "remove"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"wg set failed: {result.stderr}")
        logger.info(f"Removed peer {req.public_key[:20]}...")
        return {"status": "ok", "message": "Peer removed"}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="wg command timed out")


@app.get("/peers")
def list_peers(_=Depends(verify_secret)):
    try:
        result = subprocess.run(
            ["wg", "show", WG_INTERFACE, "dump"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"wg show failed: {result.stderr}")
        lines = result.stdout.strip().split("\n")
        peers = []
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 4:
                peers.append({
                    "public_key": parts[0],
                    "endpoint": parts[2] if parts[2] != "(none)" else None,
                    "allowed_ips": parts[3],
                    "latest_handshake": parts[4] if len(parts) > 4 else None,
                })
        return {"peers": peers}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="wg command timed out")


@app.get("/server-info")
def server_info(_=Depends(verify_secret)):
    """Return the server's WireGuard public key."""
    # Try reading from file first, fall back to `wg show`
    try:
        with open(SERVER_PUBLIC_KEY_PATH) as f:
            public_key = f.read().strip()
        if public_key:
            return {"public_key": public_key, "interface": WG_INTERFACE}
    except FileNotFoundError:
        pass

    try:
        result = subprocess.run(
            ["wg", "show", WG_INTERFACE, "public-key"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return {"public_key": result.stdout.strip(), "interface": WG_INTERFACE}
        raise HTTPException(
            status_code=500,
            detail=f"Could not read public key: wg returned '{result.stderr.strip()}'"
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=500,
            detail="wg command not found — is wireguard-tools installed?"
        )


@app.get("/health")
def health():
    wireguard = _wireguard_health()
    l2tp = _l2tp_health()
    healthy = wireguard["available"] and (not l2tp["required"] or l2tp["available"])
    return {
        # Keep the original top-level keys for backward compatibility.
        "status": "healthy" if healthy else "unhealthy",
        "interface": WG_INTERFACE,
        "wg_available": wireguard["available"],
        "wireguard": wireguard,
        "l2tp": l2tp,
    }


if __name__ == "__main__":
    import uvicorn
    socket_path = os.environ.get("WG_SOCKET_PATH", "/var/run/wg-manager/wg-manager.sock")
    if os.environ.get("WG_USE_TCP"):
        uvicorn.run(app, host="0.0.0.0", port=8729)
    else:
        os.makedirs(os.path.dirname(socket_path), exist_ok=True)
        uvicorn.run(app, uds=socket_path)
