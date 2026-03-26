from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
import subprocess
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="WireGuard Peer Manager")

API_SECRET = os.environ.get("WG_MANAGER_SECRET", "change-me-wg-secret")
WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
SERVER_PUBLIC_KEY_PATH = os.environ.get("WG_SERVER_PUBKEY_PATH", "/etc/wireguard/server_public.key")
L2TP_CHAP_SECRETS_PATH = os.environ.get("L2TP_CHAP_SECRETS_PATH", "/etc/ppp/chap-secrets")
L2TP_SERVER_NAME = "l2tp-server"


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
    try:
        result = subprocess.run(
            ["wg", "show", WG_INTERFACE],
            capture_output=True, text=True, timeout=5
        )
        return {
            "status": "healthy" if result.returncode == 0 else "degraded",
            "interface": WG_INTERFACE,
            "wg_available": result.returncode == 0
        }
    except Exception:
        return {"status": "unhealthy", "interface": WG_INTERFACE, "wg_available": False}


if __name__ == "__main__":
    import uvicorn
    socket_path = os.environ.get("WG_SOCKET_PATH", "/var/run/wg-manager/wg-manager.sock")
    if os.environ.get("WG_USE_TCP"):
        uvicorn.run(app, host="0.0.0.0", port=8729)
    else:
        os.makedirs(os.path.dirname(socket_path), exist_ok=True)
        uvicorn.run(app, uds=socket_path)
