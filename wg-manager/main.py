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


def verify_secret(x_api_key: str = Header(...)):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return True


class AddPeerRequest(BaseModel):
    public_key: str
    allowed_ips: str


class RemovePeerRequest(BaseModel):
    public_key: str


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
    try:
        with open(SERVER_PUBLIC_KEY_PATH) as f:
            public_key = f.read().strip()
        return {"public_key": public_key, "interface": WG_INTERFACE}
    except FileNotFoundError:
        raise HTTPException(
            status_code=500,
            detail=f"Server public key not found at {SERVER_PUBLIC_KEY_PATH}"
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
    uvicorn.run(app, host="0.0.0.0", port=8729)
