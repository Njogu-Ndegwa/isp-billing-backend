# Flash-Router Hotspot Provisioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Guarantee flash-filesystem routers (hEX + any device exposing a `flash` namespace, v6 & v7) receive the full hotspot support-file set during provisioning, without relying on the unreliable `reset-html-directory`.

**Architecture:** Add a NEW, additive branch to the `.rsc` generator that — only when the router's effective `html-directory` resolves to a `flash/` path — `/tool fetch`es each support file from a new backend asset endpoint that serves a canonical bundle committed to the repo. The existing non-flash path, the existing `login.html` fetch, and `reset-html-directory` are left untouched.

**Tech Stack:** Python (FastAPI), pytest, RouterOS `.rsc` scripting.

**HARD GUARDRAIL:** Do not modify the current provisioning behavior. The flash branch is runtime-gated; non-flash devices generate/run an identical script to today. `login.html` continues to be served by the existing `/login-page` endpoint and `get_login_page_html()` — those are NOT touched.

---

## File Structure

- `hotspot_template/` (repo root, **new dir**) — canonical support files served to flash devices. Top-level functional set only (no subdirs needed for the redirect portal).
- `app/services/provisioning.py` (**modify**) — add `HOTSPOT_ASSET_FILES` constant + `HOTSPOT_TEMPLATE_DIR` path; add the additive flash branch to `_rsc_login_page()`.
- `app/api/provisioning.py` (**modify**) — add `serve_hotspot_asset` endpoint; tweak the v7 `note` text in `create_provision_token`.
- `tests/test_provisioning_script.py` (**modify**) — assert the flash branch is emitted + the current path is unchanged.
- `tests/test_hotspot_asset.py` (**new**) — endpoint behavior + bundle integrity.
- `../isp-billing-admin` — **no code change** (both add-router and onboarding render the backend `note` already); verification only.

---

### Task 1: Asset manifest + bundle path constants

**Files:**
- Modify: `app/services/provisioning.py` (near line 37, after `API_USERNAME`)
- Test: `tests/test_hotspot_asset.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_hotspot_asset.py
from app.services.provisioning import HOTSPOT_ASSET_FILES, HOTSPOT_TEMPLATE_DIR

def test_manifest_is_top_level_functional_set():
    # login.html is intentionally NOT in the bundle (served by the existing
    # /login-page endpoint, current path untouched).
    assert "login.html" not in HOTSPOT_ASSET_FILES
    for essential in ("redirect.html", "errors.txt", "alogin.html", "error.html"):
        assert essential in HOTSPOT_ASSET_FILES
    # Top-level only (no subdir support files in the functional set).
    assert all("/" not in name for name in HOTSPOT_ASSET_FILES)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_hotspot_asset.py::test_manifest_is_top_level_functional_set -v`
Expected: FAIL with `ImportError: cannot import name 'HOTSPOT_ASSET_FILES'`

- [ ] **Step 3: Add the constants**

```python
# app/services/provisioning.py  (after API_USERNAME = "bitwave-api")
HOTSPOT_TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "hotspot_template",
)
# Top-level RouterOS hotspot support files needed for the captive-portal redirect
# handshake. login.html is NOT here (served by the existing /login-page endpoint).
# Subdir assets (css/, img/, xml/) are non-essential for the redirect portal and
# are intentionally out of scope (see plan "Out of scope").
HOTSPOT_ASSET_FILES = [
    "redirect.html", "alogin.html", "rlogin.html", "logout.html",
    "status.html", "error.html", "errors.txt", "radvert.html", "api.json",
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_hotspot_asset.py::test_manifest_is_top_level_functional_set -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/services/provisioning.py tests/test_hotspot_asset.py
git commit -m "feat(provisioning): add hotspot asset manifest + template path"
```

---

### Task 2: Assemble the canonical bundle on disk

**Files:**
- Create: `hotspot_template/redirect.html`, `alogin.html`, `rlogin.html`, `logout.html`, `status.html`, `error.html`, `errors.txt`, `radvert.html`, `api.json`
- Test: `tests/test_hotspot_asset.py`

**Sourcing:** Each file is a standard RouterOS hotspot default. Pull them from a known-good router (id 207 / `10.0.0.78`) — all 9 are < 4 KB so the RouterOS API `/file print` `contents` field returns them intact (unlike `md5.js`/`favicon.ico`, which exceed the ~4 KB cap and are out of scope here). Use the established pattern (read creds in a short DB session, release, then per-file `send_command_optimized("/file/print", proplist=["name","contents"], query="?name=hotspot/<f>")`) and write each result to `hotspot_template/<f>`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_hotspot_asset.py
import os
from app.services.provisioning import HOTSPOT_ASSET_FILES, HOTSPOT_TEMPLATE_DIR

def test_every_manifest_file_exists_and_nonempty():
    for name in HOTSPOT_ASSET_FILES:
        path = os.path.join(HOTSPOT_TEMPLATE_DIR, name)
        assert os.path.isfile(path), f"missing bundle file: {name}"
        assert os.path.getsize(path) > 0, f"empty bundle file: {name}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_hotspot_asset.py::test_every_manifest_file_exists_and_nonempty -v`
Expected: FAIL (files not present yet)

- [ ] **Step 3: Source the files**

Run this one-off (read-only on the router) from your workstation, then commit the resulting files. It writes each support file into `hotspot_template/`:

```bash
ssh -o BatchMode=yes dennis@54.91.202.229 'docker exec -e SRC_ID=207 -i isp_billing_app python -' <<'PY' > /tmp/assets.json
import asyncio, json, os
from app.db.database import async_session, async_engine
from app.db.models import Router
from app.services.mikrotik_api import MikroTikAPI
from app.services.provisioning import HOTSPOT_ASSET_FILES
async def main():
    async with async_session() as db:
        r = await db.get(Router, int(os.environ["SRC_ID"]))
        info = {"ip": r.ip_address, "user": r.username, "pw": r.password, "port": r.port or 8728}
        await db.commit()
    await async_engine.dispose()
    api = MikroTikAPI(info["ip"], info["user"], info["pw"], info["port"], timeout=20, connect_timeout=8)
    api.connect()
    out = {}
    for name in HOTSPOT_ASSET_FILES:
        res = api.send_command_optimized("/file/print", proplist=["name","contents"], query=f"?name=hotspot/{name}")
        rows = res.get("data", []) if res.get("success") else []
        out[name] = rows[0].get("contents","") if rows else None
    api.disconnect()
    print(json.dumps(out))
asyncio.run(main())
PY
# then on your workstation:
python - <<'PY'
import json, os
from app.services.provisioning import HOTSPOT_TEMPLATE_DIR, HOTSPOT_ASSET_FILES
data = json.load(open("/tmp/assets.json"))
os.makedirs(HOTSPOT_TEMPLATE_DIR, exist_ok=True)
for name in HOTSPOT_ASSET_FILES:
    c = data[name]
    assert c, f"empty/missing source for {name}"
    open(os.path.join(HOTSPOT_TEMPLATE_DIR, name), "w", encoding="utf-8", newline="").write(c)
print("wrote", len(HOTSPOT_ASSET_FILES), "files")
PY
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_hotspot_asset.py::test_every_manifest_file_exists_and_nonempty -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hotspot_template/
git commit -m "feat(provisioning): commit canonical hotspot support-file bundle"
```

---

### Task 3: Backend asset endpoint

**Files:**
- Modify: `app/api/provisioning.py` (add endpoint after `serve_login_page`, ~line 208)
- Test: `tests/test_hotspot_asset.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_hotspot_asset.py
from fastapi.testclient import TestClient
from main import app
client = TestClient(app)

def test_asset_endpoint_rejects_path_traversal_and_unknown_files():
    # Unknown/whitelisted-only: a name not in the manifest must 404, even if it exists.
    r = client.get("/api/provision/anytoken/hotspot-asset/..%2f..%2fmain.py")
    assert r.status_code in (400, 404)
    r2 = client.get("/api/provision/anytoken/hotspot-asset/not-a-real-asset.html")
    assert r2.status_code == 404
```

(Endpoint validates token existence like `serve_login_page`; for the unit test above, the manifest/whitelist rejection happens before/independ] of token lookup — assert the not-in-manifest path 404s.)

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_hotspot_asset.py -k path_traversal -v`
Expected: FAIL (404 endpoint not found → actually 404; tighten by asserting the route exists once implemented). If the route is absent the test passes trivially on 404 — so also assert a *valid* asset returns 200 in Step 3's test below.

- [ ] **Step 3: Implement the endpoint + valid-asset test**

```python
# app/api/provisioning.py  (after serve_login_page)
import os
from fastapi.responses import FileResponse
from app.services.provisioning import HOTSPOT_ASSET_FILES, HOTSPOT_TEMPLATE_DIR

@router.get("/api/provision/{provision_token}/hotspot-asset/{relpath:path}")
async def serve_hotspot_asset(
    provision_token: str,
    relpath: str,
    db: AsyncSession = Depends(get_db),
):
    """Serve a canonical hotspot support file for the flash-device provisioning
    path. Whitelisted to HOTSPOT_ASSET_FILES (no traversal). Token only needs to
    exist (PROVISIONED/expired accepted, like serve_login_page)."""
    if relpath not in HOTSPOT_ASSET_FILES:
        raise HTTPException(status_code=404, detail="Unknown hotspot asset")
    result = await db.execute(
        select(ProvisioningToken).where(ProvisioningToken.token == provision_token)
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Provisioning token not found")
    path = os.path.join(HOTSPOT_TEMPLATE_DIR, relpath)
    if not os.path.isfile(path):
        raise HTTPException(status_code=500, detail=f"asset {relpath} not on server")
    return FileResponse(path)
```

```python
# tests/test_hotspot_asset.py  — valid-asset path (needs a token row; use the
# project's existing async test-DB fixture/pattern — mirror tests that hit
# token-backed endpoints. Pseudocode shape:)
def test_valid_asset_served(seeded_token):  # seeded_token = a ProvisioningToken in the test DB
    r = client.get(f"/api/provision/{seeded_token}/hotspot-asset/redirect.html")
    assert r.status_code == 200
    assert len(r.content) > 0
```

- [ ] **Step 4: Run tests to verify pass**

Run: `pytest tests/test_hotspot_asset.py -v`
Expected: PASS (traversal/unknown → 404; valid asset → 200)

- [ ] **Step 5: Commit**

```bash
git add app/api/provisioning.py tests/test_hotspot_asset.py
git commit -m "feat(provisioning): serve canonical hotspot assets (whitelisted)"
```

---

### Task 4: Additive flash branch in the `.rsc` generator

**Files:**
- Modify: `app/services/provisioning.py` `_rsc_login_page()` (append after the existing fetch loop, before the closing `"""` at ~line 614)
- Test: `tests/test_provisioning_script.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_provisioning_script.py  (reuse the module's _token helper)
from app.services.provisioning import generate_rsc_script, HOTSPOT_ASSET_FILES

def test_flash_branch_present_and_runtime_gated():
    for vpn_type in ("wireguard", "l2tp"):
        s = generate_rsc_script(_token(vpn_type))
        assert ':if ([:pick $htmlDir 0 6] = "flash/")' in s, vpn_type
        for name in HOTSPOT_ASSET_FILES:
            assert f"/hotspot-asset/{name}" in s, (vpn_type, name)

def test_current_path_untouched_login_fetch_still_present():
    # Guardrail: the existing login.html fetch + reset-html-directory remain.
    for vpn_type in ("wireguard", "l2tp"):
        s = generate_rsc_script(_token(vpn_type))
        assert "/login-page" in s, vpn_type
        assert "reset-html-directory" in s, vpn_type
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_provisioning_script.py -k flash_branch -v`
Expected: FAIL (flash branch not emitted yet)

- [ ] **Step 3: Implement the additive branch**

Append inside the `_rsc_login_page` f-string, AFTER the existing `:for i ... login-page ...` loop and before the final `"""` (note `{{`/`}}` escaping; build the RouterOS array literal from the manifest):

```python
    # built above the return, alongside base_url/t/cert_flag:
    asset_array = ";".join(f'"{name}"' for name in HOTSPOT_ASSET_FILES)
```

```
# ---- STEP 5b: FLASH DEVICES -- fetch full hotspot support set ----
# Flash-filesystem routers resolve html-directory to flash/... and do NOT get
# the default file set populated (reset-html-directory is unavailable on 7.20+).
# Runtime-gated: non-flash devices skip this entirely (current path unchanged).
:if ([:pick $htmlDir 0 6] = "flash/") do={{
    :foreach asset in={{{asset_array}}} do={{
        :local adst ($htmlDir . "/" . $asset)
        :local aurl ("{base_url}/api/provision/{t}/hotspot-asset/" . $asset)
        :local aok false
        :for k from=1 to=3 do={{
            :if (!$aok) do={{
                :do {{
                    /tool fetch url=$aurl dst-path=$adst{cert_flag}
                    :set aok true
                }} on-error={{ :delay 3s }}
            }}
        }}
    }}
    :log info "Provisioning: flash-device hotspot support files fetched"
}}
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_provisioning_script.py -v`
Expected: PASS (flash branch + guardrail tests green; existing tests still pass)

- [ ] **Step 5: Commit**

```bash
git add app/services/provisioning.py tests/test_provisioning_script.py
git commit -m "feat(provisioning): additive flash-device hotspot file fetch branch"
```

---

### Task 5: Update the operator note (additive wording)

**Files:**
- Modify: `app/api/provisioning.py` `create_provision_token`, the v7 `note` (~lines 108-113)
- Test: `tests/test_provisioning_urls.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_provisioning_urls.py  (or a small new test using the create flow's note builder)
def test_v7_note_mentions_hotspot_autoinstall():
    # If the note is built inline, extract it to a helper note_for(vpn_type, ...) and test that.
    from app.api.provisioning import _provision_note  # extract during this task
    note = _provision_note("wireguard", is_routerboard=False)
    assert "hotspot" in note.lower()
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_provisioning_urls.py -k note -v`
Expected: FAIL (`_provision_note` not defined)

- [ ] **Step 3: Extract + extend the note**

Extract the existing inline `note` strings into `_provision_note(vpn_type, is_routerboard)` (verbatim move — no wording change to existing branches except appending one sentence to the v7 branch):

```python
def _provision_note(vpn_type: str, is_routerboard: bool) -> str:
    if vpn_type == "l2tp":
        ...  # existing l2tp text, unchanged
    return (
        "IMPORTANT: Before running this command on the MikroTik, ensure "
        "device-mode hotspot is enabled. Run: /system/device-mode/update hotspot=yes "
        "then tap the physical reset button on the router (quick tap, do NOT hold). "
        "Hotspot login pages install automatically (including on hEX/flash routers). "
        "If a customer still isn't redirected after provisioning, run the "
        "diagnose-customer-router check."
    )
```

Replace the inline `note = (...)` assignments in `create_provision_token` with `note = _provision_note(vpn_type, is_routerboard)`.

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_provisioning_urls.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/api/provisioning.py tests/test_provisioning_urls.py
git commit -m "feat(provisioning): note hotspot auto-install in v7 provisioning note"
```

---

### Task 6: Frontend / onboarding verification (no code change)

**Files:** none modified (verification only). `../isp-billing-admin/app/routers/page.tsx` (~1908) and `app/setup/page.tsx` (~265/1913) already render `result.note`.

- [ ] **Step 1:** In `../isp-billing-admin`, run the build: `npm run build`. Expected: succeeds (no changes).
- [ ] **Step 2:** Manually confirm the add-router page and the onboarding "Add Your First Router" step display the updated note text returned by `/api/provision/create`. (No code change required; both call the same `api.createProvisionToken`.)
- [ ] **Step 3:** No commit (no changes). If a copy tweak is desired later, it's a separate frontend task.

---

### Task 7: Live verification

**Files:** none (operational verification).

- [ ] **Step 1:** Generate a provisioning token from BOTH the add-router page and the onboarding wizard; confirm the returned `command`/`.rsc` (via `/api/provision/<token>/rsc`) contains the `:if ([:pick $htmlDir 0 6] = "flash/")` branch and the per-asset fetch URLs.
- [ ] **Step 2:** Re-provision a real flash router (hEX 213 and/or RB951-flash 215) with the new command. Confirm via the read-only `diagnose-customer-router` tool that `flash/hotspot` now contains the full support set and `findings: []`.
- [ ] **Step 3:** Confirm a non-flash router (e.g. 207) provisions identically to before (guardrail): its generated script's non-`flash/` path is unchanged and it still uses `reset-html-directory` + `/login-page`.

---

## Out of scope (documented follow-ups)
- **Subdir assets** (`css/`, `img/`, `xml/`) and the large/binary files (`md5.js` ~7 KB, `favicon.ico`): non-essential for the redirect portal; require RouterOS subdir creation and an FTP/export sourcing path (API 4 KB cap blocks them). Add later if a fully native-styled portal is wanted.
- **Universal gate:** flip the flash `:if` to run for all devices as a safety net against a future non-flash RouterOS dropping `reset-html-directory`. One-line change.
- **Repair reuse:** point `remediate-captive-portal` at the same bundle to fix already-provisioned broken routers.
