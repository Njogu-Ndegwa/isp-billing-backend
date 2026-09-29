import asyncio
import base64
import hashlib
import time
from datetime import datetime
from typing import Optional
import logging

import httpx
from fastapi import HTTPException

from app.config import settings
from app.core.runtime_mode import require_external_side_effects_enabled

logger = logging.getLogger(__name__)

# ``connect`` covers TCP + the TLS handshake. From Hetzner (DE) to Safaricom (KE)
# first packets get lost and handshakes stretch past 5 s: on 2026-09-29 about 1
# in 8 payment prompts failed with a blank "handshake operation timed out"
# (curl showed 2.3 s connects; 2 of 8 in-app handshakes timed out).
SAFARICOM_TIMEOUT = httpx.Timeout(connect=15.0, read=25.0, write=15.0, pool=5.0)
# Extra attempts when the CONNECTION failed (ConnectError / ConnectTimeout): the
# request never left, so a retry cannot double-charge or double-prompt. Read
# timeouts and HTTP errors are never retried here.
CONNECT_RETRIES = 2
CONNECT_RETRY_BACKOFF_SECONDS = 0.5
# Safaricom OAuth tokens live ~3599 s; refresh this long before they expire.
TOKEN_REFRESH_MARGIN_SECONDS = 120

_token_cache: dict[str, tuple[str, float]] = {}
_token_locks: dict[str, asyncio.Lock] = {}


def _client() -> httpx.AsyncClient:
    """One place to build the HTTP client (tests swap in a mock transport)."""
    return httpx.AsyncClient(timeout=SAFARICOM_TIMEOUT)


def _base_url() -> str:
    return "https://api.safaricom.co.ke" if settings.MPESA_ENVIRONMENT == "production" else "https://sandbox.safaricom.co.ke"


def _token_cache_key(base_url: str, key: str, secret: str) -> str:
    return hashlib.sha256(f"{base_url}|{key}|{secret}".encode()).hexdigest()


def reset_token_cache() -> None:
    _token_cache.clear()
    _token_locks.clear()


def _invalidate_token(consumer_key: Optional[str], consumer_secret: Optional[str]) -> None:
    key = consumer_key or settings.MPESA_CONSUMER_KEY
    secret = consumer_secret or settings.MPESA_CONSUMER_SECRET
    _token_cache.pop(_token_cache_key(_base_url(), key, secret), None)


async def _send_with_connect_retry(method: str, url: str, **kwargs) -> httpx.Response:
    """Send once; retry ONLY when the connection could not be made."""
    last: Optional[Exception] = None
    for attempt in range(1 + CONNECT_RETRIES):
        try:
            async with _client() as client:
                return await client.request(method, url, **kwargs)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            last = exc
            logger.warning(
                "Safaricom connection failed (%s, attempt %d/%d): %s",
                type(exc).__name__, attempt + 1, 1 + CONNECT_RETRIES, exc,
            )
            if attempt < CONNECT_RETRIES:
                await asyncio.sleep(CONNECT_RETRY_BACKOFF_SECONDS * (attempt + 1))
    assert last is not None
    raise last


def _is_invalid_token_response(response: httpx.Response) -> bool:
    return response.status_code in (401, 404) and "Invalid Access Token" in (response.text or "")

# --- Direct M-Pesa logic (for legacy/backup use) ---
class StkPushResponse:
    def __init__(self, checkout_request_id: str, merchant_request_id: str):
        self.checkout_request_id = checkout_request_id
        self.merchant_request_id = merchant_request_id


class StkPushRejected(HTTPException):
    """Safaricom answered the push request with an HTTP error status.

    Still an HTTPException(500) so existing callers behave exactly as before;
    ``safaricom_status`` lets a caller tell an explicit rejection (4xx / 500:
    no prompt was sent, safe to retry another way) from a gateway failure
    (502-504: the prompt may or may not have gone out).
    """

    def __init__(self, safaricom_status: int, detail: str):
        super().__init__(status_code=500, detail=detail)
        self.safaricom_status = safaricom_status

    @property
    def is_definite_rejection(self) -> bool:
        return 400 <= self.safaricom_status <= 500

async def get_access_token(
    consumer_key: Optional[str] = None,
    consumer_secret: Optional[str] = None,
    *,
    use_cache: bool = True,
) -> str:
    """OAuth token for these credentials, reused until shortly before it expires.

    It used to be fetched afresh for every STK push, doubling the calls over a
    lossy link. ``use_cache=False`` forces a fresh fetch (credential tests).
    """
    key = consumer_key or settings.MPESA_CONSUMER_KEY
    secret = consumer_secret or settings.MPESA_CONSUMER_SECRET
    base_url = _base_url()
    cache_key = _token_cache_key(base_url, key, secret)
    if use_cache:
        cached = _token_cache.get(cache_key)
        if cached and cached[1] > time.monotonic():
            return cached[0]
    lock = _token_locks.setdefault(cache_key, asyncio.Lock())
    async with lock:
        if use_cache:
            cached = _token_cache.get(cache_key)          # refreshed by a concurrent request
            if cached and cached[1] > time.monotonic():
                return cached[0]
        try:
            encoded_credentials = base64.b64encode(f"{key}:{secret}".encode()).decode()
            response = await _send_with_connect_retry(
                "GET",
                f"{base_url}/oauth/v1/generate?grant_type=client_credentials",
                headers={"Authorization": f"Basic {encoded_credentials}"},
            )
            response.raise_for_status()
            data = response.json()
            token = data["access_token"]
            try:
                ttl = int(data.get("expires_in", 3599))
            except (TypeError, ValueError):
                ttl = 3599
            _token_cache[cache_key] = (token, time.monotonic() + max(60, ttl - TOKEN_REFRESH_MARGIN_SECONDS))
            return token
        except Exception as e:
            logger.error(f"Failed to get M-Pesa access token: {type(e).__name__}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to get M-Pesa access token: {type(e).__name__}: {e}")

async def initiate_stk_push_direct(
    phone_number: str,
    amount: float,
    reference: str,
    shortcode: Optional[str] = None,
    passkey: Optional[str] = None,
    consumer_key: Optional[str] = None,
    consumer_secret: Optional[str] = None,
    callback_url: Optional[str] = None,
    account_reference: Optional[str] = None,
    party_b: Optional[str] = None,
    transaction_type: str = "CustomerPayBillOnline",
) -> Optional[StkPushResponse]:
    """Raise an M-Pesa Express (STK) push.

    ``party_b`` is the account the money lands in; it defaults to the signing
    ``shortcode``. Direct settlement passes the reseller's own paybill, till
    (with ``transaction_type="CustomerBuyGoodsOnline"``) or bank paybill here
    while the system shortcode still signs the request.
    """
    require_external_side_effects_enabled("M-Pesa STK push")
    try:
        access_token = await get_access_token(
            consumer_key=consumer_key,
            consumer_secret=consumer_secret,
        )
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        active_shortcode = shortcode or settings.MPESA_SHORTCODE
        active_passkey = passkey or settings.MPESA_PASSKEY
        active_callback = callback_url or settings.MPESA_CALLBACK_URL
        password = base64.b64encode(
            f"{active_shortcode}{active_passkey}{timestamp}".encode()
        ).decode()
        
        payload = {
            "BusinessShortCode": active_shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": transaction_type,
            "Amount": int(amount),
            "PartyA": phone_number,
            "PartyB": party_b or active_shortcode,
            "PhoneNumber": phone_number,
            "CallBackURL": active_callback,
            "AccountReference": account_reference or reference,
            "TransactionDesc": "Payment via STK Push"
        }

        base_url = _base_url()

        async def _post(token: str) -> httpx.Response:
            return await _send_with_connect_retry(
                "POST",
                f"{base_url}/mpesa/stkpush/v1/processrequest",
                json=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
            )

        response = await _post(access_token)
        if _is_invalid_token_response(response):
            # A reused token was revoked early: Safaricom rejected the request
            # outright, so fetching a fresh token and sending once more is safe.
            _invalidate_token(consumer_key, consumer_secret)
            access_token = await get_access_token(consumer_key=consumer_key, consumer_secret=consumer_secret)
            response = await _post(access_token)
        if response.status_code != 200:
            logger.error(f"M-Pesa API Error {response.status_code}: {response.text}")
            try:
                error_data = response.json()
                logger.error(f"M-Pesa Error Details: {error_data}")
            except:
                pass
        
        response.raise_for_status()
        result = response.json()
        logger.info(f"STK Push initiated: {result}")
        return StkPushResponse(
            checkout_request_id=result["CheckoutRequestID"],
            merchant_request_id=result["MerchantRequestID"]
        )
    except httpx.HTTPStatusError as e:
        error_msg = f"M-Pesa API returned {e.response.status_code}: {e.response.text}"
        logger.error(f"STK Push initiation failed: {error_msg}")
        raise StkPushRejected(e.response.status_code, f"STK Push initiation failed: {error_msg}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"STK Push initiation failed: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail=f"STK Push initiation failed: {type(e).__name__}: {e}")

# --- GraphQL Microservice Logic ---
async def initiate_stk_push_via_graphql_microservice(
    merchant_id: int,
    amount: float,
    phone_number: str,
    lipay_tx_no: str,
    customer_ref: str,
    graphql_url: str = "https://finance.lipay.store/graphql"
) -> dict:
    """
    Calls the payment microservice GraphQL mutation and automatically falls back
    to the older/newer mutation names when needed.
    """

    require_external_side_effects_enabled("M-Pesa GraphQL STK push")

    variables = {
        "merchantId": merchant_id,
        "amount": amount,
        "phoneNumber": phone_number,
        "lipayTxNo": lipay_tx_no,
        "customerRef": customer_ref
    }

    mutation_candidates = [
        {
            "field_name": "initiateOpenPayment",
            "arguments": [
                ("merchantId", "Int!"),
                ("amount", "Float!"),
                ("phoneNumber", "String!"),
                ("lipayTxNo", "String!"),
                ("customerRef", "String!")
            ],
            "selection": """
        checkoutRequestId
        merchantRequestId
        transactionId
        lipayTxNo
        customerRef
        errorMessage
            """,
        },
        {
            "field_name": "initiatePayment",
            "arguments": [
                ("merchantId", "Int!"),
                ("amount", "Float!"),
                ("phoneNumber", "String!")
            ],
            "selection": """
        checkoutRequestId
        merchantRequestId
        errorMessage
            """,
        },
    ]
    last_error: Optional[Exception] = None

    async with httpx.AsyncClient(timeout=SAFARICOM_TIMEOUT) as client:
        for candidate in mutation_candidates:
            field_name = candidate["field_name"]
            var_defs = ", ".join(f"${name}: {type_}" for name, type_ in candidate["arguments"])
            arg_assignments = ", ".join(f"{name}: ${name}" for name, _ in candidate["arguments"])
            mutation = f"""
    mutation initiatePayment({var_defs}) {{
      {field_name}({arg_assignments}) {{
        {candidate["selection"]}
      }}
    }}
            """
            payload_variables = {
                name: variables[name]
                for name, _ in candidate["arguments"]
                if name in variables and variables[name] is not None
            }
            try:
                response = await client.post(
                    graphql_url,
                    json={"query": mutation, "variables": payload_variables},
                )
                response.raise_for_status()
                data = response.json()

                if "errors" in data:
                    error_messages = " | ".join(
                        err.get("message", "") for err in data["errors"]
                    )
                    # Try next candidate when the mutation name is unknown
                    if (
                        field_name == "initiateOpenPayment"
                        and "Cannot query field" in error_messages
                    ):
                        last_error = Exception(error_messages)
                        continue
                    raise Exception(f"GraphQL Error: {data['errors']}")

                result = data.get("data", {}).get(field_name)
                if not result:
                    raise Exception(
                        f"GraphQL Error: Missing '{field_name}' in response: {data}"
                    )
                if result.get("errorMessage"):
                    raise Exception(f"Payment microservice error: {result['errorMessage']}")

                if field_name != "initiateOpenPayment":
                    logger.info(
                        "GraphQL mutation '%s' used for STK push fallback",
                        field_name,
                    )
                return result
            except Exception as exc:
                last_error = exc

    if last_error:
        raise last_error
    raise Exception("GraphQL Error: Unknown issue initiating STK push")

# --- Unified Payment Initiator ---
async def initiate_stk_push(
    phone_number: str,
    amount: float,
    reference: str,
    user_id: Optional[int] = None,
    mac_address: Optional[str] = None,
    use_microservice: bool = False,
    shortcode: Optional[str] = None,
    passkey: Optional[str] = None,
    consumer_key: Optional[str] = None,
    consumer_secret: Optional[str] = None,
    callback_url: Optional[str] = None,
    account_reference: Optional[str] = None,
):
    """
    Unified STK Push payment initiator.
    Uses the provided shortcode (user's paybill) if given,
    falls back to system default on failure.
    Accepts optional per-reseller credentials for direct collection.
    """
    require_external_side_effects_enabled("M-Pesa STK push")

    if shortcode and shortcode != settings.MPESA_SHORTCODE:
        try:
            return await initiate_stk_push_direct(
                phone_number=phone_number,
                amount=amount,
                reference=reference,
                shortcode=shortcode,
                passkey=passkey,
                consumer_key=consumer_key,
                consumer_secret=consumer_secret,
                callback_url=callback_url,
                account_reference=account_reference,
            )
        except Exception as e:
            logger.warning(f"STK Push with user shortcode {shortcode} failed: {e}. Falling back to default.")

    return await initiate_stk_push_direct(
        phone_number=phone_number,
        amount=amount,
        reference=reference,
        account_reference=account_reference,
    )


async def query_stk_push_status(checkout_request_id: str, access_token: str | None = None) -> dict:
    """
    Query Safaricom's STK Push Query API for the final status of a transaction.
    Returns a dict with keys: result_code (int), result_desc (str).
    Raises on network/auth errors so the caller can retry later.
    Pass *access_token* to reuse a token across a batch of queries.
    """
    require_external_side_effects_enabled("M-Pesa STK status query")

    if access_token is None:
        access_token = await get_access_token()
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    shortcode = settings.MPESA_SHORTCODE
    password = base64.b64encode(
        f"{shortcode}{settings.MPESA_PASSKEY}{timestamp}".encode()
    ).decode()

    base_url = (
        "https://api.safaricom.co.ke"
        if settings.MPESA_ENVIRONMENT == "production"
        else "https://sandbox.safaricom.co.ke"
    )

    payload = {
        "BusinessShortCode": shortcode,
        "Password": password,
        "Timestamp": timestamp,
        "CheckoutRequestID": checkout_request_id,
    }

    async with httpx.AsyncClient(timeout=SAFARICOM_TIMEOUT) as client:
        response = await client.post(
            f"{base_url}/mpesa/stkpushquery/v1/query",
            json=payload,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()
        data = response.json()
        logger.info(f"STK Query result for {checkout_request_id}: {data}")

    return {
        "result_code": int(data.get("ResultCode", -1)),
        "result_desc": data.get("ResultDesc", ""),
    }
