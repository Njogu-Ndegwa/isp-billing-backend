import base64
from datetime import datetime
from typing import Optional
import logging

import httpx
from fastapi import HTTPException

from app.config import settings

logger = logging.getLogger(__name__)

# --- Direct M-Pesa logic (for legacy/backup use) ---
class StkPushResponse:
    def __init__(self, checkout_request_id: str, merchant_request_id: str):
        self.checkout_request_id = checkout_request_id
        self.merchant_request_id = merchant_request_id

async def get_access_token() -> str:
    try:
        # Generate base64 encoded credentials from consumer key and secret
        credentials = f"{settings.MPESA_CONSUMER_KEY}:{settings.MPESA_CONSUMER_SECRET}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        # Determine API URL based on environment
        base_url = "https://api.safaricom.co.ke" if settings.MPESA_ENVIRONMENT == "production" else "https://sandbox.safaricom.co.ke"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{base_url}/oauth/v1/generate?grant_type=client_credentials",
                headers={"Authorization": f"Basic {encoded_credentials}"}
            )
            response.raise_for_status()
            return response.json()["access_token"]
    except Exception as e:
        logger.error(f"Failed to get M-Pesa access token: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get M-Pesa access token: {str(e)}")

async def initiate_stk_push_direct(phone_number: str, amount: float, reference: str, shortcode: Optional[str] = None) -> Optional[StkPushResponse]:
    try:
        access_token = await get_access_token()
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        active_shortcode = shortcode or settings.MPESA_SHORTCODE
        password = base64.b64encode(f"{active_shortcode}{settings.MPESA_PASSKEY}{timestamp}".encode()).decode()
        
        payload = {
            "BusinessShortCode": active_shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": int(amount),
            "PartyA": phone_number,
            "PartyB": active_shortcode,
            "PhoneNumber": phone_number,
            "CallBackURL": settings.MPESA_CALLBACK_URL,
            "AccountReference": reference,
            "TransactionDesc": "Payment via STK Push"
        }

        # Determine API URL based on environment
        base_url = "https://api.safaricom.co.ke" if settings.MPESA_ENVIRONMENT == "production" else "https://sandbox.safaricom.co.ke"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{base_url}/mpesa/stkpush/v1/processrequest",
                json=payload,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                }
            )
            
            # Log response for debugging
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
        raise HTTPException(status_code=500, detail=f"STK Push initiation failed: {error_msg}")
    except Exception as e:
        logger.error(f"STK Push initiation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"STK Push initiation failed: {str(e)}")

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

    async with httpx.AsyncClient() as client:
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
                    timeout=20
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
    shortcode: Optional[str] = None
):
    """
    Unified STK Push payment initiator.
    Uses the provided shortcode (user's paybill) if given,
    falls back to system default on failure.
    """
    if shortcode and shortcode != settings.MPESA_SHORTCODE:
        try:
            return await initiate_stk_push_direct(
                phone_number=phone_number,
                amount=amount,
                reference=reference,
                shortcode=shortcode
            )
        except Exception as e:
            logger.warning(f"STK Push with user shortcode {shortcode} failed: {e}. Falling back to default.")

    return await initiate_stk_push_direct(
        phone_number=phone_number,
        amount=amount,
        reference=reference
    )
