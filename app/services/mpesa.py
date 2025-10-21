import base64
from datetime import datetime
from typing import Optional
import logging

import httpx
from fastapi import HTTPException

logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
MPESA_SHORTCODE = "174379"
MPESA_PASSKEY = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919"
MPESA_CALLBACK_URL = "https://your-ngrok-subdomain.ngrok.io/api/mpesa/callback"
BASE64_ENCODED_CREDENTIALS = "dko5RmppdVBPZUFDaE5sRkdBN2c5a1lzeXZ2SVZOSk9RamliZTNaTEhnM1c0R1JUOk1CVGNWZFQ4TnRoRExwM1BjMjhScFlaR0prR2NKOXg0c3Bob3k1aGZDQkpEa0hubm1NQVFqRUlZbGJVdDhzb24="

# --- Direct M-Pesa logic (for legacy/backup use) ---
class StkPushResponse:
    def __init__(self, checkout_request_id: str, merchant_request_id: str):
        self.checkout_request_id = checkout_request_id
        self.merchant_request_id = merchant_request_id

async def get_access_token() -> str:
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
                headers={"Authorization": f"Basic {BASE64_ENCODED_CREDENTIALS}"}
            )
            response.raise_for_status()
            return response.json()["access_token"]
    except Exception as e:
        logger.error(f"Failed to get M-Pesa access token: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get M-Pesa access token: {str(e)}")

async def initiate_stk_push_direct(phone_number: str, amount: float, reference: str) -> Optional[StkPushResponse]:
    try:
        access_token = await get_access_token()
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        password = base64.b64encode(f"{MPESA_SHORTCODE}{MPESA_PASSKEY}{timestamp}".encode()).decode()
        
        payload = {
            "BusinessShortCode": MPESA_SHORTCODE,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": int(amount),
            "PartyA": phone_number,
            "PartyB": MPESA_SHORTCODE,
            "PhoneNumber": phone_number,
            "CallBackURL": MPESA_CALLBACK_URL,
            "AccountReference": reference,
            "TransactionDesc": "Payment via STK Push"
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
                json=payload,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                }
            )
            response.raise_for_status()
            result = response.json()
            logger.info(f"STK Push initiated: {result}")
            return StkPushResponse(
                checkout_request_id=result["CheckoutRequestID"],
                merchant_request_id=result["MerchantRequestID"]
            )
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
    Calls the initiateOpenPayment GraphQL mutation on the payment microservice.
    """
    mutation = """
    mutation initiateOpenPayment($merchantId: Int!, $amount: Float!, $phoneNumber: String!, $lipayTxNo: String!, $customerRef: String!) {
      initiateOpenPayment(
        merchantId: $merchantId,
        amount: $amount,
        phoneNumber: $phoneNumber,
        lipayTxNo: $lipayTxNo,
        customerRef: $customerRef
      ) {
        checkoutRequestId
        merchantRequestId
        transactionId
        lipayTxNo
        customerRef
        errorMessage
      }
    }
    """
    variables = {
        "merchantId": merchant_id,
        "amount": amount,
        "phoneNumber": phone_number,
        "lipayTxNo": lipay_tx_no,
        "customerRef": customer_ref
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(
            graphql_url,
            json={"query": mutation, "variables": variables},
            timeout=20
        )
        response.raise_for_status()
        data = response.json()
        if "errors" in data:
            raise Exception(f"GraphQL Error: {data['errors']}")
        result = data["data"]["initiateOpenPayment"]
        if result.get("errorMessage"):
            raise Exception(f"Payment microservice error: {result['errorMessage']}")
        return result

# --- Unified Payment Initiator ---
async def initiate_stk_push(
    phone_number: str,
    amount: float,
    reference: str,
    user_id: Optional[int] = None,
    mac_address: Optional[str] = None,
    use_microservice: bool = True
):
    """
    Unified STK Push payment initiator.
    """
    if use_microservice:
        merchant_id = 100000
        lipay_tx_no = f"TXN-{user_id}" if user_id else f"TXN-{reference}"
        customer_ref = mac_address or reference
        return await initiate_stk_push_via_graphql_microservice(
            merchant_id=merchant_id,
            amount=amount,
            phone_number=phone_number,
            lipay_tx_no=lipay_tx_no,
            customer_ref=customer_ref
        )
    else:
        return await initiate_stk_push_direct(
            phone_number=phone_number,
            amount=amount,
            reference=reference
        )
