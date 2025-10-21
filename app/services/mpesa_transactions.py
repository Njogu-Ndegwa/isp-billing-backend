from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from app.db.models import MpesaTransaction, MpesaTransactionStatus
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

async def save_mpesa_transaction(
    db: AsyncSession, 
    checkout_request_id: str, 
    phone_number: str, 
    amount: float, 
    reference: str,
    merchant_request_id: str = None
) -> MpesaTransaction:
    """
    Save a new M-Pesa transaction to the database.
    """
    try:
        transaction = MpesaTransaction(
            checkout_request_id=checkout_request_id,
            phone_number=phone_number,
            amount=amount,
            reference=reference,
            merchant_request_id=merchant_request_id,
            status=MpesaTransactionStatus.PENDING,  # Use uppercase enum
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(transaction)
        await db.commit()
        await db.refresh(transaction)
        logger.info(f"Saved M-Pesa transaction: {checkout_request_id}")
        return transaction
    except IntegrityError as e:
        await db.rollback()
        logger.error(f"Failed to save M-Pesa transaction: {str(e)}")
        raise ValueError(f"Transaction with checkout_request_id {checkout_request_id} already exists")
    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error saving M-Pesa transaction: {str(e)}")
        raise

async def get_mpesa_transaction_by_checkout_id(
    db: AsyncSession, 
    checkout_request_id: str
) -> Optional[MpesaTransaction]:
    """
    Retrieve an M-Pesa transaction by checkout_request_id.
    """
    try:
        stmt = select(MpesaTransaction).where(MpesaTransaction.checkout_request_id == checkout_request_id)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    except Exception as e:
        logger.error(f"Error retrieving M-Pesa transaction {checkout_request_id}: {str(e)}")
        raise

async def update_mpesa_transaction_status(
    db: AsyncSession, 
    checkout_request_id: str, 
    status: MpesaTransactionStatus, 
    receipt_number: str = None,
    result_code: str = None,
    result_desc: str = None
) -> bool:
    """
    Update the status of an M-Pesa transaction.
    
    Args:
        db: Database session
        checkout_request_id: The checkout request ID
        status: New status of the transaction
        receipt_number: M-Pesa receipt number (for successful transactions)
        result_code: Result code from M-Pesa callback
        result_desc: Result description from M-Pesa callback
    """
    try:
        values = {
            "status": status,
            "updated_at": datetime.utcnow()
        }
        
        if receipt_number:
            values["mpesa_receipt_number"] = receipt_number
            values["transaction_date"] = datetime.utcnow()
            
        if result_code:
            values["result_code"] = result_code
            
        if result_desc:
            values["result_desc"] = result_desc

        stmt = update(MpesaTransaction).where(
            MpesaTransaction.checkout_request_id == checkout_request_id
        ).values(**values)
        
        result = await db.execute(stmt)
        await db.commit()
        
        if result.rowcount == 0:
            logger.warning(f"No transaction found with checkout_request_id {checkout_request_id}")
            return False
            
        logger.info(f"Updated M-Pesa transaction status: {checkout_request_id} to {status.value}")
        return True
    except Exception as e:
        await db.rollback()
        logger.error(f"Error updating M-Pesa transaction status {checkout_request_id}: {str(e)}")
        raise

async def get_pending_mpesa_transactions(
    db: AsyncSession
) -> List[MpesaTransaction]:
    """
    Retrieve all pending M-Pesa transactions.
    """
    try:
        stmt = select(MpesaTransaction).where(MpesaTransaction.status == MpesaTransactionStatus.PENDING)
        result = await db.execute(stmt)
        return result.scalars().all()
    except Exception as e:
        logger.error(f"Error retrieving pending M-Pesa transactions: {str(e)}")
        raise

async def link_transaction_to_customer(
    db: AsyncSession, 
    checkout_request_id: str, 
    customer_id: int
) -> bool:
    """
    Link an M-Pesa transaction to a customer.
    """
    try:
        stmt = update(MpesaTransaction).where(
            MpesaTransaction.checkout_request_id == checkout_request_id
        ).values(
            customer_id=customer_id,
            updated_at=datetime.utcnow()
        )
        result = await db.execute(stmt)
        await db.commit()
        
        if result.rowcount == 0:
            logger.warning(f"No transaction found with checkout_request_id {checkout_request_id}")
            return False
            
        logger.info(f"Linked M-Pesa transaction {checkout_request_id} to customer {customer_id}")
        return True
    except Exception as e:
        await db.rollback()
        logger.error(f"Error linking M-Pesa transaction {checkout_request_id} to customer {customer_id}: {str(e)}")
        raise

async def mark_transaction_as_expired(
    db: AsyncSession, 
    checkout_request_id: str
) -> bool:
    """
    Mark a transaction as expired (for timeout scenarios).
    """
    return await update_mpesa_transaction_status(
        db=db,
        checkout_request_id=checkout_request_id,
        status=MpesaTransactionStatus.EXPIRED,
        result_code="TIMEOUT",
        result_desc="Transaction expired due to timeout"
    )

async def get_transaction_by_receipt_number(
    db: AsyncSession,
    receipt_number: str
) -> Optional[MpesaTransaction]:
    """
    Retrieve a transaction by M-Pesa receipt number.
    """
    try:
        stmt = select(MpesaTransaction).where(MpesaTransaction.mpesa_receipt_number == receipt_number)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    except Exception as e:
        logger.error(f"Error retrieving transaction by receipt number {receipt_number}: {str(e)}")
        raise