#!/usr/bin/env python3
"""
AAIP FastAPI Basic Example

This example demonstrates basic AAIP integration with FastAPI.
Shows delegation creation, verification, and authorization checking.
"""

import json
import base64
from typing import Dict, Any, Optional, List

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# AAIP imports
from aaip import (
    verify_delegation,
    generate_keypair,
    create_signed_delegation,
    check_delegation_authorization,
    validate_constraints,
    Delegation
)

app = FastAPI(
    title="AAIP FastAPI Integration",
    description="AI Agent Authorization with AAIP",
    version="1.0.0"
)

# CORS middleware for web frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request/Response Models
class CreateDelegationRequest(BaseModel):
    agent_identity: str
    scope: List[str]
    constraints: Optional[Dict[str, Any]] = None
    expires_at: str = "2025-08-26T10:00:00Z"
    not_before: str = "2025-07-26T10:00:00Z"

class PaymentRequest(BaseModel):
    amount: float
    currency: str = "USD"
    merchant: str

class CalendarEventRequest(BaseModel):
    title: str
    start_time: str
    duration_hours: float
    attendees: Optional[List[str]] = None

# Global keypair for demo (in production, use proper key management)
private_key, public_key = generate_keypair()

def get_delegation_from_header(x_aaip_delegation: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Extract and verify delegation from header."""
    if not x_aaip_delegation:
        raise HTTPException(
            status_code=401,
            detail="Missing X-AAIP-Delegation header"
        )
    
    try:
        # Decode base64 delegation
        delegation_json = base64.b64decode(x_aaip_delegation).decode('utf-8')
        delegation = json.loads(delegation_json)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid delegation format"
        )
    
    # Verify the delegation
    if not verify_delegation(delegation):
        raise HTTPException(
            status_code=401,
            detail="Invalid delegation"
        )
    
    return delegation

def require_scope(required_scope: str):
    """Decorator factory for requiring specific scopes."""
    def dependency(delegation: Dict[str, Any] = Depends(get_delegation_from_header)):
        delegation_obj = Delegation.from_dict(delegation)
        resource, action = required_scope.split(":", 1)
        if not check_delegation_authorization(delegation_obj, resource, action):
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient scope: requires {required_scope}"
            )
        return delegation
    return dependency

@app.post("/delegations")
async def create_delegation(request: CreateDelegationRequest):
    """Create a new AAIP delegation."""
    try:
        delegation = create_signed_delegation(
            issuer_identity="user@example.com",  # Would come from auth
            issuer_identity_system="oauth",
            issuer_private_key=private_key,
            subject_identity=request.agent_identity,
            subject_identity_system="custom",
            scope=request.scope,
            expires_at=request.expires_at,
            not_before=request.not_before,
            constraints=request.constraints or {}
        )
        
        return {
            "delegation": delegation,
            "usage_instructions": {
                "header": "X-AAIP-Delegation",
                "value": "Base64 encode this delegation JSON"
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/payment")
async def process_payment(
    payment: PaymentRequest,
    delegation: Dict[str, Any] = Depends(require_scope("payments:authorize"))
):
    """Process a payment with AAIP authorization."""
    try:
        # Validate constraints
        request_data = {
            "amount": payment.amount,
            "currency": payment.currency,
            "domain": payment.merchant  # Use domain for domain constraints
        }
        
        try:
            validate_constraints(delegation["delegation"]["constraints"], request_data)
        except Exception as e:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Constraint violation",
                    "details": {"error": str(e)}
                }
            )
        
        # Simulate payment processing
        transaction_id = f"txn_{payment.amount}_{payment.merchant}_{delegation['delegation']['id'][:8]}"
        
        return {
            "status": "success",
            "transaction_id": transaction_id,
            "amount": payment.amount,
            "currency": payment.currency,
            "merchant": payment.merchant,
            "message": "Payment processed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/calendar")
async def create_calendar_event(
    event: CalendarEventRequest,
    delegation: Dict[str, Any] = Depends(require_scope("calendar:write"))
):
    """Create a calendar event with AAIP authorization."""
    try:
        # Validate constraints if they exist
        if delegation["delegation"].get("constraints"):
            request_data = {
                "start_time": event.start_time,
                "duration": event.duration_hours,
                "attendee_count": len(event.attendees or [])
            }
            
            try:
                validate_constraints(delegation["delegation"]["constraints"], request_data)
            except Exception as e:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "Constraint violation", 
                        "details": {"error": str(e)}
                    }
                )
        
        # Simulate calendar event creation
        event_id = f"evt_{event.title.replace(' ', '_')}_{delegation['delegation']['id'][:8]}"
        
        return {
            "status": "success",
            "event_id": event_id,
            "title": event.title,
            "start_time": event.start_time,
            "duration_hours": event.duration_hours,
            "attendees": event.attendees,
            "message": "Calendar event created successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "aaip_version": "1.0",
        "supported_scopes": ["payments:authorize", "calendar:write"],
        "public_key": public_key
    }

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return {"error": "Not found", "path": str(request.url.path)}

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    return {"error": "Internal server error"}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )