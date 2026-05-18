#!/usr/bin/env python3
"""
AAIP v2.0 FastAPI Example

JWT-based delegation with UCAN-style delegation chains.
Uses Authorization: Bearer header and JWKS endpoint for key resolution.
"""

from typing import Any, Optional

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from aaip import (
    AAIPError,
    Delegation,
    StaticKeyResolver,
    check_delegation_authorization,
    create_jwks,
    create_signed_delegation,
    generate_keypair,
    public_key_to_jwk,
    validate_constraints,
    verify_delegation,
)

app = FastAPI(
    title="AAIP v2.0 FastAPI Integration",
    description="AI Agent Authorization with JWT-based AAIP delegations",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CreateDelegationRequest(BaseModel):
    agent_identity: str
    scope: list[str]
    constraints: Optional[dict[str, Any]] = None
    expires_at: str = "2027-08-26T10:00:00Z"
    not_before: str = "2025-07-26T10:00:00Z"


class PaymentRequest(BaseModel):
    amount: float
    currency: str = "USD"
    merchant: str


class CalendarEventRequest(BaseModel):
    title: str
    start_time: str
    duration_hours: float
    attendees: Optional[list[str]] = None


# Demo keypair (in production, use proper key management)
private_key, public_key, kid = generate_keypair()
jwk = public_key_to_jwk(public_key, kid)
key_resolver = StaticKeyResolver({kid: public_key})


def get_delegation(authorization: Optional[str] = Header(None)) -> Delegation:
    """Extract and verify delegation JWT from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid Authorization header. Expected: Bearer <jwt>",
        )

    token = authorization[7:]

    try:
        return verify_delegation(token, key_resolver)
    except AAIPError as e:
        raise HTTPException(status_code=401, detail=str(e)) from e


def require_scope(required_scope: str):
    """Dependency factory for requiring specific scopes."""

    def dependency(delegation: Delegation = Depends(get_delegation)):
        resource, action = required_scope.split(":", 1)
        if not check_delegation_authorization(delegation, resource, action):
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient scope: requires {required_scope}",
            )
        return delegation

    return dependency


@app.get("/.well-known/jwks.json")
async def jwks_endpoint():
    """JWKS endpoint for delegation verification."""
    return create_jwks([jwk])


@app.post("/delegations")
async def create_delegation(request: CreateDelegationRequest):
    """Create a new AAIP JWT delegation."""
    try:
        token = create_signed_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            private_key=private_key,
            kid=kid,
            subject_identity=request.agent_identity,
            subject_identity_system="custom",
            scope=request.scope,
            expires_at=request.expires_at,
            not_before=request.not_before,
            constraints=request.constraints or {},
        )

        return {
            "token": token,
            "usage_instructions": {
                "header": "Authorization",
                "value": f"Bearer {token}",
            },
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/payment")
async def process_payment(
    payment: PaymentRequest,
    delegation: Delegation = Depends(require_scope("payments:authorize")),
):
    """Process a payment with AAIP authorization."""
    try:
        request_data = {
            "amount": payment.amount,
            "currency": payment.currency,
            "domain": payment.merchant,
        }

        try:
            validate_constraints(delegation.constraints, request_data)
        except AAIPError as e:
            raise HTTPException(
                status_code=403,
                detail={"error": "Constraint violation", "details": str(e)},
            ) from e

        transaction_id = f"txn_{payment.amount}_{payment.merchant}_{delegation.jti[:8]}"

        return {
            "status": "success",
            "transaction_id": transaction_id,
            "amount": payment.amount,
            "currency": payment.currency,
            "merchant": payment.merchant,
            "message": "Payment processed successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/calendar")
async def create_calendar_event(
    event: CalendarEventRequest,
    delegation: Delegation = Depends(require_scope("calendar:write")),
):
    """Create a calendar event with AAIP authorization."""
    try:
        if delegation.constraints:
            request_data = {
                "start_time": event.start_time,
                "duration": event.duration_hours,
                "attendee_count": len(event.attendees or []),
            }

            try:
                validate_constraints(delegation.constraints, request_data)
            except AAIPError as e:
                raise HTTPException(
                    status_code=403,
                    detail={"error": "Constraint violation", "details": str(e)},
                ) from e

        event_id = f"evt_{event.title.replace(' ', '_')}_{delegation.jti[:8]}"

        return {
            "status": "success",
            "event_id": event_id,
            "title": event.title,
            "start_time": event.start_time,
            "duration_hours": event.duration_hours,
            "attendees": event.attendees,
            "message": "Calendar event created successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "aaip_version": "2.0",
        "supported_scopes": ["payments:authorize", "calendar:write"],
        "jwks_uri": "/.well-known/jwks.json",
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
