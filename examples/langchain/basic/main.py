#!/usr/bin/env python3
"""
AAIP v2.0 LangChain Example

Demonstrates JWT-based AAIP delegation with LangChain agents.
Features delegation chains, constraint enforcement, and audit logging.
"""

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.tools import Tool
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI

from aaip import (
    AAIPError,
    AAIPErrorCode,
    AuthorizationError,
    Delegation,
    StaticKeyResolver,
    check_delegation_authorization,
    create_signed_delegation,
    generate_keypair,
    verify_delegation,
)


class AAIPLangChainAgent:
    """LangChain agent with AAIP JWT authorization."""

    def __init__(
        self,
        agent_identity: str,
        agent_identity_system: str = "custom",
        llm_model: str = "gpt-3.5-turbo",
    ):
        self.agent_identity = agent_identity
        self.agent_identity_system = agent_identity_system
        self.current_delegation: Optional[Delegation] = None
        self._key_resolver: Optional[StaticKeyResolver] = None

        if not os.getenv("OPENAI_API_KEY"):
            print("\033[93mWarning: OPENAI_API_KEY not set. Using mock LLM.\033[0m")
            self.llm = self._create_mock_llm()
        else:
            self.llm = ChatOpenAI(model=llm_model, temperature=0)

        self.tools = self._create_authorized_tools()
        self.agent = self._create_agent()
        self.agent_executor = AgentExecutor(
            agent=self.agent,
            tools=self.tools,
            verbose=True,
            handle_parsing_errors=True,
        )

        print("\033[92mAAIP LangChain Agent initialized\033[0m")
        print(f"   Agent Identity: {self.agent_identity}")

    def set_key_resolver(self, resolver: StaticKeyResolver) -> None:
        self._key_resolver = resolver

    def _create_mock_llm(self):
        class MockLLM:
            def invoke(self, messages):
                from langchain_core.messages import AIMessage

                return AIMessage(content="I understand. Let me help you with that.")

            def bind_functions(self, functions):
                return self

        return MockLLM()

    def _create_authorized_tools(self) -> list[Tool]:
        def book_flight_wrapper(input_str: str) -> str:
            try:
                params = self._parse_tool_input(input_str)
                self._check_tool_authorization("travel:book_flight", params)
                result = f"Flight booked to {params.get('destination', 'Unknown')} for {params.get('currency', 'USD')} {float(params.get('amount', 0)):.2f}"
                print(f"[AUDIT] Tool executed: book_flight by {self.agent_identity}")
                return result
            except AAIPError as e:
                print(f"[AUDIT] Authorization denied: book_flight - {e}")
                return f"Authorization denied: {e}"

        def send_email_wrapper(input_str: str) -> str:
            try:
                params = self._parse_tool_input(input_str)
                self._check_tool_authorization("communication:send_email", params)
                result = f"Email sent to {params.get('recipient', 'unknown')} with subject: {params.get('subject', 'No subject')}"
                print(f"[AUDIT] Tool executed: send_email by {self.agent_identity}")
                return result
            except AAIPError as e:
                print(f"[AUDIT] Authorization denied: send_email - {e}")
                return f"Authorization denied: {e}"

        def make_payment_wrapper(input_str: str) -> str:
            try:
                params = self._parse_tool_input(input_str)
                self._check_tool_authorization("payments:charge", params)
                result = f"Payment of {params.get('currency', 'USD')} {float(params.get('amount', 0)):.2f} sent to {params.get('recipient', 'Unknown')}"
                print(f"[AUDIT] Tool executed: make_payment by {self.agent_identity}")
                return result
            except AAIPError as e:
                print(f"[AUDIT] Authorization denied: make_payment - {e}")
                return f"Authorization denied: {e}"

        return [
            Tool(
                name="book_flight",
                description="Book a flight.",
                func=book_flight_wrapper,
            ),
            Tool(
                name="send_email", description="Send an email.", func=send_email_wrapper
            ),
            Tool(
                name="make_payment",
                description="Process a payment.",
                func=make_payment_wrapper,
            ),
        ]

    def _create_agent(self):
        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You are a helpful AI assistant with AAIP delegation-based authorization.",
                ),
                MessagesPlaceholder("chat_history", optional=True),
                ("human", "{input}"),
                MessagesPlaceholder("agent_scratchpad"),
            ]
        )
        return create_openai_functions_agent(self.llm, self.tools, prompt)

    def set_delegation(self, token: str) -> bool:
        """Set the current delegation from a JWT string."""
        try:
            if self._key_resolver is None:
                raise AuthorizationError(
                    AAIPErrorCode.IDENTITY_VERIFICATION_FAILED,
                    "No key resolver configured",
                )

            delegation = verify_delegation(token, self._key_resolver)

            if delegation.aud != self.agent_identity:
                print(
                    f"\033[91mDelegation is not for this agent (aud={delegation.aud})\033[0m"
                )
                return False

            self.current_delegation = delegation

            print(f"\033[92mDelegation activated for {self.agent_identity}\033[0m")
            print(f"   Delegation ID: {delegation.jti}")
            print(f"   Scope: {', '.join(delegation.scope)}")
            print(f"   Issuer: {delegation.iss}")
            return True

        except Exception as e:
            print(f"\033[91mFailed to set delegation: {e}\033[0m")
            return False

    def _check_tool_authorization(
        self, required_scope: str, params: dict[str, Any]
    ) -> None:
        if not self.current_delegation:
            raise AuthorizationError(
                AAIPErrorCode.SCOPE_INSUFFICIENT,
                "No delegation available",
            )

        resource, action = required_scope.split(":", 1)
        if not check_delegation_authorization(
            self.current_delegation, resource, action, params
        ):
            raise AuthorizationError(
                AAIPErrorCode.SCOPE_INSUFFICIENT,
                f"Permission '{required_scope}' not granted or constraints violated",
            )

    def _parse_tool_input(self, input_str: str) -> dict[str, Any]:
        try:
            return json.loads(input_str)
        except json.JSONDecodeError:
            params = {}
            for line in input_str.strip().split("\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    params[key.strip()] = value.strip()
            return params

    async def execute_task(self, task: str) -> str:
        if not self.current_delegation:
            return "No delegation available. Agent not authorized."

        try:
            result = await self.agent_executor.ainvoke(
                {"input": task, "chat_history": []}
            )
            return result.get("output", "Task completed with no output")
        except Exception as e:
            return f"Task failed: {e}"


def create_demo_delegation(
    user_identity: str,
    scope: list[str],
    constraints: Optional[dict[str, Any]] = None,
    agent_identity: str = "agent-123",
    private_key=None,
    kid: str = None,
) -> str:
    """Create a demo JWT delegation. Returns JWT string."""
    if private_key is None or kid is None:
        private_key, _, kid = generate_keypair()

    now = datetime.now(timezone.utc)
    return create_signed_delegation(
        issuer_identity=user_identity,
        issuer_identity_system="oauth",
        private_key=private_key,
        kid=kid,
        subject_identity=agent_identity,
        subject_identity_system="custom",
        scope=scope,
        expires_at=(now + timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
        not_before=now.isoformat().replace("+00:00", "Z"),
        constraints=constraints or {},
    )


async def main():
    print("AAIP v2.0 LangChain Example")
    print("=" * 50)

    private_key, public_key, kid = generate_keypair()
    resolver = StaticKeyResolver({kid: public_key})

    agent = AAIPLangChainAgent(agent_identity="travel-assistant-v1")
    agent.set_key_resolver(resolver)

    token = create_demo_delegation(
        user_identity="alice@example.com",
        scope=["travel:book_flight", "payments:charge"],
        constraints={"max_amount": {"value": 2000.0, "currency": "USD"}},
        agent_identity="travel-assistant-v1",
        private_key=private_key,
        kid=kid,
    )

    if agent.set_delegation(token):
        result = await agent.execute_task("Book a flight to Paris, budget $800")
        print(f"Result: {result}")

    print("\033[92mDemo completed!\033[0m")


if __name__ == "__main__":
    asyncio.run(main())
