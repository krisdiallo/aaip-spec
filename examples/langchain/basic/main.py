#!/usr/bin/env python3
"""
AAIP LangChain Basic Example

This example demonstrates how to integrate AAIP (AI Agent Identity Protocol) 
with LangChain agents to provide authorization and delegation capabilities.

Features demonstrated:
- Agent identity management
- User delegation creation
- Tool access control via delegations
- Constraint enforcement
- Audit logging

Requirements:
- Python 3.9+
- langchain
- aaip library
"""

import os
import json
import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

# LangChain imports
from langchain.agents import create_openai_functions_agent, AgentExecutor
from langchain.tools import Tool
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI

# AAIP imports
from aaip import (
    create_signed_delegation,
    generate_keypair,
    verify_delegation,
    check_delegation_authorization,
    Delegation,
    ValidationError,
    AuthorizationError
)


class AAIPLangChainAgent:
    """
    LangChain agent wrapper with AAIP authorization capabilities.
    
    This class wraps a standard LangChain agent and provides:
    - Delegation-based authorization for tool usage
    - Constraint enforcement before tool execution
    - Audit logging for all actions
    - Identity management integration
    """
    
    def __init__(
        self, 
        agent_identity: str,
        agent_identity_system: str = "custom",
        llm_model: str = "gpt-3.5-turbo"
    ):
        """
        Initialize the AAIP-enabled LangChain agent.
        
        Args:
            agent_identity: Unique identifier for this agent
            agent_identity_system: Identity system type (default: "custom")
            llm_model: LLM model to use for the agent
        """
        self.agent_identity = agent_identity
        self.agent_identity_system = agent_identity_system
        self.current_delegation: Optional[Dict[str, Any]] = None
        
        # Initialize LLM
        if not os.getenv("OPENAI_API_KEY"):
            print("\033[93mWarning: OPENAI_API_KEY not set. Using mock LLM for demo.\033[0m")
            self.llm = self._create_mock_llm()
        else:
            self.llm = ChatOpenAI(model=llm_model, temperature=0)
        
        # Create tools with AAIP authorization
        self.tools = self._create_authorized_tools()
        
        # Create agent
        self.agent = self._create_agent()
        self.agent_executor = AgentExecutor(
            agent=self.agent,
            tools=self.tools,
            verbose=True,
            handle_parsing_errors=True
        )
        
        print("\033[92mAAIP LangChain Agent initialized\033[0m")
        print(f"   Agent Identity: {self.agent_identity}")
        print(f"   Identity System: {self.agent_identity_system}")
    
    def _create_mock_llm(self):
        """Create a mock LLM for demo purposes when OpenAI API key is not available."""
        class MockLLM:
            def invoke(self, messages):
                # Simple mock response
                from langchain_core.messages import AIMessage
                return AIMessage(content="I understand you want to use a tool. Let me help you with that.")
            
            def bind_functions(self, functions):
                return self
        
        return MockLLM()
    
    def _create_authorized_tools(self) -> List[Tool]:
        """Create tools wrapped with AAIP authorization checks."""
        
        def book_flight_wrapper(input_str: str) -> str:
            """Book a flight with delegation authorization."""
            try:
                # Parse input (in real implementation, this would be more sophisticated)
                params = self._parse_tool_input(input_str)
                
                # Check authorization
                self._check_tool_authorization("travel:book_flight", params)
                
                # Execute the actual tool
                result = self._book_flight_impl(params)
                
                # Log successful action (simplified logging)
                print(f"[AUDIT] Tool executed: book_flight by {self.agent_identity}")
                
                return result
                
            except (AuthorizationError, ValidationError) as e:
                print(f"[AUDIT] Authorization denied: book_flight by {self.agent_identity} - {str(e)}")
                return self._color_text(f"Authorization denied: {str(e)}", "91")
            except Exception as e:
                print(f"[AUDIT] Error: book_flight by {self.agent_identity} - {str(e)}")
                return self._color_text(f"Error: {str(e)}", "91")
        
        def send_email_wrapper(input_str: str) -> str:
            """Send email with delegation authorization."""
            try:
                params = self._parse_tool_input(input_str)
                self._check_tool_authorization("communication:send_email", params)
                result = self._send_email_impl(params)
                
                print(f"[AUDIT] Tool executed: send_email by {self.agent_identity}")
                
                return result
                
            except (AuthorizationError, ValidationError) as e:
                print(f"[AUDIT] Authorization denied: send_email by {self.agent_identity} - {str(e)}")
                return self._color_text(f"Authorization denied: {str(e)}", "91")
        
        def make_payment_wrapper(input_str: str) -> str:
            """Make payment with delegation authorization."""
            try:
                params = self._parse_tool_input(input_str)
                self._check_tool_authorization("payments:charge", params)
                result = self._make_payment_impl(params)
                
                print(f"[AUDIT] Tool executed: make_payment by {self.agent_identity}")
                
                return result
                
            except (AuthorizationError, ValidationError) as e:
                print(f"[AUDIT] Authorization denied: make_payment by {self.agent_identity} - {str(e)}")
                return self._color_text(f"Authorization denied: {str(e)}", "91")
        
        return [
            Tool(
                name="book_flight",
                description="Book a flight. Input should include destination, dates, and budget.",
                func=book_flight_wrapper
            ),
            Tool(
                name="send_email",
                description="Send an email. Input should include recipient, subject, and message.",
                func=send_email_wrapper
            ),
            Tool(
                name="make_payment",
                description="Process a payment. Input should include amount, currency, and recipient.",
                func=make_payment_wrapper
            )
        ]
    
    def _create_agent(self):
        """Create the LangChain agent with proper prompt."""
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a helpful AI assistant with access to various tools.
            
You have been granted specific permissions by a user through AAIP delegations.
Always use the appropriate tools to complete tasks, respecting any constraints
that have been placed on your actions.

If a tool fails due to authorization constraints, explain this to the user
and suggest alternatives that might work within the granted permissions.
            """),
            MessagesPlaceholder("chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder("agent_scratchpad")
        ])
        
        return create_openai_functions_agent(self.llm, self.tools, prompt)
    
    def set_delegation(self, delegation: Dict[str, Any]) -> bool:
        """
        Set the current delegation for this agent.
        
        Args:
            delegation: Delegation dictionary or object
            
        Returns:
            True if delegation is valid and set successfully
        """
        try:
            # Verify the delegation
            if not verify_delegation(delegation):
                raise AuthorizationError("Invalid delegation")
            
            # Store the delegation as dict
            self.current_delegation = delegation
            
            # Check that this delegation is for this agent
            if self.current_delegation["delegation"]["subject"]["id"] != self.agent_identity:
                raise AuthorizationError("Delegation is not for this agent")
            
            print(f"[AUDIT] Delegation activated for agent {self.agent_identity}")
            
            print(f"\033[92mDelegation activated for agent {self.agent_identity}\033[0m")
            print(f"   Delegation ID: {self.current_delegation['delegation']['id']}")
            print(f"   Scope: {', '.join(self.current_delegation['delegation']['scope'])}")
            print(f"   Expires: {self.current_delegation['delegation']['expires_at']}")
            
            return True
            
        except Exception as e:
            print(f"\033[91mFailed to set delegation: {str(e)}\033[0m")
            return False
    
    def _check_tool_authorization(self, required_scope: str, params: Dict[str, Any]) -> None:
        """
        Check if the current delegation authorizes the requested tool usage.
        
        Args:
            required_scope: Required permission scope for the tool
            params: Parameters being passed to the tool
            
        Raises:
            AuthorizationError: If authorization check fails
            ConstraintError: If constraints are violated
        """
        if not self.current_delegation:
            raise AuthorizationError("No delegation available - agent not authorized")
        
        # Use the check_delegation_authorization function
        resource, action = required_scope.split(':', 1)
        if not check_delegation_authorization(
            Delegation.from_dict(self.current_delegation),
            resource,
            action,
            params
        ):
            raise AuthorizationError(f"Permission '{required_scope}' not granted or constraints violated")
        
        print(f"[AUDIT] Authorization granted: {required_scope} for {self.agent_identity}")
    
    def _parse_tool_input(self, input_str: str) -> Dict[str, Any]:
        """Parse tool input string into parameters dictionary."""
        try:
            # Try to parse as JSON first
            return json.loads(input_str)
        except json.JSONDecodeError:
            # Fallback to simple parsing for demo
            params = {}
            lines = input_str.strip().split('\n')
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    params[key.strip()] = value.strip()
            return params
    
    def _color_text(self, text: str, color_code: str) -> str:
        """Helper to wrap text in ANSI color codes."""
        return f"\033[{color_code}m{text}\033[0m"
    
    def _book_flight_impl(self, params: Dict[str, Any]) -> str:
        """Mock flight booking implementation."""
        destination = params.get('destination', 'Unknown')
        amount = float(params.get('amount', 0))
        currency = params.get('currency', 'USD')
        return self._color_text(f"Flight booked to {destination} for {currency} {amount:.2f}", "94")
    
    def _send_email_impl(self, params: Dict[str, Any]) -> str:
        """Mock email sending implementation."""
        recipient = params.get('recipient', 'unknown@example.com')
        subject = params.get('subject', 'No subject')
        return self._color_text(f"Email sent to {recipient} with subject: {subject}", "92")
    
    def _make_payment_impl(self, params: Dict[str, Any]) -> str:
        """Mock payment processing implementation."""
        amount = float(params.get('amount', 0))
        currency = params.get('currency', 'USD')
        recipient = params.get('recipient', 'Unknown')
        return self._color_text(f"Payment of {currency} {amount:.2f} sent to {recipient}", "93")
    
    async def execute_task(self, task: str) -> str:
        """
        Execute a task using the agent with AAIP authorization.
        
        Args:
            task: Natural language description of the task
            
        Returns:
            Result of the task execution
        """
        if not self.current_delegation:
            return self._color_text("No delegation available. Agent cannot execute tasks without authorization.", "91")
        
        try:
            print(f"[AUDIT] Task started: {task} by {self.agent_identity}")
            
            result = await self.agent_executor.ainvoke({
                "input": task,
                "chat_history": []
            })
            
            print(f"[AUDIT] Task completed successfully: {task} by {self.agent_identity}")
            
            return result.get("output", "Task completed with no output")
            
        except Exception as e:
            print(f"[AUDIT] Task failed: {task} by {self.agent_identity} - {str(e)}")
            return self._color_text(f"Task failed: {str(e)}", "91")


def create_demo_delegation(
    user_identity: str,
    scope: List[str],
    constraints: Optional[Dict[str, Any]] = None,
    expires_at: str = None,
    not_before: str = None,
    user_private_key: str = None,
    agent_identity: str = None
) -> Dict[str, Any]:
    """
    Create a demonstration delegation for the example.
    
    Args:
        user_identity: Identity of the user granting permissions
        scope: List of permissions to grant
        constraints: Optional constraints on the permissions
        expires_at: ISO 8601 expiration timestamp (e.g., "2025-07-25T10:00:00Z")
        not_before: ISO 8601 start timestamp (e.g., "2025-07-24T10:00:00Z")
        user_private_key: Private key for signing the delegation (auto-generated if None)
        agent_identity: Identity of the agent receiving permissions (auto-generated if None)
        
    Returns:
        Signed delegation dictionary
    """
    from datetime import datetime, timezone, timedelta
    
    # Generate keypair if not provided
    if user_private_key is None:
        user_private_key, _ = generate_keypair()
    
    # Generate agent identity if not provided
    if agent_identity is None:
        agent_identity = "agent-123"
    
    # Set default timestamps if not provided
    now = datetime.now(timezone.utc)
    if expires_at is None:
        expires_at = (now + timedelta(hours=24)).isoformat().replace('+00:00', 'Z')
    if not_before is None:
        not_before = now.isoformat().replace('+00:00', 'Z')
    
    delegation = create_signed_delegation(
        issuer_identity=user_identity,
        issuer_identity_system="oauth",
        issuer_private_key=user_private_key,
        subject_identity=agent_identity,
        subject_identity_system="custom",
        scope=scope,
        expires_at=expires_at,
        not_before=not_before,
        constraints=constraints or {}
    )
    
    print(f"[AUDIT] Delegation created: {delegation['delegation']['id']} for {agent_identity}")
    
    return delegation


async def main():
    """Main demonstration function."""
    print("AAIP LangChain Basic Example")
    print("=" * 50)

    # Generate keypair for the user
    print("Generating user keypair...")
    user_private_key, user_public_key = generate_keypair()
    user_identity = "alice@example.com"
    
    # Create agent
    print("Creating AAIP LangChain agent...")
    agent = AAIPLangChainAgent(
        agent_identity="travel-assistant-v1",
        agent_identity_system="custom"
    )
    
    # Define different scenarios
    scenarios = [
        {
            "name": "Travel Booking with Spending Limits",
            "scope": ["travel:book_flight", "payments:charge"],
            "constraints": {
                "max_amount": {"value": 2000.0, "currency": "USD"},
                "allowed_domains": ["airline.com", "travel.com"]
            },
            "task": "Book a flight to Paris for next week, budget is $800"
        },
        {
            "name": "Email Communication with Domain Restrictions",
            "scope": ["communication:send_email"],
            "constraints": {
                "allowed_domains": ["example.com", "company.com"],
                "blocked_keywords": ["spam", "urgent"]
            },
            "task": "Send an email to john@example.com about the meeting tomorrow"
        },
        {
            "name": "Payment Processing with Amount Limits",
            "scope": ["payments:charge"],
            "constraints": {
                "max_amount": {"value": 1000.0, "currency": "USD"}
            },
            "task": "Process a payment of $300 to supplier-xyz"
        }
    ]
    
    # Run scenarios
    for i, scenario in enumerate(scenarios, 1):
        print(f"\nScenario {i}: {scenario['name']}")
        print("-" * 60)
        
        # Create delegation for this scenario
        print("Creating delegation...")
        delegation = create_demo_delegation(
            user_identity=user_identity,
            scope=scenario["scope"],
            constraints=scenario["constraints"],
            agent_identity=agent.agent_identity
        )
        
        # Set delegation on agent
        if agent.set_delegation(delegation):
            # Execute the task
            print(f"Executing task: {scenario['task']}")
            result = await agent.execute_task(scenario["task"])
            print(f"Result: {result}")
        else:
            print("\033[91mFailed to set delegation\033[0m")
        
        print("\n" + "="*60)
    
    # Demonstrate constraint violation
    print("\nDemonstrating Constraint Violation")
    print("-" * 60)
    
    # Create a restrictive delegation
    restrictive_delegation = create_demo_delegation(
        user_identity=user_identity,
        scope=["travel:book_flight", "payments:charge"],
        constraints={"max_amount": {"value": 100.0, "currency": "USD"}},
        agent_identity=agent.agent_identity
    )
    
    agent.set_delegation(restrictive_delegation)
    
    # Try to book expensive flight
    expensive_task = "Book a first-class flight to Tokyo for $5000"
    print(f"Executing task that should fail: {expensive_task}")
    result = await agent.execute_task(expensive_task)
    print(f"Result: {result}")
    
    print("\033[92mDemo completed successfully!\033[0m")
    print("\nThis example demonstrated:")
    print("- Agent identity management with AAIP")
    print("- Delegation creation and verification")
    print("- Tool authorization based on delegated permissions")
    print("- Standard constraint enforcement (spending limits, domain restrictions, etc.)")
    print("- Basic audit logging")
    print("- Integration with LangChain agents")


if __name__ == "__main__":
    asyncio.run(main())