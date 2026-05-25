"""Shared LLM client for GhostTrace agents.

Uses Groq (free cloud API) by default. Groq provides extremely fast inference
on Llama 3.1 70B with a generous free tier (30 req/min, 14,400 req/day).

Supported providers:
    - groq (default): Free cloud API, no credit card needed
    - ollama: Free local inference (needs beefy hardware)
    - anthropic: Paid Claude API

Setup for Groq (recommended):
    1. Sign up at https://console.groq.com (free, no credit card)
    2. Create an API key
    3. export GROQ_API_KEY=your_key_here
    4. That's it — run the backend
"""

import os
from openai import OpenAI, AsyncOpenAI


# Configuration via environment variables
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "groq")  # "groq", "ollama", or "anthropic"
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_BASE_URL = "https://api.groq.com/openai/v1"

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")


def get_llm_client() -> OpenAI:
    """Get a synchronous LLM client.

    Returns an OpenAI-compatible client configured for the selected provider.
    Default is Groq (free, fast cloud inference).

    Returns:
        OpenAI client instance.
    """
    if LLM_PROVIDER == "groq":
        return OpenAI(
            base_url=GROQ_BASE_URL,
            api_key=GROQ_API_KEY,
        )

    if LLM_PROVIDER == "anthropic":
        return OpenAI(
            base_url="https://api.anthropic.com/v1/",
            api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        )

    # Ollama (free, local)
    return OpenAI(
        base_url=OLLAMA_BASE_URL,
        api_key="ollama",
    )


def get_async_llm_client() -> AsyncOpenAI:
    """Get an async LLM client.

    Returns an async OpenAI-compatible client configured for the selected provider.
    Default is Groq (free, fast cloud inference).

    Returns:
        AsyncOpenAI client instance.
    """
    if LLM_PROVIDER == "groq":
        return AsyncOpenAI(
            base_url=GROQ_BASE_URL,
            api_key=GROQ_API_KEY,
        )

    if LLM_PROVIDER == "anthropic":
        return AsyncOpenAI(
            base_url="https://api.anthropic.com/v1/",
            api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        )

    # Ollama (free, local)
    return AsyncOpenAI(
        base_url=OLLAMA_BASE_URL,
        api_key="ollama",
    )


def get_model_name() -> str:
    """Get the model name to use for LLM calls.

    Returns:
        Model identifier string for the configured provider.
    """
    if LLM_PROVIDER == "groq":
        return GROQ_MODEL
    if LLM_PROVIDER == "anthropic":
        return "claude-sonnet-4-20250514"
    return OLLAMA_MODEL


def call_llm(system_prompt: str, user_message: str, max_tokens: int = 2000) -> str:
    """Make a synchronous LLM call and return the response text.

    Args:
        system_prompt: The system prompt defining agent behavior.
        user_message: The user message with context/evidence.
        max_tokens: Maximum tokens in the response.

    Returns:
        The raw text response from the LLM.

    Raises:
        Exception: If the LLM call fails for any reason.
    """
    client = get_llm_client()
    model = get_model_name()

    response = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        temperature=0.3,
    )

    return response.choices[0].message.content


async def acall_llm(system_prompt: str, user_message: str, max_tokens: int = 2000) -> str:
    """Make an async LLM call and return the response text.

    Args:
        system_prompt: The system prompt defining agent behavior.
        user_message: The user message with context/evidence.
        max_tokens: Maximum tokens in the response.

    Returns:
        The raw text response from the LLM.

    Raises:
        Exception: If the LLM call fails for any reason.
    """
    client = get_async_llm_client()
    model = get_model_name()

    response = await client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        temperature=0.3,
    )

    return response.choices[0].message.content
