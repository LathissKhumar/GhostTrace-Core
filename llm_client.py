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

from openai import OpenAI, AsyncOpenAI

from config import settings

LLM_PROVIDER = settings.llm_provider
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1/"


def get_llm_client() -> OpenAI:
    """Get a synchronous LLM client for the configured provider."""
    if LLM_PROVIDER == "groq":
        return OpenAI(
            base_url=GROQ_BASE_URL,
            api_key=settings.groq_api_key,
        )

    if LLM_PROVIDER == "anthropic":
        return OpenAI(
            base_url=ANTHROPIC_BASE_URL,
            api_key=settings.anthropic_api_key,
        )

    return OpenAI(
        base_url=settings.ollama_base_url,
        api_key="ollama",
    )


def get_async_llm_client() -> AsyncOpenAI:
    """Get an async LLM client for the configured provider."""
    if LLM_PROVIDER == "groq":
        return AsyncOpenAI(
            base_url=GROQ_BASE_URL,
            api_key=settings.groq_api_key,
        )

    if LLM_PROVIDER == "anthropic":
        return AsyncOpenAI(
            base_url=ANTHROPIC_BASE_URL,
            api_key=settings.anthropic_api_key,
        )

    return AsyncOpenAI(
        base_url=settings.ollama_base_url,
        api_key="ollama",
    )


def get_model_name() -> str:
    """Get the model name for the configured provider."""
    if LLM_PROVIDER == "groq":
        return settings.groq_model
    if LLM_PROVIDER == "anthropic":
        return "claude-sonnet-4-20250514"
    return settings.ollama_model


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
