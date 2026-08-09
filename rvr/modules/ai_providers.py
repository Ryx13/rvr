"""
RVR — AI provider abstraction
Lets the AI analysis phase talk to Gemini, Claude, or OpenAI interchangeably.
Provider selection: explicit `AI_PROVIDER` env var, or auto-detect based on
whichever API key is set (checked in the order below).
"""

import os
from typing import Optional

from rvr.utils.console import log_error


class AIProvider:
    name = "base"
    env_var = ""
    default_model = ""

    def __init__(self, api_key: str, model: Optional[str] = None):
        self.api_key = api_key
        self.model = model or self.default_model

    def query(self, prompt: str) -> Optional[str]:
        raise NotImplementedError


class GeminiProvider(AIProvider):
    name = "gemini"
    env_var = "GEMINI_API_KEY"
    default_model = "gemini-2.0-flash"

    def query(self, prompt: str) -> Optional[str]:
        try:
            from google import genai

            client = genai.Client(api_key=self.api_key)
            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
            )
            return response.text
        except ImportError:
            log_error("google-genai not installed. Run: pip install google-genai")
            return None
        except Exception as e:
            log_error(f"Gemini API error: {e}")
            return None


class ClaudeProvider(AIProvider):
    name = "claude"
    env_var = "ANTHROPIC_API_KEY"
    default_model = "claude-sonnet-5"

    def query(self, prompt: str) -> Optional[str]:
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key)
            response = client.messages.create(
                model=self.model,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}],
            )
            return "".join(
                block.text for block in response.content if getattr(block, "type", "") == "text"
            )
        except ImportError:
            log_error("anthropic not installed. Run: pip install anthropic")
            return None
        except Exception as e:
            log_error(f"Claude API error: {e}")
            return None


class OpenAIProvider(AIProvider):
    name = "openai"
    env_var = "OPENAI_API_KEY"
    default_model = "gpt-4o"
    base_url: Optional[str] = None  # None = OpenAI's default endpoint

    def query(self, prompt: str) -> Optional[str]:
        try:
            from openai import OpenAI

            client = OpenAI(api_key=self.api_key, base_url=self.base_url)
            response = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
            )
            return response.choices[0].message.content
        except ImportError:
            log_error("openai not installed. Run: pip install openai")
            return None
        except Exception as e:
            log_error(f"{self.name} API error: {e}")
            return None


class GroqProvider(OpenAIProvider):
    """Groq — free tier, no credit card, OpenAI-compatible endpoint.
    Get a key at https://console.groq.com/keys
    """
    name = "groq"
    env_var = "GROQ_API_KEY"
    default_model = "llama-3.3-70b-versatile"
    base_url = "https://api.groq.com/openai/v1"


# Checked in this order when AI_PROVIDER=auto (or unset)
PROVIDERS = [GeminiProvider, GroqProvider, ClaudeProvider, OpenAIProvider]


def get_provider() -> Optional[AIProvider]:
    """Resolve which AI provider to use based on AI_PROVIDER env var / available keys."""
    requested = os.getenv("AI_PROVIDER", "auto").strip().lower()
    model_override = os.getenv("AI_MODEL")

    if requested != "auto":
        for cls in PROVIDERS:
            if cls.name == requested:
                key = os.getenv(cls.env_var)
                if not key:
                    log_error(f"AI_PROVIDER={requested} but {cls.env_var} is not set")
                    return None
                return cls(api_key=key, model=model_override)
        log_error(f"Unknown AI_PROVIDER: {requested}")
        return None

    for cls in PROVIDERS:
        key = os.getenv(cls.env_var)
        if key:
            return cls(api_key=key, model=model_override)

    return None