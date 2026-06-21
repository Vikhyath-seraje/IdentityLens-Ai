import os
import time
import google.generativeai as genai
from pathlib import Path
from dotenv import load_dotenv

# Always load .env from the project root, regardless of working directory
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

class AIEngine:
    def __init__(self):
        # Configure Gemini API
        api_key = os.getenv("GEMINI_API_KEY")
        self.model = None
        self._last_error = None
        if api_key:
            try:
                genai.configure(api_key=api_key)
                # Use gemini-2.5-flash: fast, capable, and widely available.
                self.model = genai.GenerativeModel('gemini-2.5-flash')
            except Exception as e:
                self._last_error = f"Failed to initialise Gemini: {e}"

    def _generate_with_retry(self, prompt, max_retries=3):
        """Call the model with exponential-backoff retries for transient errors."""
        last_err = None
        for attempt in range(max_retries):
            try:
                # request_options gives the underlying HTTP call more headroom
                resp = self.model.generate_content(
                    prompt,
                    request_options={"timeout": 90},
                )
                # Some responses come back blocked/empty — surface that clearly
                text = getattr(resp, "text", None)
                if text:
                    return text, None
                # Empty/blocked response — try to read the reason
                feedback = getattr(resp, "prompt_feedback", None)
                reason = getattr(feedback, "block_reason", None) if feedback else None
                return None, (f"Empty response from Gemini"
                              + (f" (blocked: {reason})" if reason else ""))
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
                # 429 / 503 are transient — back off and retry
                msg = str(e).lower()
                if "429" in msg or "503" in msg or "quota" in msg or "rate" in msg or "deadline" in msg or "timeout" in msg:
                    time.sleep(1.5 * (attempt + 1))  # 1.5s, 3s, 4.5s
                    continue
                # Non-transient error — don't retry
                break
        return None, last_err

    def get_remediation(self, anomaly_description, identity_context):
        """
        Generates AI-powered remediation recommendations using Gemini.
        Returns a markdown string. On failure, returns a helpful message
        that still lets the analyst proceed.
        """
        if not self.model:
            base = "AI API key not configured. Please set GEMINI_API_KEY in the .env file."
            if self._last_error:
                base += f"\n\nDetails: {self._last_error}"
            return base

        prompt = f"""
        You are an expert cybersecurity analyst. An anomaly has been detected in the enterprise identity management system.

        Identity Context: {identity_context}
        Anomaly Description: {anomaly_description}

        Please provide a concise, actionable remediation plan to address this risk.
        Structure your response with:
        1. Immediate Action
        2. Root Cause Investigation
        3. Preventative Measures
        """

        text, err = self._generate_with_retry(prompt)
        if text:
            return text
        # All retries failed — give the analyst context, not a dead end
        return ("> ⚠️ **Gemini AI is temporarily unavailable.**\n\n"
                f"The AI Copilot could not reach Gemini just now (`{err}`).\n\n"
                "This is usually transient (rate limit or network blip). "
                "Please try again in a moment. Meanwhile, here is a standard "
                "checklist for this anomaly type:\n\n"
                "1. **Immediate Action** — verify the account status and disable "
                "if the risk is confirmed.\n"
                "2. **Root Cause Investigation** — review recent access logs and "
                "privilege changes.\n"
                "3. **Preventative Measures** — tighten access reviews and "
                "monitoring for this identity class.\n")

if __name__ == "__main__":
    engine = AIEngine()
    result = engine.get_remediation(
        anomaly_description="User terminated on 2023-10-15 but has active AD and AWS accounts.",
        identity_context="Identity ID: ID-1045, Name: John Doe, Department: Engineering, Type: Employee"
    )
    print(result)

