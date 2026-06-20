import os
import google.generativeai as genai
from pathlib import Path
from dotenv import load_dotenv

# Always load .env from the project root, regardless of working directory
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

class AIEngine:
    def __init__(self):
        # Configure Gemini API
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-2.5-flash')
        else:
            self.model = None

    def get_remediation(self, anomaly_description, identity_context):
        """
        Generates AI-powered remediation recommendations using Gemini.
        """
        if not self.model:
            return "AI API key not configured. Please set GEMINI_API_KEY in the .env file."
            
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
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error generating AI explanation: {e}"

if __name__ == "__main__":
    engine = AIEngine()
    result = engine.get_remediation(
        anomaly_description="User terminated on 2023-10-15 but has active AD and AWS accounts.",
        identity_context="Identity ID: ID-1045, Name: John Doe, Department: Engineering, Type: Employee"
    )
    print(result)
