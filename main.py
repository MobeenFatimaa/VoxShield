import os
import json
import requests
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

ASSEMBLYAI_API_KEY = os.getenv("ASSEMBLYAI_API_KEY")
if not ASSEMBLYAI_API_KEY:
    raise RuntimeError("ASSEMBLYAI_API_KEY is not set in environment variables.")

app = FastAPI(title="VoxShield AI - Real-Time Phishing Inspector")

# Mock database of flagged scam entities
FLAGGED_SCAM_ENTITIES = {
    "accounts": ["9988776655", "123456789", "000999888"],
    "names": ["IRS Support", "Urgent Legal Services", "Tech Support Helpdesk"],
    "keywords": ["gift card", "crypto deposit", "wire immediately", "bail money", "overdue tax fine"]
}

class ToolCallRequest(BaseModel):
    name: str
    arguments: dict

@app.get("/api/agent/token")
def get_voice_agent_token():
    """Mints a temporary WebSocket token for browser streaming."""
    headers = {
        "Authorization": ASSEMBLYAI_API_KEY,
        "Content-Type": "application/json"
    }
    # Requests token endpoint for AssemblyAI Voice Agent session
    res = requests.post("https://api.assemblyai.com/v1/realtime/token", headers=headers, json={"expires_in": 3600})
    if res.status_code != 200:
        raise HTTPException(status_code=res.status_code, detail="Failed to fetch AssemblyAI token")
    return res.json()

@app.post("/api/tools/verify_transaction_safety")
def verify_transaction_safety(payload: dict):
    """
    Tool function called directly during real-time voice streaming.
    Checks parameters against security risk patterns.
    """
    args = payload.get("arguments", payload)
    
    recipient = str(args.get("recipient_name", "")).lower()
    account = str(args.get("account_or_routing", ""))
    urgency = str(args.get("urgency_keywords", "")).lower()
    amount = args.get("amount", 0)

    is_flagged_account = any(acc in account for acc in FLAGGED_SCAM_ENTITIES["accounts"])
    is_flagged_name = any(name.lower() in recipient for name in FLAGGED_SCAM_ENTITIES["names"])
    has_scam_keyword = any(kw in urgency for kw in FLAGGED_SCAM_ENTITIES["keywords"])

    if is_flagged_account or is_flagged_name or has_scam_keyword or (amount and amount > 5000):
        return {
            "status": "ALERT_HIGH_RISK",
            "is_phishing": True,
            "risk_score": 0.95,
            "reason": f"Recipient '{recipient}' or account details matched known phishing registries and high-risk pressure patterns.",
            "recommendation": "STOP IMMEDIATELY. Do not transfer funds or share verification codes."
        }
    
    return {
        "status": "SAFE",
        "is_phishing": False,
        "risk_score": 0.05,
        "reason": "No suspicious fraud patterns identified.",
        "recommendation": "Transaction appears standard."
    }

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
def serve_index():
    with open("static/index.html", "r") as f:
        return f.read()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
