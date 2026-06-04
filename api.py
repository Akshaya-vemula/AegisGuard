from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, List

import pandas as pd

from ueba_service import score_df


app = FastAPI(
    title="AegisGuard Threat Scoring API",
    version="1.0.0",
    description="UEBA-Based Insider Threat Detection Backend"
)


class TelemetryEvent(BaseModel):
    user_id: str
    timestamp: str
    department: Optional[str] = None
    role: Optional[str] = None
    login_count: Optional[int] = 0
    file_access: float
    avg_file_access_30d: float
    usb_usage: Optional[float] = 0
    emails_sent: Optional[float] = 0
    email_subject: Optional[str] = ""
    network_traffic_mb: float


@app.get("/health")
def health():
    return {
        "status": "ok"
    }


@app.post("/score")
def score(event: TelemetryEvent):

    df = pd.DataFrame([event.model_dump()])

    result = score_df(df)

    latest = result.iloc[-1]

    return {
        "user_id": latest['user_id'],
        "timestamp": str(latest['timestamp']),
        "risk_score": float(latest['risk_score']),
        "threat_level": latest['threat_level'],
        "risk_factors": latest['risk_factors'],
        "patterns_found": latest['patterns_found']
    }


@app.post("/score/batch")
def score_batch(events: List[TelemetryEvent]):

    rows = [event.model_dump() for event in events]

    df = pd.DataFrame(rows)

    scored = score_df(df)

    results = []

    for _, row in scored.iterrows():

        results.append({
            "user_id": row['user_id'],
            "timestamp": str(row['timestamp']),
            "risk_score": float(row['risk_score']),
            "threat_level": row['threat_level'],
            "risk_factors": row['risk_factors'],
            "patterns_found": row['patterns_found']
        })

    return {
        "count": len(results),
        "results": results
    }