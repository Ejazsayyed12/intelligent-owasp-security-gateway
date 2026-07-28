from fastapi import FastAPI
from engines.detection_engine import analyze_request

app = FastAPI(
    title="OWASP Security Gateway",
    version="1.0"
)


@app.get("/")
def home():

    return {
        "project": "OWASP Security Gateway",
        "status": "Running"
    }


@app.get("/scan")
def scan(payload: str):

    return analyze_request(payload)