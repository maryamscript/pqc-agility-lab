
from fastapi import FastAPI

from app.routes.scanner import router as scanner_router


app = FastAPI(
    title="PQC-Agility-Lab",
    description="Post-Quantum Crypto-Agility Framework",
    version="1.0.0"
)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "PQC-Agility-Lab Backend",
        "message": "Backend is running successfully"
    }


app.include_router(scanner_router)
