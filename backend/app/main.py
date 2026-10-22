from fastapi import FastAPI

app = FastAPI(
    title="PQC-Agility-Lab",
    description="Post-Quantum Crypto-Agility Framework",
    version="1.0.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "PQC-Agility-Lab backend",
    }