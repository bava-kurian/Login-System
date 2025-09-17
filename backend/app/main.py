from fastapi import FastAPI
from app.api.auth import router as auth_router

app = FastAPI()

@app.get("/health")
def healthcheck():
    return {"status": "ok"}

app.include_router(auth_router)

