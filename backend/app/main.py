# backend/app/main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import router
from app.database import init_db
from app.scheduler import init_scheduler, shutdown_scheduler
import os

app = FastAPI(
    title="API Sentinel",
    description="AI-powered API security testing platform",
    version="0.2.0"
)

# CORS — in production lock this down to your frontend's origin
ALLOWED_ORIGINS_ENV = os.getenv("ALLOWED_ORIGINS", "*").strip()
if ALLOWED_ORIGINS_ENV == "*":
    ALLOWED_ORIGINS = ["*"]
    ALLOW_CREDENTIALS = False
else:
    ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGINS_ENV.split(",") if origin.strip()]
    ALLOW_CREDENTIALS = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.on_event("startup")
def startup():
    """Initialise SQLite tables and start the APScheduler."""
    init_db()
    init_scheduler()


@app.on_event("shutdown")
def shutdown_event():
    shutdown_scheduler()


@app.get("/")
def root():
    return {"message": "API Sentinel", "version": "0.2.0", "status": "running"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)