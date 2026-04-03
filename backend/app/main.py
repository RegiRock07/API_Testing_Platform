# backend/app/main.py
from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import router
from app.database import init_db
import os

app = FastAPI(
    title="API Sentinel",
    description="AI-powered API security testing platform",
    version="0.2.0"
)

# CORS — in production lock this down to your frontend's origin
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.on_event("startup")
def startup():
    """Initialise SQLite tables on first run."""
    init_db()


@app.get("/")
def root():
    return {"message": "API Sentinel", "version": "0.2.0", "status": "running"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)