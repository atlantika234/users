import uvicorn
from sqlalchemy import text
from fastapi import FastAPI, APIRouter, HTTPException
from app.db import engine, Base, DBConnectionDep
from users.routers import session_router, user_router, profile_router
from app.settings import settings
from datetime import datetime, timezone

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.app.NAME,
    version=settings.app.VERSION
)
base_router = APIRouter(tags=['base'])
routers = [session_router, user_router, profile_router]

@base_router.get("/")
def status(db: DBConnectionDep):
    try:
        result = db.execute(text("SELECT 1"))
        print(result)
        return {"version": settings.app.VERSION, "name": settings.app.NAME, "status": "ok", "env": settings.app.ENV, "datetime": datetime.now(timezone.utc)}
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Error db connection")

[app.include_router(router, prefix=settings.app.BASE_URL_PREFIX) for router in routers]

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.app.HOST, port=settings.app.PORT, reload=True, workers=1)
