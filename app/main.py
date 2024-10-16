import uvicorn
from fastapi import FastAPI
from db import SessionLocal, engine, Base
from users.routers import router

Base.metadata.create_all(bind=engine)

app = FastAPI(debug=True)
app.include_router(router, prefix='/users')

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, workers=1)