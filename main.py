# main.py – FastAPI 앱 + Redis Pub/Sub → WebSocket relay
from fastapi import FastAPI, WebSocket, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from redis import Redis
import asyncio, os, json

from routers import auth, predict, report, logs, mapdata, stats, admin
from database import Base, engine
from dotenv import load_dotenv
load_dotenv()

# ---------- 기본 세팅 ----------
Base.metadata.create_all(bind=engine)
app = FastAPI(title="AI 기반 DDoS 탐지 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# ---------- Redis 연결 ----------
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
rdb = Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# ---------- 라우터 ----------
app.include_router(auth.router)
app.include_router(predict.router)
app.include_router(report.router)
app.include_router(logs.router)
app.include_router(mapdata.router)
app.include_router(stats.router)
app.include_router(admin.router)

@app.get("/")
def root():
    return {"message": "AI DDoS Detection API is running!"}

# ---------- WebSocket: dashboard용 실시간 스트림 ----------
@app.websocket("/ws")
async def ws_events(ws: WebSocket):
    await ws.accept()
    pubsub = rdb.pubsub()
    pubsub.subscribe("ddos-events")
    loop = asyncio.get_event_loop()

    try:
        while True:
            # pubsub.get_message 는 블로킹이므로 스레드로
            msg = await loop.run_in_executor(None, pubsub.get_message, True, 1)
            if msg and msg["type"] == "message":
                await ws.send_text(msg["data"])
    except Exception:
        pass
    finally:
        await ws.close()

# ---------- Swagger - OAuth 버튼 ----------
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title, version="1.0.0",
        description="AI DDoS 시스템 API",
        routes=app.routes,
    )
    schema["components"]["securitySchemes"] = {
        "OAuth2Password": {"type": "oauth2", "flows": {
            "password": {"tokenUrl": "/token", "scopes": {}}}}
    }
    for path in schema["paths"]:
        for m in schema["paths"][path]:
            schema["paths"][path][m]["security"] = [{"OAuth2Password": []}]
    app.openapi_schema = schema
    return schema

app.openapi = custom_openapi
