import os
import hmac
import token
import uuid
import uvicorn
import aiofiles
import datetime
import logging
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Depends, Response, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

load_dotenv(".env")
auth_token = os.environ.get("AUTHORIZATION_TOKEN")
if not auth_token or len(auth_token) < 32:
    raise RuntimeError("AUTHORIZATION_TOKEN not found in .env file or is too short (must be at least 32 characters).")

app = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host if request.client else "unknown"

# Sets up logging, rate limiting, and makes directories if they don't exist.
log_folder = "server/logs/"
upload_folder = "server/uploads"
os.makedirs(upload_folder, exist_ok=True)
os.makedirs(log_folder, exist_ok=True)
max_file_size = int(0.5 * 1024 * 1024) # 0.5 MB in bytes
logging.basicConfig(level=logging.INFO,format="%(asctime)s - %(levelname)s - %(message)s",handlers=[logging.StreamHandler(),logging.FileHandler(f"{log_folder}/server.log", encoding='utf-8')])
logger = logging.getLogger(__name__)
limiter = Limiter(key_func=get_client_ip)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"error": "You've been rate limited. Please slow down."}
    )

@app.get("/")
@limiter.limit("5/minute")
async def main(request: Request):
    return {"message": "Server running."}

@app.get("/favicon.ico", include_in_schema=False) # This prevents 404 errors for favicon requests
async def favicon():
    return Response(content=None, status_code=204)

@app.get("/health")
async def health():
    return {"status": "ok"}

async def auth(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization[7:] # Remove "Bearer"
    if not hmac.compare_digest(token, auth_token):
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.post("/upload", dependencies=[Depends(auth)])
@limiter.limit("5/minute")
async def protected(request: Request):
    content_length = request.headers.get('content-length')
    if content_length:
        try:
            if int(content_length) > max_file_size:
                raise HTTPException(status_code=413, detail="Payload exceeds maximum allowed size.")
        except ValueError:
            pass
    body = b''
    async for chunk in request.stream():
        body += chunk
        if len(body) > max_file_size:
            raise HTTPException(status_code=413, detail="Payload exceeds maximum allowed size.")
    try:
        text_body = body.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Invalid UTF-8 encoding.")

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    file_id = str(uuid.uuid4())[:8]
    filename = f"{timestamp}_{file_id}.txt"
    file_path = os.path.join(upload_folder, filename)
    try:
        async with aiofiles.open(file_path, "w", encoding="utf-8") as f:
            await f.write(text_body)
    except Exception as e:
        logger.warning(f"Failed to save upload from IP: {get_client_ip(request)} - Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to save data.")
    logger.info(f"Upload saved: {filename} from IP: {get_client_ip(request)}")    
    return {"status": "success"}

if __name__ == "__main__":
    logger.info("Starting server on http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)
