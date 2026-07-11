# from fastapi import FastAPI
# from app.routes.auth import router as auth_router

# app = FastAPI(title="Supabase Auth API")

# @app.get("/")
# def health():
#     return {"status": "ok"}

# app.include_router(auth_router, prefix="/api")

# from fastapi import FastAPI
# from app.routes.me import router as me_router
# from app.routes.subscription import router as subscription_router
# from app.routes.settings import router as settings_router

# app = FastAPI(title="SecureLint API")

# app.include_router(me_router, prefix="/api")
# app.include_router(subscription_router, prefix="/api")
# app.include_router(settings_router, prefix="/api")

from fastapi import FastAPI, Request
from fastapi.responses import Response

from app.routes.auth import router as auth_router
from app.routes.me import router as me_router
from fastapi.middleware.cors import CORSMiddleware
from app.routes.subscription import router as subscription_router
from app.routes.settings import router as settings_router
from app.routes.incidents import router as incidents_router
from app.routes.scan import router as scan_router
from app.routes.admin import router as admin_router
from app.routes.payment import router as payment_router
from app.routes.user import router as user_router
from app.routes.contact import router as contact_router
from app.routes.coupons import router as coupons_router
app = FastAPI(
    title="SecureLint API",
    docs_url=None,        # disables /docs
    redoc_url=None,       # disables /redoc
    openapi_url=None      # disables /openapi.json
)

_ALLOWED_ORIGINS_EXACT = {
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "https://securelint.app",
    "https://vaptlabs.com",
    "https://securelint.in",
    "https://www.securelint.in",
    "https://securelint-nextjs.netlify.app",
    "https://securelint.netlify.app",
}

_ALLOWED_ORIGIN_SUFFIXES = (
    ".netlify.app",
    ".vercel.app",
)

def _is_allowed_origin(origin: str) -> bool:
    if origin in _ALLOWED_ORIGINS_EXACT:
        return True
    for suffix in _ALLOWED_ORIGIN_SUFFIXES:
        if origin.endswith(suffix):
            return True
    return False

_CORS_HEADERS = {
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods":     "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers":     "Authorization, Content-Type, X-Requested-With",
    "Access-Control-Max-Age":           "600",
}

@app.middleware("http")
async def dynamic_cors(request: Request, call_next):
    origin = request.headers.get("origin", "")
    allowed = _is_allowed_origin(origin)

    # Preflight
    if request.method == "OPTIONS":
        headers = dict(_CORS_HEADERS)
        headers["Access-Control-Allow-Origin"] = origin if allowed else ""
        return Response(status_code=204, headers=headers)

    response = await call_next(request)
    if allowed:
        response.headers["Access-Control-Allow-Origin"]      = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"]     = _CORS_HEADERS["Access-Control-Allow-Methods"]
        response.headers["Access-Control-Allow-Headers"]     = _CORS_HEADERS["Access-Control-Allow-Headers"]
    return response

app.include_router(auth_router, prefix="/api")
app.include_router(me_router, prefix="/api")
app.include_router(subscription_router, prefix="/api")
app.include_router(settings_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")
app.include_router(scan_router, prefix="/api")
app.include_router(admin_router, prefix="/api")
app.include_router(payment_router, prefix="/api")
app.include_router(user_router,    prefix="/api")
app.include_router(contact_router, prefix="/api")
app.include_router(coupons_router, prefix="/api")