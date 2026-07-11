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

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes.auth import router as auth_router
from app.routes.me import router as me_router
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
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# The admin dashboard uses XHR with an Authorization header (no cookies /
# withCredentials), so allow_origins="*" is safe and works from any origin
# including Netlify preview branches.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,          # must be False when allow_origins="*"
    allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    allow_headers=["Authorization","Content-Type","X-Requested-With","x-org-id"],
)

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