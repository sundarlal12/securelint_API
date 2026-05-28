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
app = FastAPI(
    title="SecureLint API",
    docs_url=None,        # disables /docs
    redoc_url=None,       # disables /redoc
    openapi_url=None      # disables /openapi.json
)

origins = [
    # local dev
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    # production
    "https://securelint.app",
    "https://vaptlabs.com",
    "https://securelint.in",
    "https://www.securelint.in",
    # Netlify deployments (main + preview branches)
    "https://securelint-nextjs.netlify.app",
    "https://securelint.netlify.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,          # explicit list required when allow_credentials=True
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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