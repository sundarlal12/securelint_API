# from dotenv import load_dotenv
# import os

# load_dotenv()  # load .env ONCE, globally

# SUPABASE_URL = os.getenv("NEXT_PUBLIC_SUPABASE_URL")
# SUPABASE_ANON_KEY = os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")

# if not SUPABASE_URL or not SUPABASE_ANON_KEY:
#     raise RuntimeError("Supabase env vars not loaded")

# import requests
# from jose import jwt
# from fastapi import HTTPException, Security
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# SUPABASE_URL = "https://jhqgyufsgxjessfvdyyc.supabase.co"
# JWKS_URL = f"{SUPABASE_URL}/auth/v1/certs"

# security = HTTPBearer()
# jwks = requests.get(JWKS_URL).json()

# def verify_supabase_jwt(
#     creds: HTTPAuthorizationCredentials = Security(security)
# ):
#     try:
#         payload = jwt.decode(
#             creds.credentials,
#             jwks,
#             algorithms=["RS256"],
#             audience="authenticated"
#         )
#         return payload
#     except Exception:
#         raise HTTPException(status_code=401, detail="Invalid or expired token")



# import requests
# from jose import jwt
# from fastapi import HTTPException, Security
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# SUPABASE_URL = "https://jhqgyufsgxjessfvdyyc.supabase.co"
# JWKS_URL = f"{SUPABASE_URL}/auth/v1/certs"

# security = HTTPBearer()

# jwks = requests.get(JWKS_URL).json()

# def verify_supabase_jwt(
#     creds: HTTPAuthorizationCredentials = Security(security)
# ):
#     token = creds.credentials

#     try:
#         payload = jwt.decode(
#             token,
#             jwks,
#             algorithms=["RS256"],
#             audience="authenticated",
#             options={
#                 "verify_aud": True,
#                 "verify_iss": False  # Supabase does not enforce iss strictly
#             }
#         )
#         return payload

#     except Exception as e:
#         print("JWT VERIFY ERROR:", str(e))
#         raise HTTPException(status_code=401, detail="Invalid or expired token")



from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
import os

security = HTTPBearer()

SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")

if not SUPABASE_JWT_SECRET:
    raise RuntimeError("SUPABASE_JWT_SECRET not set")

def verify_supabase_jwt(
    creds: HTTPAuthorizationCredentials = Security(security)
):
    token = creds.credentials

    try:
        payload = jwt.decode(
            token,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            audience="authenticated"
        )
        return payload

    except Exception as e:
        print("JWT VERIFY ERROR:", str(e))
        raise HTTPException(status_code=401, detail="Invalid or expired token")
