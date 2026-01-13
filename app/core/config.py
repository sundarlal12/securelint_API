# from dotenv import load_dotenv
# import os

# load_dotenv()  # load .env file

# SUPABASE_URL = os.getenv("NEXT_PUBLIC_SUPABASE_URL")
# SUPABASE_ANON_KEY = os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")

# if not SUPABASE_URL or not SUPABASE_ANON_KEY:
#     raise RuntimeError("Supabase env vars not loaded")

import os

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise RuntimeError("SUPABASE_URL or SUPABASE_ANON_KEY is not set")
