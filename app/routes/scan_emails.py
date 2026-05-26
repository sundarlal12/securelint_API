import os
import random
import httpx
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

# Load .env for local dev (mirrors app/core/config.py pattern)
if os.getenv("VERCEL") != "1":
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

router = APIRouter()

# Realistic browser User-Agent pool
_USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

securelint_BASE = os.getenv("WOT_SCAN_URL")
if not securelint_BASE:
    raise RuntimeError("WOT_SCAN_URL is not set in environment variables")

# Fixed gbData payload (matches the extension's format)
GB_DATA = (
    '{"attributes":{"wid":"37b8f995a8e4a0022df19f368edcbf3a962ed44a",'
    '"firstRunDate":1778487339080}}'
)


@router.get("/scanEmails")
async def scan_emails(email: str = Query(..., description="Email address to scan for leaks")):
    """
    Proxy wrapper around the securelint leak-scan API.
    Adds a random User-Agent on every request to avoid rate-limiting.
    """
    params = {
        "fromDate": "1",
        "gbData": GB_DATA,
        "mails": email,
    }

    headers = {
        "User-Agent": random.choice(_USER_AGENTS),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.google.com/",
        "Origin": "https://www.google.com",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(securelint_BASE, params=params, headers=headers)
            resp.raise_for_status()
            return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=exc.response.status_code,
            detail=f"Upstream securelint API error: {exc.response.text}",
        )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to reach securelint API: {str(exc)}",
        )
