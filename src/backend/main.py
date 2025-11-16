"""
Backend main application file.
"""

import time
import json

import fastapi
import fastapi.responses

import db

app = fastapi.FastAPI()


@app.get(
    "/meta/site.webmanifest", response_class=fastapi.responses.FileResponse
)
async def site_webmanifest():
    """Serve site.webmanifest file."""
    return fastapi.responses.FileResponse("src/frontend/site.webmanifest")


@app.get(
    "/meta/{icon_name}.png", response_class=fastapi.responses.FileResponse
)
async def favicon(icon_name: str):
    """Serve favicon and touch icons."""
    if icon_name in [
        "favicon-16x16",
        "favicon-32x32",
        "apple-touch-icon",
        "android-chrome-192x192",
        "android-chrome-512x512",
    ]:
        return fastapi.responses.FileResponse(f"src/frontend/{icon_name}.png")

    return fastapi.responses.Response(status_code=404)


@app.get("/", response_class=fastapi.responses.HTMLResponse)
async def view_domain():
    """Serve the main HTML view."""
    with open("src/frontend/view.html", encoding="utf-8") as f:
        html = f.read()
    return fastapi.responses.HTMLResponse(content=html, status_code=200)


@app.get("/api/v1/domains", response_class=fastapi.responses.JSONResponse)
async def list_domain():
    """List all monitored domains."""
    domain_info = db.list_items("config#domain#")
    print(domain_info)

    return fastapi.responses.JSONResponse(
        {
            "domains": domain_info,
        }
    )


@app.get(
    "/api/v1/domain/{domain}/{record_type}",
    response_class=fastapi.responses.JSONResponse,
)
async def get_domain(domain: str, record_type: str):
    """Get information about domain

    Args:
        domain (str): domain name
        record_type (str): DNS record type

    Returns:
        JSONResponse: JSON with domain information
    """
    domain_info = db.get_latest_item(domain + "#" + record_type)
    print(domain_info)
    time.sleep(0.3)

    return fastapi.responses.JSONResponse(
        {
            "mark": domain_info["mark"],
            "timestamp": int(domain_info["timestamp"]),
            "fqdn": domain_info["fqdn"],
            "ns": domain_info["ns"],
            "type": domain_info["type"],
            "records": json.loads(domain_info["records"]),
        },
    )


@app.head("/api/v1/domain/{domain}/{_}")
async def head_domain(domain: str, _: str):
    """HEAD request to check if domain record exists.

    Args:
        domain (str): domain name
        record_type (str): DNS record type

    Returns:
        Response: 200 if exists, 204 if not
    """

    domain_info = db.get_item(domain)
    print(domain_info)
    if domain_info is None:
        return fastapi.responses.Response(status_code=204)

    return fastapi.responses.Response(status_code=200)
