import fastapi
import fastapi.responses

import time

import json

import db

app = fastapi.FastAPI()


def generate_html_response():
    with open("src/frontend/view.html", encoding="utf-8") as f:
        html = f.read()
    return fastapi.responses.HTMLResponse(content=html, status_code=200)


@app.get("/", response_class=fastapi.responses.HTMLResponse)
async def view_domain():
    return generate_html_response()


@app.get("/api/v1/domains", response_class=fastapi.responses.JSONResponse)
async def list_domain():
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


@app.head("/api/v1/domain/{domain}/{record_type}")
async def head_domain(domain: str, record_type: str):
    domain_info = db.get_item(domain)
    print(domain_info)
    if domain_info is None:
        return fastapi.responses.Response(status_code=204)

    return fastapi.responses.Response(status_code=200)
