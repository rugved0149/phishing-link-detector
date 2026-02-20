from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import sys
import os

# allow importing core engine
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from app import check_url

app = FastAPI(title="Phishing Link Detector")

app.mount("/static", StaticFiles(directory="web/static"), name="static")
templates = Jinja2Templates(directory="web/templates")


class URLRequest(BaseModel):
    url: str


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/analyze")
async def analyze(data: URLRequest):
    result = check_url(data.url)
    return JSONResponse(content=result)
