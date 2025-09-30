from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import httpx, os

# 0) .env (solo útil en local)
load_dotenv()

# 1) ENV
CONTACT_INBOX_TOKEN  = os.environ.get("CONTACT_INBOX_TOKEN", "")
DJANGO_INBOX_URL     = os.environ.get("DJANGO_INBOX_URL", "").strip()  # deja vacío si no usarás Django ahora
RECAPTCHA_SECRET_KEY = os.environ.get("RECAPTCHA_SECRET_KEY", "").strip()

RECAPTCHA_URL = "https://www.google.com/recaptcha/api/siteverify"

# 2) APP
app = FastAPI(title="Contacto API")

# 3) CORS
ALLOWED_ORIGINS = [
    "https://araque08.com",
    "https://www.araque08.com",
    # "http://127.0.0.1:5500",
    # "http://localhost:5500",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"^https:\/\/(www\.)?araque08\.com$",
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=False,
)

# 4) Salud
@app.get("/")
def root():
    return {"ok": True}

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

# 5) reCAPTCHA
async def verify_recaptcha(token: str, ip: str | None):
    if not RECAPTCHA_SECRET_KEY:
        return {"ok": False, "reason": "missing-secret"}
    data = {"secret": RECAPTCHA_SECRET_KEY, "response": token}
    if ip:
        data["remoteip"] = ip
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(RECAPTCHA_URL, data=data)
        r.raise_for_status()
        j = r.json()
        # j incluye: success, challenge_ts, hostname, ["error-codes"]
        return {
            "ok": bool(j.get("success")),
            "hostname": j.get("hostname"),
            "errors": j.get("error-codes", []),
        }

# 6) Endpoint
@app.post("/submit-contact")
async def submit_contact(
    request: Request,
    empresa: str = Form("", description="Honeypot; debe permanecer vacío"),  # quítalo si no lo quieres
    name: str = Form(..., min_length=2, max_length=80),
    email: str = Form(..., max_length=120),
    phone: str = Form("", max_length=20),
    subject: str = Form(..., min_length=3, max_length=120),
    message: str = Form(..., min_length=10, max_length=2000),
    terms: str = Form(...),
    g_recaptcha_response: str = Form(..., alias="g-recaptcha-response"),
):
    # Origen (opcional, por si quieres reforzar)
    origin = request.headers.get("origin") or request.headers.get("referer") or ""

    # Honeypot
    if empresa.strip():
        raise HTTPException(status_code=400, detail="Bot detectado")

    # Validaciones mínimas
    if "@" not in email or "." not in email:
        raise HTTPException(status_code=400, detail="Correo inválido")
    if terms not in ("on", "true", "1", "yes", "si", "sí"):
        raise HTTPException(status_code=400, detail="Debes aceptar los términos")

    # reCAPTCHA
    ok = await verify_recaptcha(g_recaptcha_response, request.client.host if request.client else None)
    if not ok:
        raise HTTPException(status_code=400, detail="reCAPTCHA inválido")

    # (Opcional) Enviar a Django SOLO si está configurado
    if DJANGO_INBOX_URL and CONTACT_INBOX_TOKEN:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                DJANGO_INBOX_URL,
                data={
                    "name": name,
                    "email": email,
                    "phone": phone,
                    "subject": subject,
                    "message": message,
                    "terms": terms,
                },
                headers={"X-Contact-Token": CONTACT_INBOX_TOKEN},
            )
            if r.status_code >= 400:
                raise HTTPException(status_code=502, detail=f"Guardar en CMS falló: {r.text}")

    return JSONResponse({"ok": True, "message": "Validación OK"}, status_code=200)
