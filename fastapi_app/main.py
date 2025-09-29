from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import httpx, os

app = FastAPI(title="Contacto API")

@app.get("/")
def root():
    return {"ok": True}   # 200 en raíz

@app.get("/healthz")
def healthz():
    return {"status": "ok"}  # 200 para healthcheck explícito


load_dotenv()  # carga .env si existe

# === ENV ===
CONTACT_INBOX_TOKEN  = os.environ.get("CONTACT_INBOX_TOKEN")
DJANGO_INBOX_URL     = os.environ.get("DJANGO_INBOX_URL", "http://127.0.0.1:9000/contact/inbox/")
RECAPTCHA_SECRET_KEY = os.environ.get("RECAPTCHA_SECRET_KEY")

# === C O R S ===
# Agrega aquí los dominios desde donde enviarás el form (tu sitio estático, etc.)
ALLOWED_ORIGINS = [
    "https://araque08.com",
    "https://www.araque08.com",
    #"http://127.0.0.1:5500",
    #"http://localhost:5500",
    #"http://127.0.0.7:5500",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === reCAPTCHA ===
RECAPTCHA_URL = "https://www.google.com/recaptcha/api/siteverify"

# Usa variable de entorno para la clave secreta real:
# export RECAPTCHA_SECRET_KEY="TU_CLAVE_SECRETA_V2"
RECAPTCHA_SECRET_KEY = os.getenv("6LcCb9UrAAAAAH2yPDMGdJm_STkdNyjyh2znThhl&response=", "").strip()

# Para pruebas, puedes usar las claves de prueba de Google (si no has configurado la real):
# Site key (cliente): 6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI
# Secret (servidor): 6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe

async def verify_recaptcha(token: str, ip: str | None) -> bool:
    """
    Verifica reCAPTCHA v2 (checkbox). Devuelve True si Google confirma.
    """
    secret = RECAPTCHA_SECRET_KEY or "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"  # fallback a test secret
    data = {"secret": secret, "response": token}
    if ip:
        data["remoteip"] = ip

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(RECAPTCHA_URL, data=data)
        r.raise_for_status()
        payload = r.json()
        return bool(payload.get("success", False))

@app.get("/")
def health():
    return {"ok": True, "msg": "API arriba"}

@app.post("/submit-contact")
async def submit_contact(
    request: Request,
    # Honeypot
    empresa: str = Form("", description="Honeypot; debe permanecer vacío"),
    # Campos reales del form
    name: str = Form(..., min_length=2, max_length=80),
    email: str = Form(..., max_length=120),
    phone: str = Form("", max_length=20),
    subject: str = Form(..., min_length=3, max_length=120),
    message: str = Form(..., min_length=10, max_length=2000),
    terms: str = Form(...),  # "on" | "true" | "1"
    # reCAPTCHA
    g_recaptcha_response: str = Form(..., alias="g-recaptcha-response"),
):
    # 0) Origen (opcional): si quieres reforzar, valida Origin/Referer
    origin = request.headers.get("origin") or request.headers.get("referer") or ""
    if ALLOWED_ORIGINS and not any(origin.startswith(o) for o in ALLOWED_ORIGINS if o):
        # No lo bloqueamos duro por si hay casos de falta de header, pero puedes activar:
        # raise HTTPException(status_code=400, detail="Origen no permitido")
        pass

    # 1) Honeypot
    if empresa.strip():
        raise HTTPException(status_code=400, detail="Bot detectado")

    # 2) Validaciones mínimas adicionales
    if "@" not in email or "." not in email:
        raise HTTPException(status_code=400, detail="Correo inválido")
    terms_ok = terms in ("on", "true", "1", "yes", "si", "sí")
    if not terms_ok:
        raise HTTPException(status_code=400, detail="Debes aceptar los términos")

    # 3) reCAPTCHA
    client_ip = request.client.host if request.client else None
    ok = await verify_recaptcha(g_recaptcha_response, client_ip)
    if not ok:
        raise HTTPException(status_code=400, detail="reCAPTCHA inválido")

    # 5) Enviar a Django para guardar
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
        # Si Django devuelve error, propágalo
        if r.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"Guardar en CMS falló: {r.text}")

    return JSONResponse({"ok": True, "message": "Validación OK y guardado en CMS"}, status_code=200)


    return JSONResponse(
        {"ok": True, "message": "Validación reCAPTCHA OK. Datos recibidos."},
        status_code=200,
    )