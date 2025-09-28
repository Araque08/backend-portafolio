import json
from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.utils.html import strip_tags
from .models import ContactMessage

@csrf_exempt  # solo recibimos desde FastAPI (server→server), por eso exento de CSRF
def inbox(request):
    if request.method != "POST":
        return HttpResponseBadRequest("Método no permitido")

    # Autenticación simple por token compartido
    token = request.headers.get("X-Contact-Token", "")
    if not settings.CONTACT_INBOX_TOKEN or token != settings.CONTACT_INBOX_TOKEN:
        return HttpResponseBadRequest("No autorizado")

    # Acepta form-encoded o JSON
    data = request.POST or {}
    if not data:
        try:
            data = json.loads(request.body.decode("utf-8"))
        except Exception:
            return HttpResponseBadRequest("Payload inválido")

    name = strip_tags((data.get("name") or "").strip())
    email = (data.get("email") or "").strip()
    phone = (data.get("phone") or "").strip()
    subject = strip_tags((data.get("subject") or "").strip())
    message = (data.get("message") or "").strip()
    terms = str(data.get("terms") or "").lower() in ("on", "true", "1", "yes", "si", "sí")

    if len(name) < 2 or len(subject) < 3 or len(message) < 10 or not email:
        return HttpResponseBadRequest("Datos inválidos")

    ContactMessage.objects.create(
        name=name,
        email=email,
        phone=phone,
        subject=subject,
        message=message,
        terms=terms,
        ip=request.META.get("REMOTE_ADDR"),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
    )
    return JsonResponse({"ok": True, "saved": True})
