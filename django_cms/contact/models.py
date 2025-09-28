from django.db import models

class ContactMessage(models.Model):
    name = models.CharField("Nombre", max_length=80)
    email = models.EmailField("Correo", max_length=120)
    phone = models.CharField("Teléfono", max_length=20, blank=True)
    subject = models.CharField("Asunto", max_length=120)
    message = models.TextField("Mensaje", max_length=2000)
    terms = models.BooleanField("Aceptó términos", default=False)
    ip = models.GenericIPAddressField("IP remitente", null=True, blank=True)
    user_agent = models.TextField("User-Agent", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Mensaje de contacto"
        verbose_name_plural = "Mensajes de contacto"

    def __str__(self):
        return f"{self.name} <{self.email}> — {self.subject}"
