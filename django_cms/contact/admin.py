from django.contrib import admin
from .models import ContactMessage

@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ("created_at", "name", "email", "subject", "terms")
    list_filter = ("created_at", "terms")
    search_fields = ("name", "email", "subject", "message")
    readonly_fields = ("created_at", "ip", "user_agent")
