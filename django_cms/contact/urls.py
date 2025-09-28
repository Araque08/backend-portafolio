from django.urls import path
from .views import inbox

urlpatterns = [
    path("inbox/", inbox, name="contact_inbox"),
]
