from django.urls import path
from . import views
from .views import *

urlpatterns = [
    path('', home, name='home'),
    path('register/', views.register, name='register'),
    path('signin/', views.signin, name='signin'),
    path("about/", about, name="about"),
    path("chats/", chat, name="chat"),
    path('logout/', views.logout_view, name='logout'),
]
