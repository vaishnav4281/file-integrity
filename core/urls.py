
from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('register/', views.register_integrity, name='register'),
    path('verify/', views.verify_integrity, name='verify'),
]
