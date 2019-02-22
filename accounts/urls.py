# -*- coding: utf-8 -*-
from django.conf.urls import include
from django.urls import path
from rest_framework import routers

from accounts import views

router = routers.SimpleRouter()

router.register(r'accounts', views.AccountViewSet, 'accounts')

urlpatterns = [
    path('auth/login/', views.LoginView.as_view(), name='login'),
    path('auth/logout/', views.LogoutView.as_view(), name='logout'),
    path('', include(router.urls)),
]
