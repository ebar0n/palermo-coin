# -*- coding: utf-8 -*-
import django
from django.conf import settings
from django.conf.urls import include, url
from django.contrib import admin
from django.urls import path, re_path

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/', include('accounts.urls')),
    re_path('static/(.*)$', django.views.static.serve, {'document_root': settings.STATIC_ROOT}),
    re_path('media/(.*)$', django.views.static.serve, {'document_root': settings.MEDIA_ROOT}),
]

if settings.DOCS:
    from rest_framework_swagger.views import get_swagger_view
    schema_view = get_swagger_view(title='Leviatan API')
    urlpatterns += [
        url(r'^$', schema_view)
    ]
