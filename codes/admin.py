# -*- coding: utf-8 -*-
from django.contrib import admin

from codes import models


@admin.register(models.Code)
class CodeAdmin(admin.ModelAdmin):
    list_display = ('title', 'points', 'qr', 'expires', 'created_at')
    list_filter = ('expires', 'created_at')
    readonly_fields = ('qr',)
    ordering = ('expires',)
    search_fields = ('title',)


@admin.register(models.CodeRedeemed)
class CodeRedeemedAdmin(admin.ModelAdmin):
    list_display = ('account', 'code', 'created_at')
    list_filter = ('code', 'created_at')
    ordering = ('created_at',)
    search_fields = ('code__title', 'account__email')
