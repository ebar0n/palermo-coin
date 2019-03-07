# -*- coding: utf-8 -*-
from django.contrib import admin
from django.utils.translation import ugettext as _

from accounts import models
from accounts.forms import AccountChangeForm


@admin.register(models.Account)
class AccountAdmin(admin.ModelAdmin):
    """
    AccountAdmin

    """
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('personal info'), {'fields': ('first_name', 'last_name', 'phone_number')}),
        (_('permissions info'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')
        }),
        (_('other info'), {'fields': ('points', 'last_login', 'created_at', 'updated_at')}),
    )
    filter_horizontal = ('groups', 'user_permissions',)
    form = AccountChangeForm
    list_display = ('email', 'points', 'is_active', 'is_staff', 'is_superuser')
    list_filter = ('is_staff', 'is_active', 'is_superuser', 'created_at')
    ordering = ('created_at',)
    readonly_fields = ('points', 'last_login', 'created_at', 'updated_at')
    search_fields = ('email',)
