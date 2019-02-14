# -*- coding: utf-8 -*-
from rest_framework import permissions

from accounts.permissions import IsAdminOrAccountOwner


class DefaultCRUDPermissions(object):
    """
    Mixin to verify if the user can access to a method through a web service

    """

    def get_permissions(self):
        """
        Get permissions

        """
        if self.action == 'create':
            return [permissions.AllowAny()]

        if self.action in ['update', 'partial_update', 'destroy', 'retrieve']:
            return [IsAdminOrAccountOwner()]

        if self.action == 'list':
            return [permissions.IsAdminUser()]

        return [permission() for permission in self.permission_classes]
