# -*- coding: utf-8 -*-
import base64
import datetime
import json
import uuid

from django.conf import settings
from django.contrib.auth import logout
from django.db.utils import IntegrityError
from django.shortcuts import redirect
from django.utils import timezone
from django.utils.translation import ugettext as _
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import permissions, status, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts import mixins, models, serializers
from accounts.permissions import IsAdminOrAccountOwner
from codes.models import Code, CodeRedeemed
from utils import language
from utils.tasks.emails import send_mail


class LoginView(APIView):
    """
    Authentication confirmation for social auth

    """
    permission_classes = (permissions.AllowAny,)

    def get(self, request, *args, **kwargs):
        account = request.user
        if account.is_authenticated:
            logout(request)
            if account.is_active:
                token, created = Token.objects.get_or_create(user=account)
                if not settings.FRONTEND_LOGIN_REDIRECT_URL:
                    serialized_account = serializers.AccountSerializer(account)
                    data = serialized_account.data
                    data['token'] = token.pk
                    return Response(data)
                else:
                    return redirect(
                        '{}?token={}'.format(
                            settings.FRONTEND_LOGIN_REDIRECT_URL,
                            base64.urlsafe_b64encode(token.pk.encode()).decode()
                        )
                    )
            else:
                return Response({
                    'status': 'Unauthorized',
                    'message': _('Your account has been disabled.')
                }, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({
                'status': 'Unauthorized',
                'message': _('Username/password combination invalid.')
            }, status=status.HTTP_401_UNAUTHORIZED)

    def post(self, request, *args, **kwargs):
        """
        Authentication for account

        """
        serializer = serializers.LoginSerializer(
            data=request.data
        )
        if not serializer.is_valid():
            return Response({'errors': serializer.errors}, status.HTTP_400_BAD_REQUEST)

        data = serializer.data
        email = data.get('email')
        password = data.get('password')

        try:
            account = models.Account.objects.get(
                email=email
            )
        except models.Account.DoesNotExist:
            account = None

        if account and account.check_password(password):
            if account.is_active:
                serialized_account = serializers.AccountSerializer(account)
                data = serialized_account.data

                token, created = Token.objects.get_or_create(user=account)
                data['token'] = token.pk

                return Response(data)
            else:
                return Response({
                    'status': 'Unauthorized',
                    'message': _('Your account has been disabled.')
                }, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({
                'status': 'Unauthorized',
                'message': _('Username/password combination invalid.')
            }, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    """
    Logout View

    """
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        """
        Unauthenticated for account

        """
        Token.objects.filter(user=request.user).delete()
        logout(request)
        return Response({}, status=status.HTTP_204_NO_CONTENT)


class AccountViewSet(mixins.DefaultCRUDPermissions, viewsets.ModelViewSet):
    """
    ViewSet for Accounts

    """
    filter_backends = (DjangoFilterBackend, SearchFilter)
    filter_fields = ('birthdate', 'civil_status', 'educational_level')
    search_fields = ('email', 'first_name', 'last_name')
    queryset = models.Account.objects.all()

    def get_serializer_class(self):
        serializer = serializers.AccountSerializer

        if self.action == 'reset_password_ask':
            serializer = serializers.ResetPasswordAskSerializer
        elif self.action == 'reset_password_change':
            serializer = serializers.ResetPasswordChangueSerializer
        elif self.action == 'change_password':
            serializer = serializers.ChanguePasswordSerializer
        elif self.action == 'check_email':
            serializer = serializers.CheckEmailSerializer
        elif self.action == 'redeemed':
            serializer = serializers.CodeRedeemedSerializer

        return serializer

    def get_queryset(self):
        """
        Get queryset

        """
        queryset = super(AccountViewSet, self).get_queryset()
        return queryset.filter(is_active=True)

    def get_throttles(self):
        """
        Get throttles

        """
        if self.action == 'create':
            self.throttle_scope = 'create_account'
        return super(AccountViewSet, self).get_throttles()

    def destroy(self, request, pk=None):
        """
        Not destroy, set is_active = False

        """
        account = self.get_object()
        account.is_active = False
        account.save(update_fields=['is_active', 'updated_at'])

        return Response({}, status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def get_account(self, request, *args, **kwargs):
        """
        Get account authenticated

        """
        serializer = self.get_serializer_class()(request.user)
        return Response(serializer.data)

    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def reset_password_ask(self, request, *args, **kwargs):
        """
        Reset password ask of the account

        """
        serializer = self.get_serializer_class()(data=request.data)

        if not serializer.is_valid():
            return Response({'errors': serializer.errors}, status.HTTP_400_BAD_REQUEST)

        data = serializer.data
        try:
            account = models.Account.objects.get(
                email=data.get('email').lower()
            )
        except models.Account.DoesNotExist:
            return Response({
                'status': 'Not Found',
                'message': _('Account does not exist.')
            }, status.HTTP_404_NOT_FOUND)

        if account.reset_password_key_expires and account.reset_password_key_expires > timezone.now():
            return Response({
                'status': 'Bad request',
                'message': _('We already sent a link to reset the password.')
            }, status.HTTP_400_BAD_REQUEST)

        account.reset_password_key = uuid.uuid4().hex
        account.reset_password_key_expires = timezone.now() + datetime.timedelta(hours=4)
        account.save(update_fields=['reset_password_key', 'reset_password_key_expires', 'updated_at'])

        json_data = {
            'email': account.email,
            'token': account.reset_password_key,
        }
        url = '{}password/reset/{}/'.format(
            request.META.get('HTTP_HOST'),
            base64.urlsafe_b64encode(json.dumps(json_data).encode()).decode()
        )

        data = {
            'name': account.get_full_name(),
            'url': url,
        }
        template = 'reset-password-{}.html'.format(language.get_language())
        send_mail.delay([account.email], _('Reset password'), template, data)

        return Response({}, status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def reset_password_change(self, request, *args, **kwargs):
        """
        Reset password change of the account

        """
        serializer = self.get_serializer_class()(data=request.data)

        if not serializer.is_valid():
            return Response({'errors': serializer.errors}, status.HTTP_400_BAD_REQUEST)

        data = serializer.data
        try:
            account = models.Account.objects.get(
                email=data.get('email').lower()
            )
        except models.Account.DoesNotExist:
            return Response({
                'status': 'Not Found',
                'message': _('Account does not exist.')
            }, status.HTTP_404_NOT_FOUND)

        if account.reset_password_key != data.get('token'):
            return Response({
                'status': 'Bad request',
                'message': _('Token does not match with the account.')
            }, status.HTTP_400_BAD_REQUEST)

        if account.reset_password_key_expires and account.reset_password_key_expires < timezone.now():
            return Response({
                'status': 'Bad request',
                'message': _('The token has already expired, please request a new one.')
            }, status.HTTP_400_BAD_REQUEST)

        account.set_password(data.get('password'))
        account.reset_password_key = ''
        account.reset_password_key_expires = None
        account.save()

        return Response({}, status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['post'], permission_classes=[IsAdminOrAccountOwner])
    def change_password(self, request, *args, **kwargs):
        """
        Change the password of the account

        """
        account = self.get_object()
        serializer = self.get_serializer_class()(data=request.data)

        if not serializer.is_valid():
            return Response({'errors': serializer.errors}, status.HTTP_400_BAD_REQUEST)

        data = serializer.data
        if not account.check_password(data.get('old_password')):
            return Response({
                'status': 'Bad request',
                'message': _('Current password does not match.')
            }, status=status.HTTP_400_BAD_REQUEST)

        account.set_password(data.get('new_password'))
        account.save(update_fields=['password', 'updated_at'])

        return Response({}, status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def check_email(self, request, *args, **kwargs):
        """
        Verifies the existence of a registered account with an email

        """
        serializer = self.get_serializer_class()(data=request.data)

        if not serializer.is_valid():
            return Response({'errors': serializer.errors}, status.HTTP_400_BAD_REQUEST)

        data = serializer.data
        email = data.get('email').lower()

        status_code = status.HTTP_200_OK
        if models.Account.objects.filter(email=email).exists():
            status_code = status.HTTP_406_NOT_ACCEPTABLE
        return Response({}, status=status_code)

    @action(detail=True, methods=['post'], permission_classes=[IsAdminOrAccountOwner])
    def redeemed(self, request, *args, **kwargs):
        """
        Redeem codes for points

        """

        account = self.get_object()

        serializer = self.get_serializer_class()(data=request.data)

        if not serializer.is_valid():
            return Response({'errors': serializer.errors}, status.HTTP_400_BAD_REQUEST)

        try:
            code = Code.objects.get(uuid=serializer.data.get('uuid'))
        except Code.DoesNotExist:
            return Response({
                'status': 'Bad request',
                'message': _('Invalid code.')
            }, status=status.HTTP_400_BAD_REQUEST)

        if code.expires < timezone.now():
            return Response({
                'status': 'Bad request',
                'message': _('Already expired.')
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            CodeRedeemed.objects.create(account=account, code=code)
        except IntegrityError:
            return Response({
                'status': 'Bad request',
                'message': _('Already redeemed.')
            }, status=status.HTTP_400_BAD_REQUEST)

        account.refresh_from_db()
        return Response({'points': code.points})
