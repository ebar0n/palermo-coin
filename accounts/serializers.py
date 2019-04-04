# -*- coding: utf-8 -*-

from django.contrib.auth import authenticate, login
from django.utils.translation import ugettext as _
from rest_framework import serializers

from accounts import models
from utils.validations import validate_password


class AccountSerializer(serializers.ModelSerializer):
    """
    Account Serializer

    """

    class Meta:
        """
        Meta

        """
        model = models.Account
        fields = (
            'id', 'email', 'first_name', 'last_name',
            'phone_number', 'birthdate', 'baptism', 'civil_status',
            'educational_level', 'area_knowledge', 'school', 'interests',
            'points', 'is_staff', 'is_superuser',
        )
        read_only_fields = ('id', 'points', 'is_staff', 'is_superuser')

    def create(self, validated_data):
        """
        Create

        """
        password = self.context['request'].data.get('password')
        if not password:
            raise serializers.ValidationError({'password': [_('This field is required.')]})

        password_errors = validate_password(password)
        if password_errors:
            raise serializers.ValidationError({'password': password_errors})

        account = models.Account.objects.create_user(
            password=password,
            **validated_data
        )
        account.save()

        auth = authenticate(username=account.username, password=password)
        login(self.context['request'], auth)

        return account


class ResetPasswordAskSerializer(serializers.Serializer):
    """
    ResetPasswordAsk Serializer

    """
    email = serializers.EmailField()


class ResetPasswordChangueSerializer(serializers.Serializer):
    """
    ResetPasswordChangue Serializer

    """
    email = serializers.EmailField()
    token = serializers.CharField(max_length=32)
    password = serializers.CharField(max_length=128)

    def validate_password(self, password):
        password_errors = validate_password(password)
        if password_errors:
            raise serializers.ValidationError(password_errors)
        return password


class ChanguePasswordSerializer(serializers.Serializer):
    """
    ChanguePassword Serializer

    """
    old_password = serializers.CharField(max_length=128)
    new_password = serializers.CharField(max_length=128)

    def validate_new_password(self, password):
        password_errors = validate_password(password)
        if password_errors:
            raise serializers.ValidationError(password_errors)
        return password


class CheckEmailSerializer(serializers.Serializer):
    """
    CheckEmail Serializer

    """
    email = serializers.EmailField()


class CodeRedeemedSerializer(serializers.Serializer):
    """
    Code Serializer

    """
    uuid = serializers.UUIDField(format='hex_verbose')


class LoginSerializer(serializers.Serializer):
    """
    Login Serializer

    """
    email = serializers.EmailField()
    password = serializers.CharField(max_length=128)
