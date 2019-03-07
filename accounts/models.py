# -*- coding: utf-8 -*-

from django.contrib.auth import models as auth_models
from django.db import models
from django.utils.translation import ugettext as _


class AccountManager(auth_models.BaseUserManager):
    """
    Custom User Manager which inherits from BaseUserManager

    """

    def create_user(self, email, password=None, **kwargs):
        """
        Creates and saves a User with the given email, name
        and password.

        :param email: User email
        :param password: User password
        :param kwargs: Extra args
        :return: User's model instance

        """
        if not email:
            raise ValueError(_('Users must have an email address'))
        account = self.model(
            email=self.normalize_email(email).lower(),
            **kwargs
        )
        account.is_active = True
        account.set_password(password)
        account.save()
        return account

    def create_superuser(self, email, password, **kwargs):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.

        :param email: User email
        :param password: User password
        :param kwargs: Extra args
        :return: User's model instance

        """
        account = self.create_user(email, password, **kwargs)
        account.is_staff = True
        account.is_superuser = True
        account.save()
        return account


class Account(auth_models.AbstractBaseUser, auth_models.PermissionsMixin):
    """
    Custom User model which inherits from AbstractBaseUser

    """
    email = models.EmailField(unique=True)
    first_name = models.CharField(verbose_name=_('first name'), max_length=50, blank=True)
    last_name = models.CharField(verbose_name=_('last name'), max_length=50, blank=True)
    phone_number = models.CharField(verbose_name=_('phone number'), max_length=20, blank=True)
    is_active = models.BooleanField(verbose_name=_('is active'), default=False)
    is_staff = models.BooleanField(
        verbose_name=_('is staff'), default=False, help_text=_('can login to the django admin.')
    )
    reset_password_key = models.CharField(max_length=40, blank=True, editable=False)
    reset_password_key_expires = models.DateTimeField(null=True, editable=False)
    created_at = models.DateTimeField(verbose_name=_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name=_('updated at'), auto_now=True)
    points = models.PositiveIntegerField(default=0, editable=False)

    objects = AccountManager()
    USERNAME_FIELD = 'email'

    class Meta:
        verbose_name = _('account')

    def __str__(self):
        """
        :return: Email

        """
        return self.email

    def get_full_name(self):
        """
        :return: first_name + last_name

        """
        return '{} {}'.format(self.first_name, self.last_name)

    def get_short_name(self):
        """
        :return: first_name

        """
        return self.first_name

    @property
    def username(self):
        """
        :return: email

        """
        return self.email
