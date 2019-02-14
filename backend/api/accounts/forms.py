# -*- coding: utf-8 -*-
from django import forms
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import ugettext as _

from accounts.models import Account


class AccountChangeForm(forms.ModelForm):
    set_password = False

    class Meta:
        model = Account
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super(AccountChangeForm, self).__init__(*args, **kwargs)
        self.fields['password'].help_text = _(
            'Raw passwords are not stored, '
            'so there is no way to see this user\'s password. '
            'Fill in this field, if you want to assign a new password.'
        )
        self.fields['password'].widget = forms.PasswordInput()
        if self.instance.pk:
            self.fields['password'].required = False

    def clean_password(self):
        password = self.cleaned_data.get('password')
        if password:
            validate_password(password, None)
            self.set_password = True
        elif self.instance.pk:
            password = self.instance.password
        return password

    def save(self, commit=True):
        if self.set_password:
            self.instance.set_password(self.cleaned_data.get('password'))
        return super(AccountChangeForm, self).save(commit=commit)
