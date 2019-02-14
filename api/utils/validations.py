# -*- coding: utf-8 -*-
import re

from django.utils.translation import ugettext as _


def validate_password(password):
    """
    Validate whether the password meets all validator requirements.
    If the password is valid, return ``None``.
    If the password is invalid, raise ValidationError with all error messages.
    """
    errors = []

    if len(password) < 8:
        errors.append(_('Must be at least 8 characters'))

    if not re.search('[0-9]', password):
        errors.append(_('Must include a number'))

    if not re.search('[A-Z]', password):
        errors.append(_('Must include a capital letter'))

    if not re.search('[^a-zA-Z0-9]', password):
        errors.append(_('Must include a special character'))

    if errors:
        return errors
