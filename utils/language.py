# -*- coding: utf-8 -*-
from django.conf import settings
from django.utils import translation

LANGUAGES = []
for lang in settings.LANGUAGES:
    LANGUAGES.append(lang[0])


def get_language():
    """
    Get language

    """
    lang = translation.get_language()
    if lang in LANGUAGES:
        return lang[:2]
    else:
        return settings.LANGUAGE_CODE[:2]
