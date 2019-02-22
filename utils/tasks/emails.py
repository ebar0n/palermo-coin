# -*- coding: utf-8 -*-
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string

from api.celery import app


@app.task(name='send_mail')
def send_mail(recipient_list, subject, template_name, data):
    """
    Just send an email with Sparkpost (Sparkpost Template)

    :param subject: str
    :param recipient_list: list
    :param template_name: str
    :param data: dict
    :return:

    """

    html_content = render_to_string('emails/' + template_name, data)
    msg = EmailMultiAlternatives(subject, '', settings.DEFAULT_FROM_EMAIL, recipient_list)
    msg.attach_alternative(html_content, 'text/html')
    msg.send()
