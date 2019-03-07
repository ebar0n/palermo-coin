import uuid
from io import BytesIO

import qrcode
from django.core.files import File
from django.db import models
from django.dispatch import receiver
from django.utils.translation import ugettext as _


class Code(models.Model):
	title = models.CharField(max_length=50)
	uuid = models.UUIDField(default=uuid.uuid4, editable=False)
	qr = models.ImageField(upload_to='qr', null=True)
	points = models.PositiveSmallIntegerField()
	expires = models.DateTimeField()
	created_at = models.DateTimeField(verbose_name=_('created at'), auto_now_add=True)
	updated_at = models.DateTimeField(verbose_name=_('updated at'), auto_now=True)

	def __str__(self):
		return '{} - {}'.format(self.title, self.points)


class CodeRedeemed(models.Model):
	account = models.ForeignKey('accounts.Account', on_delete=models.CASCADE)
	code = models.ForeignKey(Code, on_delete=models.CASCADE)
	created_at = models.DateTimeField(verbose_name=_('created at'), auto_now_add=True)

	class Meta:
		unique_together = (('account', 'code'),)



@receiver(models.signals.post_save, sender=Code)
def save_code(sender, instance, created, **kwargs):
	if not instance.qr:
		qr = qrcode.QRCode(
		    version=1,
		    error_correction=qrcode.constants.ERROR_CORRECT_L,
		    box_size=8,
		    border=1,
		)
		qr.add_data(instance.uuid)
		qr.make(fit=True)

		img = qr.make_image()

		blob = BytesIO()
		img.save(blob, 'JPEG')  
		filename = 'code-%s.jpg' % (instance.id)
		instance.qr.save(filename, File(blob)) 
		instance.save()


@receiver(models.signals.post_save, sender=CodeRedeemed)
def save_redeemed(sender, instance, created, **kwargs):
	if created:
		account = instance.account
		account.points += instance.code.points
		account.save()   	


@receiver(models.signals.post_delete, sender=CodeRedeemed)
def delete_redeemed(sender, instance, *args, **kwargs):
	account = instance.account
	account.points -= instance.code.points
	account.save()
