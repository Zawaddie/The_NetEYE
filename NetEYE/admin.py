from django.contrib import admin

# Register your models here.

from NetEYE.models import MpesaPayments, mpesaRequest


admin.site.register(MpesaPayments)
admin.site.register(mpesaRequest)