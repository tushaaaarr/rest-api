from django.contrib import admin
from home.models import UserData,ResetToken
# Register your models here.

admin.site.register(UserData)
admin.site.register(ResetToken)
