from django.db import models
from django.dispatch import receiver
from django.urls import reverse
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.mail import send_mail  
import requests
# from views import ForgotPasswordReset
# from home import views

# Create your models here.
class UserData(models.Model):
    user_id = models.CharField(max_length=255)
    user_pass = models.TextField()
    is_active = models.BooleanField(default=False)
    # personal details
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    gender = models.CharField(max_length=255)
    height = models.CharField(max_length=255)
    weight = models.CharField(max_length=255)
    def __str__(self):
        return '%s' % (self.user_id)
    
class ResetToken(models.Model):
    user_id = models.CharField(max_length=255)
    token = models.CharField(max_length=255)
    hash_pass = models.TextField(default='')
    def __str__(self):
        return '%s' % (self.user_id)




    # print(response.json())