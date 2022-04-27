from django.http import HttpResponse
from django.shortcuts import render,redirect,HttpResponse
from home.models import UserData,ResetToken
import hashlib
from django.contrib.sites.shortcuts import get_current_site  
from django.utils.encoding import force_bytes, force_text  
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode  
from django.template.loader import render_to_string  
from home.tokens import account_activation_token  
from django.contrib.auth.models import User  
from django.core.mail import EmailMessage 
from django.core import mail
from django.conf import settings
import datetime 
import requests
import json
from rest_framework import status
from rest_framework import generics
from rest_framework.response import Response
from django.contrib.auth.models import User
from .serializers import ChangePasswordSerializer
from rest_framework.permissions import IsAuthenticated   
from django.dispatch import receiver
from django.urls import reverse
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.mail import send_mail  
import requests
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,logout
from django.contrib.auth import authenticate, login as dj_login

def home(request):
    # if request.session.get('user') == None:
    #     return redirect('/login')
    if request.user.is_authenticated:
        context = {}
        user = str(request.user)
        # Submit Form
        if request.POST:   
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            gender = request.POST.get('gender')
            height = request.POST.get('height')
            weight = request.POST.get('weight')
            if UserData.objects.filter(user_id=user).exists():
                # Update db values
                UserData.objects.filter(user_id = user).update(
                first_name = first_name,last_name=last_name,gender=gender,height=height,weight=weight
                )
                return redirect('/result')
        
        try:
            user_ob = UserData.objects.get(user_id = user)
            context['user_id'] = user
            context['first_name'] = user_ob.first_name 
            context['last_name'] = user_ob.last_name
            context['gender'] = user_ob.gender
            context['height'] = user_ob.height       
            context['weight'] = user_ob.weight
        except:
            pass
        return render(request,'home.html',
        {'context':context})

    else:
        return redirect('/login')

def CalculateBMI(request):
    if request.user.is_authenticated:
        user = str(request.user)
        context = {}
        user_ob = UserData.objects.get(user_id = user)
        height= user_ob.height       
        weight= user_ob.weight
        result = float(weight)/(float(height)*float(height))
        context['result'] = str(result)
        # Sending Analysis of person’s BMI, date of BMI calculation.
        mail_from = settings.SMTP_HOST_USER
        mail_to = user
        current_site = get_current_site(request)  
        mail_subject = ''  
        message = render_to_string('user_details.html', {  
            'username': user,  
            'name': str(user_ob.first_name) + str(' ') + str(user_ob.last_name),
            'bmi':result,
            'time':datetime.datetime.now().date(),
            'gender':user_ob.gender,
        })  
        to_email = mail_to  
        email = EmailMessage(  
                    mail_subject, message, to=[to_email]  
        )  
        email.content_subtype = 'html'
        email.send()  
        return render(request,'result.html',{'context':context})
    else:
        return redirect('/login')

def login(request):
    context = {}
    if request.POST:
        user_name = request.POST.get('user_email')
        user_pass = request.POST.get('user_pass')

        # Checking user pass
        if UserData.objects.filter(user_id=user_name).exists():
            ob = UserData.objects.get(user_id = user_name)
            ob_user_name = ob.user_id
            ob_user_pass = ob.user_pass
            # comparing user pass
            if user_pass != str(ob_user_pass):
                context['message'] = 'Incorrect Password '
            else:
                # session_data = {
                # 'user_name': user_name,
                # 'status': 1,
                # }
                # request.session['user'] = session_data
                user = authenticate(username=user_name, password=user_pass)
                if user is not None:
                    dj_login(request, user)
                    return redirect('/')
        else:
            context['message'] = 'User Not Found'

    return render(request,'auth/login.html',{'context':context})

def LogoutUser(request):
    # request.session.clear()
    logout(request)
    return redirect('/login')

def register(request):
    context = {}
    if request.POST:
        user_name = request.POST.get('user_email')
        user_pass1 = request.POST.get('user_pass1')
        user_pass2 = request.POST.get('user_pass2')
        try:
            user= User.objects.get(username=user_name)
            context['message'] = 'Already user found'
        except:
            if user_pass1 != user_pass2:
                context['message'] = 'Password not matched'
            # hashed_pass = getHash(user_pass)
            else:
                # Store User Details in Db
                user = User.objects.create_user(username = user_name, password = user_pass1)
                user.email = user_name
                user.save()
                UserData(user_id = user_name, 
                            user_pass = user_pass1
                    ).save()    
                user = UserData.objects.get(user_id=user_name)
                user.is_active = False  
                mail_from = settings.SMTP_HOST_USER
                mail_to = user_name
                current_site = get_current_site(request)  
                print()
                mail_subject = 'Activation link has been sent to your email id'  
                message = render_to_string('email_page.html', {  
                    'username': user.user_id,  
                    'domain': current_site.domain,  
                    'uid':urlsafe_base64_encode(force_bytes(user.pk)),  
                    'token':account_activation_token.make_token(user),  
                })  
                to_email = mail_to  
                email = EmailMessage(  
                            mail_subject, message, to=[to_email]  
                )  
                email.content_subtype = 'html'
                email.send()  
                return HttpResponse('Activation link has been sent to your email id... Please check your email inbox')

    return render(request,'auth/register.html',{'context':context})

def getHash(raw_pass):
    hash_pass = hashlib.md5(raw_pass.encode('utf-8'))
    hash_pass = hash_pass.hexdigest()
    return hash_pass

def activate(request, uidb64, token):    
    try:  
        uid = force_text(urlsafe_base64_decode(uidb64))  
        user = UserData.objects.get(pk=uid)  
    except(TypeError, ValueError, OverflowError, UserData.DoesNotExist):  
        user = None  
    if user is not None and account_activation_token.check_token(user, token):  
        user.is_active = True  
        user.save()  
        return render(request,'success_email.html')  
        
    else:  
        return HttpResponse('Activation link is invalid!')  
    
def ForgorPassword(request):
    context = {}
    if request.POST:
        user_email= request.POST.get('user_email')
        try:
            User.objects.get(username=user_email)
            url = 'http://127.0.0.1:8000/api/password_reset/'
            body = {
            "email": user_email
                }
            res = requests.post(url,data =body)
            # if status is okay
            if res.status_code == 200:
                obj, created = ResetToken.objects.update_or_create(
                user_id=user_email)
                return redirect(f"forgot-password/reset/{user_email}")
            else:
                context['message'] = res.content.decode('utf-8')
        except:
            context['message'] = 'User Not Found'
    return render(request,'auth/forgot-password.html',{'context':context})

def PasswordReset(request):
    return render(request,'auth/password-reset.html')

# Updating new token 
@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):
    obj, created = ResetToken.objects.update_or_create(
        user_id=reset_password_token.user.email
        )
    ResetToken.objects.filter(user_id = reset_password_token.user.email).update(token = reset_password_token.key)
   
def ForgotPasswordReset(request,user):
    context = {}
    ob = ResetToken.objects.get(user_id = user)
    context['user_id'] = user
    if request.POST:
        user_pass1 =request.POST.get('user_pass1') 
        user_pass2 =request.POST.get('user_pass2') 
        if user_pass1 != user_pass2:
            context['message'] = 'Password not matched'
        url = 'http://127.0.0.1:8000/api/password_reset/confirm/'
        body = {
                "token":ob.token,
                "password":user_pass1
                }
        response = requests.post(url, data = body)
        print(response.json())
        if response.status_code != 200:
            context['message'] = response.content.decode('utf-8')
        else:
            context['message'] = 'Your Password is Upadated Successfully ... Try to login.'
            return redirect('/login')
    return render(request,'auth/reset-password.html',{'context':context})

class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)
    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }
            return Response(response)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




