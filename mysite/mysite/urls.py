
from django.contrib import admin
from django.urls import path,include
from home import views
from home.views import ChangePasswordView
urlpatterns = [
    path('admin/', admin.site.urls),
    path('',views.home,name='home'),
    path('login',views.login,name='login'),
    path('logout',views.LogoutUser,name='LogoutUser'),
    path('register',views.register,name='register'),
    path('activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',  
        views.activate, name='activate'),  
    path('result',views.CalculateBMI,name='result'),
    path('api/change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('api/password_reset/', include('django_rest_passwordreset.urls', namespace='password_reset')),
    path('forgot-password',views.ForgorPassword,name='forgot-password'),
    path('forgot-password/reset/<str:user>',views.ForgotPasswordReset,name='forgot-password/reset/<str:user>'),
]
