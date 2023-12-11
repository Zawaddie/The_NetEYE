from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'), 
    path('login/',views.login_user, name='login'),  
    path('signup/', views.signup, name='signup'), 
    path('logout/', views.user_logout, name='logout'), 
    path('dashboard/', views.dashboard, name='dashboard'),  
    path('features/', views.features, name='features'), 
    path('services/', views.services, name='services'),
    path('subscription/', views.subscription, name='subscription'),
    path('payment/', views.payment, name='payment'),
     path('settings/', views.settings, name='settings'),
    path('update_chart_data/', views.update_chart_data, name='update_chart_data'),
    path('mpesa-callback/', views.stk_callback, name='update_chart_data'),
]

