from django.urls import path
from . import views
from .views import password_reset_request, password_reset_confirm,update_profile

urlpatterns = [
    # Redirect root URL to register page
    path('', views.register, name='register'),

    # Regular views
    path('login/', views.user_login, name='login'),  # Correct URL pattern for login
    path('register/', views.register, name='register'),
    path('tasks/', views.task_list, name='task_list'),
    path('tasks/add/', views.add_task, name='add_task'),
    path('tasks/<int:task_id>/edit/', views.update_task, name='update_task'),
    path('tasks/<int:task_id>/delete/', views.delete_task, name='delete_task'),
    path('password_reset/',password_reset_request, name = 'password_reset'),
    path('reset_password/<uidb64>/<token>/', password_reset_confirm, name='password_reset_confirm'),
    path('profile/', update_profile, name='profile'),
    path('logout/', views.user_logout, name = 'logout'),


    # API views
    path('api/tasks/', views.task_list_api, name='task_list_api'),
    path('api/tasks/create/', views.task_create_api, name='task_create_api'),
    path('api/login/', views.login_api, name='login_api'),
    path('api/logout/', views.logout_api, name='logout_api'),
]
