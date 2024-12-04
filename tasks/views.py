from django.shortcuts import render, get_object_or_404, redirect
from .models import Task
from .forms import TaskForm
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.contrib import messages
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import JsonResponse
from .serializers import TaskSerializer
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings


# Registration view
def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Check if username already exists
        if User.objects.filter(username=username).exists():
            return render(request, 'tasks/register.html', {'error': 'Username already exists'})

        # Create the user
        user = User.objects.create_user(username=username, password=password)

        # Generate a token for the user
        Token.objects.get_or_create(user=user)

        return redirect('login')  # Redirect to login after registration

    return render(request, 'tasks/register.html')
# Login view
# Modify the login view to issue a token
def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)  # Create session for the user
            # Issue a token for API use
            token, _ = Token.objects.get_or_create(user=user)
            if request.content_type == 'application/json':  # If API client
                return JsonResponse({'token': token.key}, status=200)
            else:
                return redirect('task_list')  # Redirect to task list for web clients
        else:
            error = 'Invalid credentials'
            if request.content_type == 'application/json':  # If API client
                return JsonResponse({'error': error}, status=401)
            else:
                return render(request, 'tasks/login.html', {'error': error})
    return render(request, 'tasks/login.html')

def user_logout(request):
    logout(request)
    messages.success(request, "You have logged out successfully.")  # Optional: Success message
    return redirect('login')

# Task list view (only shows tasks of the logged-in user)
def task_list(request):
    if request.user.is_authenticated:
        tasks = Task.objects.filter(user=request.user)  # Filter tasks by logged-in user
        return render(request, 'tasks/task_list.html', {'tasks': tasks})
    return redirect('login')  # Redirect to login if not authenticated

# API to list tasks (only accessible to authenticated users)
@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def task_list_api(request):
    tasks = Task.objects.filter(user=request.user)  # Only show tasks of the logged-in user
    serializer = TaskSerializer(tasks, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

# API to create a new task (only accessible to authenticated users)
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def task_create_api(request):
    serializer = TaskSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(user=request.user)  # Link task to logged-in user
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# User login to generate token
@api_view(['POST'])
def login_api(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)

    if user:
        token, _ = Token.objects.get_or_create(user=user)
          # Print the token to the console for debugging
        print(f"Generated token for user {user.username}: {token.key}")
        return Response({'token': token.key}, status=status.HTTP_200_OK)
    return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

# User logout to delete token
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def logout_api(request):
    try:
        # Get token from the Authorization header
        token = Token.objects.get(user=request.user)
        
        # Delete the token explicitly to log out the user
        token.delete()

        return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)
    except Token.DoesNotExist:
        return Response({'error': 'Token not found'}, status=status.HTTP_400_BAD_REQUEST)

#password reset request
@api_view(['POST'])
def password_reset_request(request):
    email = request.data.get('email')
    user = User.objects.filter(email = email).first()
    if user:
        token = PasswordResetTokenGenerator().make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = f"http://yourdomain.com/reset_password/{uid}/{token}/"
        send_mail(
            'Password Reset Request',
            f'Click the link to reset your password: {reset_link}',
            'from@example.com',
            [email],
            fail_silently=False,
        )
        return Response({'message': 'Password reset link sent to email.'}, status=status.HTTP_200_OK)
    return Response({'error': 'Email not registered.'}, status = status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def password_reset_confirm(request, uidb64, token):
    new_password = request.data.get('new_password')
    user_id = force_str(urlsafe_base64_decode(uidb64))
    user = User.objects.get(pk=user_id)

    if PasswordResetTokenGenerator().check_token(user,token):
        user.set_password(new_password)
        user.save()
        return Response({'message': 'Password reset succesfully'}, status=status.HTTP_200_OK)
    return Response({'error': 'Invalid or expired token.'}, status = status.HTTP_400_BAD_REQUEST)


# Views for task CRUD operations (unchanged)
@login_required
def add_task(request):
    if request.method == 'POST':
        form = TaskForm(request.POST)
        if form.is_valid():
            task = form.save(commit=False)
            task.user = request.user  # Ensure the task is linked to the logged-in user
            task.save()
            messages.success(request, "Task added successfully")
            return redirect('task_list')
    else:
        form = TaskForm()

    return render(request, 'tasks/task_form.html', {'form': form})

@login_required
def update_task(request, task_id):
    task = get_object_or_404(Task, id=task_id)
    if request.method == 'POST':
        form = TaskForm(request.POST, instance=task)
        if form.is_valid():
            form.save()
            return redirect('task_list')
    else:
        form = TaskForm(instance=task)
    return render(request, 'tasks/task_form.html', {'form': form, 'task': task})

@login_required
def delete_task(request, task_id):
    task = get_object_or_404(Task, id=task_id)
    task.delete()
    messages.success(request, "Task deleted successfully")
    return redirect('task_list')

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def update_profile(request):
    user = request.user
    user.first_name = request.data.get('first_name', user.first_name)
    user.last_name = request.data.get('last_name', user.last_name)
    user.profile.gender = request.data.get('gender', user.profile.gender)
    user.profile.profession = request.data.get('profession', user.profile.profession)
    user.save()
    user.profile.save()
    return Response({'message': 'Profile updated successfully.'}, status=status.HTTP_200_OK)

@login_required
def profile(request):
    if request.method == 'POST':
        # Update user profile
        user = request.user
        user.first_name = request.POST.get('first_name', user.first_name)
        user.last_name = request.POST.get('last_name', user.last_name)
        user.profile.gender = request.POST.get('gender', user.profile.gender)
        user.profile.profession = request.POST.get('profession', user.profile.profession)
        user.profile.save()
        user.save()
        messages.success(request, 'Profile updated successfully.')
        return redirect('profile')
    
    return render(request, 'tasks/profile.html', {'user': request.user})