from django.contrib import admin
from .models import Task

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'completed', 'created_at', 'updated_at')
    list_filter = ('completed', 'created_at')
    search_fields = ('title', 'description')
    # ordering = ('-created_at')



# A view in Django is a Python function (or class) that handles HTTP requests and returns HTTP responses.
# FBVs are simple functions that take a request object as input and return a response.
