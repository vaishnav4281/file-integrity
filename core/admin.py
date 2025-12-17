
from django.contrib import admin
from .models import IntegrityProfile

@admin.register(IntegrityProfile)
class IntegrityProfileAdmin(admin.ModelAdmin):
    list_display = ('file_name', 'file_size', 'created_at')
    readonly_fields = ('full_hash', 'chunk_hashes', 'created_at')
