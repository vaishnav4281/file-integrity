
from django.db import models

class IntegrityProfile(models.Model):
    file_name = models.CharField(max_length=255)
    file_size = models.BigIntegerField()
    full_hash = models.CharField(max_length=64)  # SHA256 hex digest
    chunk_hashes = models.JSONField()  # List of chunk hashes
    chunk_entropies = models.JSONField(default=list) # List of chunk entropies (float)
    file_header = models.CharField(max_length=64, default="") # First 16-32 bytes in Hex
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.file_name} ({self.created_at})"
