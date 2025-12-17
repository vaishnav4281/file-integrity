import os
from django.core.wsgi import get_wsgi_application

# Ensure this matches your actual project name
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'file_integrity.settings')

application = get_wsgi_application()

# ADD THIS LINE - Vercel looks for 'app' specifically
app = application 

