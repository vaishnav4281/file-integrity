#!/bin/bash
echo "Building the project..."
python3 -m pip install -r requirements.txt

echo "Collecting static files..."
# This will now use the new STATIC_ROOT (staticfiles_build)
python3 manage.py collectstatic --noinput --clear

echo "Build process completed."
