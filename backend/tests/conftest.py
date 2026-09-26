import os

# API tests call endpoints directly; sign-in itself is covered in test_auth.py
os.environ.setdefault("LOGVAULT_AUTH", "false")
