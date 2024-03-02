import base64
import os
import sys
import re
from cs50 import SQL
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordClass:
    def __init__(self) -> None:
        self.key = None
        self.salt = os.urandom(16)
        # Configure CS50 Library to use SQLite database
        self.db = SQL("sqlite:///passwords.db") or None

    # Create Fernet key
    def create_key(self, u_password):
        pass


