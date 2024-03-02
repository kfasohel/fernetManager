import sqlite3
import base64
import os
import sys
import re

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PasswordClass:

    def __init__(self) -> None:
        self._key = None
        self._salt = os.urandom(16)

        # Connect or create a new database
        self._dbname = "users.db"
        if not self.database_exists(self._dbname):
            self.create_tables()
        self._conn = sqlite3.connect(self._dbname)
        self._cur = self._conn.cursor()

    @property
    def key(self):
        return self._key

    @property
    def salt(self):
        return self._salt

    @staticmethod
    def database_exists(self: object, dbname: str) -> bool:
        """
        Check if a database file exists in the same folder as the Python script.
        Parameters:
        - filename: The name of the database file to check.
        Returns:
        - True if the database file exists, False otherwise.
        """
        current_dir = os.path.dirname(os.path.abspath(__file__))  # Get the directory of the Python script
        print(current_dir)  # For testing
        db_path = os.path.join(current_dir, dbname)  # Construct the full path to the database file
        return os.path.exists(db_path)  # Check if the file exists

    def create_tables(self):
        self._conn = sqlite3.connect(self._dbname)
        self._cur = self._conn.cursor()
        # TODO : Create two tables
        self.close_conn()

    @property
    def dbname(self):
        return self._dbname

    # Close sqlite3 database connection
    def close_conn(self):
        self._conn.commit()
        self._conn.close()

    # Create Fernet key
    def create_key(self, u_password):
        pass

# pc = PasswordClass()
# print(pc.db)
# pc.close_conn()
