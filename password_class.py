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
        self._dbname = "fernets.db"
        if not self.database_exists(self):
            self.create_tables(self)
        self._conn = sqlite3.connect(self._dbname)
        self._cur = self._conn.cursor()

    @property
    def key(self):
        return self._key

    @property
    def salt(self):
        return self._salt

    @staticmethod
    def database_exists(self) -> bool:
        """
        Check if a database file exists in the same folder as the Python file.
        Parameters:
        - filename: The name of the database file to check.
        Returns:
        - True if the database file exists, False otherwise.
        """
        current_dir = os.path.dirname(os.path.abspath(__file__))  # Get the directory of the Python script
        print(current_dir)  # For testing
        db_path = os.path.join(current_dir, self._dbname)  # Construct the full path to the database file
        return os.path.exists(db_path)  # Check if the file exists

    @staticmethod
    def create_tables(self):
        self._conn = sqlite3.connect(self._dbname)
        self._cur = self._conn.cursor()

        # Create users table
        self._cur.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                username TEXT,
                hash TEXT,
                salt TEXT
            )
        """)

        self._cur.execute("""
            CREATE TABLE passwords (
                pid INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                uid INTEGER NOT NULL,
                site TEXT,
                encrypted_pass BLOB,
                FOREIGN KEY(uid) REFERENCES users (id)
            )
        """)
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

pc = PasswordClass()
print(pc.dbname)
pc.close_conn()
