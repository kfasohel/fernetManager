import getpass
import hashlib
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
        self._salt = os.urandom(16)  # To be changed according to logged-in user
        self._key = None # To be created according to logged-in user
        self._userid = None # To be set according to logged-in user
        self._logged_in = False

        # Connect or create a new database
        self._dbname = "fernets.db"
        self._conn = sqlite3.connect(self._dbname) # create or connect to db
        self._cur = self._conn.cursor()
        self.create_tables(self)

    @property
    def salt(self):
        return self._salt

    @salt.setter
    def salt(self, salt):
        print("Not allowed!")

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, u_password):
        u_password_bytes = u_password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=480000,
        )
        self._key = Fernet(base64.urlsafe_b64encode(kdf.derive(u_password_bytes)))
        print("Key created")


    @property
    def userid(self):
        return self._userid

    @userid.setter
    def userid(self, user_id):
        self._userid = user_id

    @staticmethod
    def create_tables(self):
        # Create users table
        self._cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                username TEXT,
                hash TEXT,
                salt BLOB
            )
        """)

        # Create passwords table
        self._cur.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                pid INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                uid INTEGER NOT NULL,
                site_name TEXT,
                site_url TEXT,
                sit_pass_encrypted BLOB,
                FOREIGN KEY(uid) REFERENCES users (id)
            )
        """)
        self._conn.commit()
        print("Database ready")

    @property
    def dbname(self):
        return self._dbname

    # Close sqlite3 database connection
    def close_conn(self):
        self._cur.close()
        self._conn.close()
        print("Database connection termination successful")

    # Add user ? the user database should be handled by app.py
    def add_user(self, u_name, p_hash):
        query = "SELECT username FROM users WHERE username = ?"
        data_to_check = [u_name,]
        if not self._cur.execute(query, data_to_check).fetchone():
            data_query = "INSERT INTO users (username, hash, salt) VALUES (?, ?, ?)"
            data_to_insert = [u_name, p_hash, self._salt]
            self._cur.execute(data_query, data_to_insert)
            self._conn.commit()
            print("User added")
            return True
        print("Username already taken!")
        return False

    def set_user(self, u_name):
        query = "SELECT id FROM users WHERE username = ?"
        data_to_check = [u_name,]
        user_id_from_db = self._cur.execute(query, data_to_check).fetchone()
        if user_id_from_db:
            self._userid = user_id_from_db[0]
            query = "SELECT salt FROM users WHERE id = ?"
            data_to_insert = [self._userid,]
            self._salt = self._cur.execute(query, data_to_insert).fetchone()[0]
            print(self._salt) # For testing
            passwd = getpass.getpass("Enter you encryption password: ")  #This password can be different and not stored.
            self.key = passwd # To call the setter method
            self._logged_in = True # Will be checked while encrypting and decrypting
            print("User set")
            return True
        print("User data does not match!")
        return False

    # Add entry
    def add_entry(self, site_name, site_pass, site_url):
        site_pass_encrypted = self._key(site_pass)





username = input("Username: ")
password = getpass.getpass("Password: ")
pass_hash = hashlib.sha256(password.encode()).hexdigest()


pc = PasswordClass()
pc.add_user(username, pass_hash)
pc.set_user(username)
pc.close_conn()
