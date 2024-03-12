import sqlite3
import base64
import os
import time

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich import print as printc


class PasswordClass:
    """

    """
    def __init__(self) -> None:
        self._salt = os.urandom(16)  # To be changed according to logged-in user, internal method only
        self.key = None  # To be created according to logged-in user
        self.userid = None  # To be set according to logged-in user
        self.logged_in = False

        # Connect or create a new database
        self._dbname = "fernets.db"
        self._conn = sqlite3.connect(self._dbname)  # create or connect to db, internal method only
        self._cur = self._conn.cursor()  # Create a cursor object, internal method only
        self.create_tables(self) # Create specific tables for the database if not exists

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
        if u_password:
            u_password_bytes = u_password.encode('utf-8')
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self._salt,
                iterations=480000,
            )
            self._key = Fernet(base64.urlsafe_b64encode(kdf.derive(u_password_bytes)))
            print("Key created")
        else:
            printc("[yellow][+][/yellow] Key will be created with password from user")

    @property
    def userid(self):
        return self._userid

    @userid.setter
    def userid(self, user_id):
        self._userid = user_id

    @property
    def logged_in(self):
        return self._logged_in

    @logged_in.setter
    def logged_in(self, value):
        self._logged_in = value

    @property
    def dbname(self):
        return self._dbname

    @dbname.setter
    def dbname(self, value):
        printc("[bold red]Not allowed.")

    @staticmethod
    def create_tables(self) -> None:
        # Create users table
        self._cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                username TEXT,
                salt BLOB,
                hash TEXT
            )
        """)

        # Create passwords table
        self._cur.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                pid INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                uid INTEGER NOT NULL,
                site_name TEXT,
                site_url TEXT,
                site_username TEXT,
                site_pass_encrypted BLOB,
                FOREIGN KEY(uid) REFERENCES users (id)
            )
        """)
        self._conn.commit()
        printc("[green][+][/green] Database ready")

    # Close sqlite3 database connection
    def close_conn(self) -> None:
        self._cur.close()
        self._conn.close()
        printc("[green][+][/green] Database connection termination successful")

    # Add user ? the user database should be handled by app.py
    def add_user(self, u_name, p_hash) -> bool:
        u_name = u_name.capitalize()
        query = "SELECT username FROM users WHERE username = ?"
        data_to_check = [u_name, ]
        if not self._cur.execute(query, data_to_check).fetchone():
            data_query = "INSERT INTO users (username, hash, salt) VALUES (?, ?, ?)"
            data_to_insert = [u_name, p_hash, self._salt]
            self._cur.execute(data_query, data_to_insert)
            self._conn.commit()
            return True
        return False

    # Check if user exists in the database
    def check_user(self, u_name, p_hash):
        supplied_data = [u_name, ]
        u_name_found = self._cur.execute("SELECT username FROM users WHERE username = ?", supplied_data).fetchone()
        if u_name_found:
            p_hash_match = self._cur.execute("SELECT hash FROM users WHERE username = ?", supplied_data).fetchone()
            if p_hash == p_hash_match[0]:
                return True
        return False

    def set_user(self, u_name):
        u_name = u_name.capitalize()
        query = "SELECT id FROM users WHERE username = ?"
        data_to_check = [u_name, ]
        user_id_from_db = self._cur.execute(query, data_to_check).fetchone()
        if user_id_from_db:
            self._userid = user_id_from_db[0]
            query = "SELECT salt FROM users WHERE id = ?"
            data_to_insert = [self._userid, ]
            self._salt = self._cur.execute(query, data_to_insert).fetchone()[0]
            self._logged_in = True  # Will be checked while encrypting and decrypting
            printc(f"\nWelcome [bold green]{u_name}[/bold green].")
            return True
        return False

    # Check site-name in the database to avoid duplicate entry
    def check_site(self, s_name):
        supplied_data = [self.userid, s_name,]
        s_name_found = self._cur.execute("SELECT site_name FROM passwords WHERE uid = ? AND site_name = ?", supplied_data).fetchall()
        if s_name_found:
            return True
        return False


    # Add entry
    def add_entry(self, site_name, site_url, site_username, site_pass):
        site_name = site_name.capitalize()
        if self._logged_in:
            site_pass_encrypted = self._key.encrypt(site_pass.encode())
            query = "INSERT INTO passwords (uid, site_name, site_url, site_username, site_pass_encrypted) VALUES (?, ?, ?, ?, ?)"
            data_to_insert = [self.userid, site_name, site_url, site_username, site_pass_encrypted]
            self._cur.execute(query, data_to_insert)
            self._conn.commit()
            return True
        return False

    def find_entry(self, site_title=None):
        if self._logged_in:
            if not site_title:
                query = "SELECT site_name, site_url, site_username, site_pass_encrypted FROM passwords WHERE uid = ?"
                data_to_put = [self.userid, ]
            else:
                site_title = site_title.capitalize()
                query = "SELECT site_name, site_url, site_username, site_pass_encrypted FROM passwords WHERE uid = ? AND site_name = ?"
                data_to_put = [self.userid, site_title]
            output = self._cur.execute(query, data_to_put).fetchall()
            if output:
                try:
                    output_processed = []
                    for item in output:
                        item = list(item)
                        item[3] = self.key.decrypt(item[3]).decode()
                        output_processed.append(item)
                    return output_processed

                except Exception as e:
                    printc("[bold red]Password error!")  # For debugging
                    time.sleep(1)
                    return
            else:
                return

    def delete_entry(self, site_title=None):
        if self._logged_in:
            if not site_title:
                query = "DELETE FROM passwords WHERE uid = ?"
                data_to_put = [self.userid, ]
            else:
                site_title = site_title.capitalize()
                query = "DELETE FROM passwords WHERE uid = ? AND site_name = ?"
                data_to_put = [self.userid, site_title]
            self._cur.execute(query, data_to_put)
            self._conn.commit()
            return True
        return False
