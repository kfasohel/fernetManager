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
    This class provides functionalities for preserving passwords using strong symmetric encryption and decryption.
    However, for user's password hash asymmetric encryption is used.
    It uses cryptography library and Fernet algorithm for encryption.
    It uses sqlite3 database to preserve data.
    The database is created or connected (if exists) when an instance is created.
    It can be used in both command line and web applications.

    Attributes:
        _salt : randomly generated for each user and stored in db. Length - 16 Bytes.
        _key : generated with user password, salt and Fernet encryption algorithm.
        _userid : Unique id for each user created by the database.
        _logged_in: Boolean value to set or verify user's log in status.
        _dbname : to set or change database file name. Default is: "fernets.db".
        _conn: to connect to the database.
        _cur: to create a cursor() to the database.
    Methods:
        __init__(self) -> None: Initiates an object.
        create_tables(self) -> None: to create required tables in the database if not exists.
        close_conn(self) -> None: to close connection to the database.
        def key(self, u_password) -> None: It creates a Fernet key and sets it to the 'key' attribute.
        def check_user(self, u_name, p_hash) -> bool: Check if user exists in the database.
        def add_user(self, u_name, p_hash) -> bool: Adds a new user to the database.
        def set_user(self, u_name) -> bool: Logs in the user.
        def check_site(self, s_name) -> bool: Checks site-name in the database. It can be used before adding a entry.
        def add_entry(self, site_name, site_url, site_username, site_pass) -> bool: Adds an entry to the database.
        def find_entry(self, site_title=None) -> list[any] or None: Finds an entry by site-name and returns as a list.
        def delete_entry(self, site_title=None): Deletes a single entry or all entries of a user based on argument.

    Special Notes: ChatGPT 3.5 and  Gemini chats were utilized for:
         - finding out necessary libraries e.g. 'rich', 'getpass' and their sample usage.
         - debugging when code output was not as expected.
         - to gain knowledge on what various cryptographic terms imply.
    """

    def __init__(self) -> None:
        self._salt = os.urandom(
            16
        )  # To be changed according to logged-in user, internal method only
        self.key = None  # To be created according to logged-in user
        self.userid = None  # To be set according to logged-in user
        self.logged_in = False

        # Connect or create a new database
        self._dbname = "fernets.db"  # database name
        self._conn = sqlite3.connect(
            self._dbname
        )  # creates or connects to db, internal use only
        self._cur = self._conn.cursor()  # Create a cursor object, internal method only
        self.create_tables(self)  # Create required tables in the database if not exists

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
    def key(self, u_password) -> None:
        """
        It creates a Fernet key for encryption and decryption and sets it to the 'key' attribute.
        :param u_password: str, users password which is an element necessary for creation of a Fernet key.
        :return: None.
        """
        if u_password:
            u_password_bytes = u_password.encode("utf-8")
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
        """
        It is a static method.
        It creates two tables if not already exist.
        :param self: self is passed from __init__ method to execute this static method.
        :return: None
        """
        self._cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                username TEXT,
                salt BLOB,
                hash TEXT
            )
        """
        )

        # Create passwords table
        self._cur.execute(
            """
            CREATE TABLE IF NOT EXISTS passwords (
                pid INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                uid INTEGER NOT NULL,
                site_name TEXT,
                site_url TEXT,
                site_username TEXT,
                site_pass_encrypted BLOB,
                FOREIGN KEY(uid) REFERENCES users (id)
            )
        """
        )
        self._conn.commit()
        printc("[green][+][/green] Database ready")

    def close_conn(self) -> None:
        """Terminates cursor and connection to the database"""
        self._cur.close()
        self._conn.close()
        printc("[green][+][/green] Database connection termination successful")

    def check_user(self, u_name, p_hash) -> bool:
        """Check if u_name(username) exists in the database"""
        supplied_data = [
            u_name,
        ]
        u_name_found = self._cur.execute(
            "SELECT username FROM users WHERE username = ?", supplied_data
        ).fetchone()
        if u_name_found:
            p_hash_match = self._cur.execute(
                "SELECT hash FROM users WHERE username = ?", supplied_data
            ).fetchone()
            if p_hash == p_hash_match[0]:
                return True
        return False

    def add_user(self, u_name, p_hash) -> bool:
        """
        Adds new user to the database
        :param u_name: str, name of the user to add.
        :param p_hash: str, string representation of asymmetric hash created by hashlib.sha256
        :return:
        """
        u_name = u_name.capitalize()
        query = "SELECT username FROM users WHERE username = ?"
        data_to_check = [
            u_name,
        ]
        if not self._cur.execute(query, data_to_check).fetchone():
            data_query = "INSERT INTO users (username, hash, salt) VALUES (?, ?, ?)"
            data_to_insert = [u_name, p_hash, self._salt]
            self._cur.execute(data_query, data_to_insert)
            self._conn.commit()
            return True
        return False

    def set_user(self, u_name) -> bool:
        """
        Logs in the user for later operations.
        :param u_name: str, the name of the user to be logged in.
        :return: True/False, based on teh success/failure of the operation.
        """
        u_name = u_name.capitalize()
        query = "SELECT id FROM users WHERE username = ?"
        data_to_check = [
            u_name,
        ]
        user_id_from_db = self._cur.execute(query, data_to_check).fetchone()
        if user_id_from_db:
            self.userid = user_id_from_db[0]
            query = "SELECT salt FROM users WHERE id = ?"
            data_to_insert = [
                self._userid,
            ]
            self._salt = self._cur.execute(query, data_to_insert).fetchone()[0]
            self._logged_in = True  # Will be checked while encrypting and decrypting
            printc(f"\nWelcome [bold green]{u_name}[/bold green].")
            return True
        return False

    def check_site(self, s_name) -> bool:
        """
        Check site-name in the database to avoid duplicate entry while adding entry.
        :param s_name: str, title of the site to check.
        :return: True/False, based on teh success/failure of the operation.
        """
        supplied_data = [
            self.userid,
            s_name,
        ]
        s_name_found = self._cur.execute(
            "SELECT site_name FROM passwords WHERE uid = ? AND site_name = ?",
            supplied_data,
        ).fetchall()
        if s_name_found:
            return True
        return False

    def add_entry(self, site_name, site_url, site_username, site_pass) -> bool:
        """
        Adds password entry details to the database
        :param site_name: str, title of the site to add.
        :param site_url: str, url of the site (optional)
        :param site_username: str, username for the website (optional)
        :param site_pass: bytes, encrypted password as bytes object.
        :return: True/False, based on teh success/failure of the operation.
        """
        site_name = site_name.capitalize()
        if self._logged_in:
            site_pass_encrypted = self._key.encrypt(site_pass.encode())
            query = "INSERT INTO passwords (uid, site_name, site_url, site_username, site_pass_encrypted) VALUES (?, ?, ?, ?, ?)"
            data_to_insert = [
                self.userid,
                site_name,
                site_url,
                site_username,
                site_pass_encrypted,
            ]
            self._cur.execute(query, data_to_insert)
            self._conn.commit()
            return True
        return False

    def find_entry(self, site_title=None) -> list[any] or None:
        """
        Finds an entry in the database based on site_title given by the user.
        Returns the found entry or all the entries if site_title is not given.
        Site passwords are decrypted to plain text while returning.
        :param site_title: str, title of the site to delete.
        :return: a list containing all the names found in the database or None if nothing is found.
        """
        if self._logged_in:
            if not site_title:
                query = "SELECT site_name, site_url, site_username, site_pass_encrypted FROM passwords WHERE uid = ?"
                data_to_put = [
                    self.userid,
                ]
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
        """
        Deletes a single entry if site_title is given or all entries if no title is provided
        :param site_title: str, title of the site to delete.
        :return: True/False according to the success of the database operation.
        """
        if self._logged_in:
            if not site_title:
                query = "DELETE FROM passwords WHERE uid = ?"
                data_to_put = [
                    self.userid,
                ]
            else:
                site_title = site_title.capitalize()
                query = "DELETE FROM passwords WHERE uid = ? AND site_name = ?"
                data_to_put = [self.userid, site_title]
            self._cur.execute(query, data_to_put)
            self._conn.commit()
            return True
        return False
