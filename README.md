# MY PASSWORDS
### Video Demo:  https://youtu.be/7Ky0I8l5U1Y
## Description:
-   It is basically a command line software created using python and sqlite database program.
-   The main purpose of this software is to safe-keep user's passwords for different websites by encrypting them and storing them in a secured way along with other details.
-   The software is designed in such a way that it can also be used with python-based web frameworks with minor tweaks.

### Special Thanks to ChatGPT 3.5 and Gemini, which were used for:
- Finding out necessary libraries e.g. 'rich, 'getpass' etc. and their sample usage.
- Debugging/asking questions when code output was not as expected.
- To gain knowledge on various cryptographic terms and ideas.

## Basic Structure:
-   The software consists of a python class file, another python file, and an sqlite database file.
-   The class file named 'password_class.py' has most of the functionality including database creation/connection, adding user, adding entry, finding entry, deleting entry etc.
-   The other file named 'my_passwords.py' manages the whole program superficially with the class file as its base. It almost has identical functions to manage the program superficially with setting attributes or method calls to the class object.
-   The sqlite database named 'fernets.db' has two tables, users and passwords. Basically, the login data is saved in 'users' table. Passwords and other website related data are stored in the 'passwords' table.

    ### password_class.py:
    - This class provides functionalities for preserving passwords using strong symmetric encryption and decryption.
    - However, for user's password hash asymmetric encryption is used.
    - It uses cryptography library and Fernet algorithm for encryption.
    - It uses sqlite3 database to preserve data.
    - The database is created or connected (if exists) when an instance is created.
    - It can be used in both command line and web applications.

        ### Attributes:
        - **_salt**: Randomly generated for each user and stored in db. Length is 16 Bytes.
        - **_key**: Generated with user password, salt and Fernet encryption algorithm.
        - **_userid**: Unique id for each user created by the database.
        - **_logged_in**: Boolean value to set or verify user's log in status.
        - **_dbname**: To set or change database file name. Default is: "fernets.db".
        - **_conn**: To connect to the database.
        - **_cur**: To create a cursor() to the database.
      
        ### Methods:
        - **__init__(self) -> None**: Initiates an object.
        - **create_tables(self) -> None**: It creates required tables in the database if not exists.
        - **close_conn(self) -> None**: It closes connection to the database.
        - **key(self, u_password) -> None**: It creates a Fernet key and sets it to the 'key' attribute.
        - **check_user(self, u_name, p_hash) -> bool**: It checks if user exists in the database.
        - **add_user(self, u_name, p_hash) -> bool**: It adds a new user to the database.
        - **set_user(self, u_name) -> bool**: It logs in the user.
        - **check_site(self, s_name) -> bool**: It checks only the site-name in the database before adding an entry.
        - **add_entry(self, site_name, site_url, site_username, site_pass) -> bool**: It adds an entry to the database.
        - **find_entry(self, site_title=None) -> list[any] or None**: It finds an entry or all the entries by site-name and returns as a list with decrypted password and other data.
        - **delete_entry(self, site_title=None)**: It deletes a single entry or all entries of a user based on provided argument.
    
    ### my_passwords.py:
   - This file acts as the front end of the software. It interacts with the user and performs the tasks with the help of the password class.
   - Besides the main function, this file has ten other functions:
     - **choice_group_one() -> None**: Offers the user with login, register and quit options.
     - **register()**: Registers the user into the database. Saves username and hashed password for future login.
     - **login**: Logs in the user after validating data stored in the database.
     - **choice_group_two() -> None**: Provides the user with adding, finding, deleting entries and logout and quit options.
     - **get_data() -> list**: Gets site related data from user to add an entry in the database.
     - **find_data() -> None**: Finds data in the database using site name as search-term for the logged-in user. Calls display_data() if data is found.
     - **find_all() -> None**: Finds all data of the logged-in user in the database. Calls display_data() if data is found.
     - **display_data(data) -> None**: Prints the data received as argument on the screen in a table format.
     - **delete_data() -> None**: Deletes a single entry from the database based on user input.
     - **delete_all() -> None**: Deletes all the entries for the logged-in user based on user confirmation.

   
## How to use:
- On opening the software, the user will be offered with the 'choice_group_one' which will offer 3 choices: Login, Register and Quit. The number or letter in the brackets to be entered as choice.
- For the first use, 'Register' has to be chosen and on-screen instructions to be followed.
- After register, the first choice group will reappear. Now 'Login' can be chosen or 'Quit'.
- If 'Login' is chosen, on-screen instructions to be followed to complete the process.
- If successfully logged in, the user will be presented with 'choice_group_two' where entry-related options e.g., adding, finding, deleting etc. will be offered.
- The numbers or letters in the preceding bracket for each choice to be entered in the prompt.
- After finishing the intended tasks, the user can either choose 'Log out' or 'Quit'.
- 'Log out' will roll the user to 'choice_group_one' again. Here 'Login' or 'Register' as a different user is possible.
- 'Quit' in both choice groups will quit the software.
  

## Precautions:
- For personal use, it has to be ensured that the 'fernets.db' i.e., the database file is not deleted or tempered with. In that case, the stored data can be lost partially or completely.

## Testing the Program:
- All the functions of the software were tested by me number of times over the span of a few days to come up with the solutions for contingencies. Nonetheless, further testing is always encouraged for bug finding and fixing.

## Conclusion:
- I have enjoyed making this software as much as I enjoyed taking the course 'CS50x'. I learned a great deal from this course. My special thanks to Prof. David J. Malan and his esteemed team for presenting the world with this wonderful opportunity for learning Computer Science and Programming.
