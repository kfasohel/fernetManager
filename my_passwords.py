import hashlib
import time

from password_class import PasswordClass
from rich import print as printc
from rich.console import Console
from getpass import getpass

# Global variables
pc = PasswordClass()
console = Console()


def main():
    printc("[green]Welcome to your own password manager.")
    logged_check = choice_group_one()
    if logged_check:
        choice_group_two()


# Add register function
def register():
    username = input("Username: ").strip()
    while True:
        password = getpass("Password: ")
        if password == getpass("Retype password: ") and password != "":
            break
        print("Passwords didn't match")
    pass_hash = hashlib.sha256(password.encode()).hexdigest()
    if pc.add_user(username, pass_hash):
        return True
    return False


# Add login function
def login():
    username = input("Username: ").strip()
    while True:
        password = getpass("Password: ")
        if password == getpass("Retype password: ") and password != "":
            break
        print("Passwords didn't match")
    pass_hash = hashlib.sha256(password.encode()).hexdigest()
    checked = pc.check_user(username, pass_hash)
    if checked:
        if pc.set_user(username):
            return True
    return False


# A function with login, register and quit options
def choice_group_one():
    while True:
        printc("[yellow]What do you want to do: ")
        printc("\t[green](1) Login\n\t[blue](2) Register\n\t[red](q) Quit")
        choice = console.input("[yellow]Enter choice: ")

        # Sort choice
        match choice:
            case '1':
                logged = login()
                if logged:
                    printc("[magenta]You are logged in. 🍃\n")
                    return True
                else:
                    printc("[red]Login credentials didn't match!")
            case '2':
                registered = register()
                if registered:
                    printc("[green]Registered. ☘️")
                else:
                    printc("[red]Username taken.")
            case 'q':
                pc.close_conn()
                return False
            case _:
                printc("[red]Invalid choice")
                pass


# A function with add, find passwords for sites
def choice_group_two():
    while True:
        printc("[yellow]What do you want to do: ")
        printc("\t[green](1) Add entry\n\t[blue](2) Find entry\n\t[red](q) Quit")
        choice = console.input("[yellow]Enter choice: ")

        # Sort choice
        match choice:
            case '1':
                site_name, site_url, site_pass = get_data()
                if pc.add_entry(site_name=site_name, site_url=site_url, site_pass=site_pass):
                    printc("[cyan]Data entry successful.")
                else:
                    printc("[red]Something went wrong!")

            case '2':
                site_to_find = console.input("[cyan]Enter site name: ")
                if site_to_find:
                    pc.find_entry(site_to_find)
                time.sleep(2)
            case 'q':
                pc.close_conn()
                break
            case _:
                printc("[red]Invalid choice")
                pass


# Get necessary data from the user and return it
def get_data():
    site_name = input("Enter name of the Site/Website: ").strip()
    site_url = input("Enter the URL: ").strip()
    while True:
        site_pass = getpass("Enter the site password: ")
        if site_pass == getpass("Retype your password: ") and site_pass != "":
            break
        print("Passwords didn't match or empty")
    return [site_name, site_url, site_pass]


if __name__ == "__main__":
    main()
