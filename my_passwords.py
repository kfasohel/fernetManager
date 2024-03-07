import hashlib

from password_class import PasswordClass
from rich import print as printc
from rich.console import Console
from getpass import getpass
from hashlib import sha256

pc = PasswordClass()
def main():
    console = Console()
    printc("[green]Welcome to your own password manager.")
    while True:
        printc("[yellow]What do you want to do: ")
        printc("\t[green](1) Login\n\t[blue](2) Register\n\t[red](q) Quit")
        choice = console.input("[yellow]Enter choice: ")

        # Sort choice
        match choice:
            case '1':
                logged = login()
                if logged:
                    printc("[magenta]You are logged in. 🍃")
                    # TODO: add next choice prompt
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
                break
            case _:
                printc("[red]Invalid choice")
                pass


# Add register function
def register():
    username = input("Username: ").strip()
    while True:
        password = getpass("Password: ")
        if password == getpass("Retype password: "):
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
        if password == getpass("Retype password: "):
            break
        print("Passwords didn't match")
    pass_hash = hashlib.sha256(password.encode()).hexdigest()
    checked = pc.check_user(username, pass_hash)
    if checked:
        if pc.set_user(username):
            return True
    return False





if __name__ == "__main__":
    main()