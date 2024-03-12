import hashlib
import time

from password_class import PasswordClass
from rich import print as printc
from rich.console import Console
from rich.table import Table
from getpass import getpass

# Global objects and variables
pc = PasswordClass()
console = Console()
quit_prog = False


def main():
    printc("\n[green]Welcome to your own password manager.")
    while not quit_prog:
        choice_group_one()
        if pc.logged_in:
            choice_group_two()

    pc.close_conn()
    printc("\n[bold green]Have a good day.[/bold green] ☕\n")


# Add register function
def register():
    while True:
        username = input("Username: ").strip().capitalize()
        if username:
            password = getpass("Password: ")
            if password == getpass("Retype password: ") and password != "":
                break
            printc("[red]Passwords didn't match or empty")
        else:
            printc("[red]Username can not be empty")
    pass_hash = hashlib.sha256(password.encode()).hexdigest()
    if pc.add_user(username, pass_hash):
        return True
    return False


# Add login function
def login():
    while True:
        username = input("Username: ").strip().capitalize()
        if username:
            password = getpass("Password: ")
            if password == getpass("Retype password: ") and password != "":
                break
            printc("[red]Passwords didn't match or empty")
        else:
            printc("[red]Username can not be empty")
    pass_hash = hashlib.sha256(password.encode()).hexdigest()
    checked = pc.check_user(username, pass_hash)
    if checked:
        if pc.set_user(username):
            pc.key = password
            if pc.key:
                pc.logged_in = True
                return True
    return False


# A function with login, register and quit options
def choice_group_one():
    global quit_prog
    while True:
        printc("\n[yellow]What do you want to do: ")
        printc("\t[green](1) Login\n\t[blue](2) Register\n\t[red](q) Quit")
        choice = console.input("[yellow]Enter choice: ").strip()

        # Sort choice
        match choice:
            case '1':
                logged = login()
                if logged:
                    printc("[magenta]You are logged in. 🍃\n")
                    return
                else:
                    printc("[red]Login credentials didn't match!")
            case '2':
                registered = register()
                if registered:
                    printc("[green]Registered. ☘️")
                else:
                    printc("[red]Username taken.")
            case 'q':
                quit_prog = True
                return
            case _:
                printc("[red]Invalid choice")
                break


# A function with add, find passwords for sites
def choice_group_two():
    global quit_prog
    while True:
        printc("[yellow]What do you want to do: ")
        printc(
            "\t[green](1) Add entry\n\t[blue](2) Find entry\n\t[cyan](3) Show All\n\t[red](4) Delete entry\n\t[dim red](d) Delete All[/dim red]\n\t[magenta](x) Log out\n\t[red](q) Quit")
        choice = console.input("[yellow]Enter choice: ").strip()

        # Sort choice
        match choice:
            case '1':
                site_name, site_url, site_username, site_pass = get_data()
                if pc.add_entry(site_name=site_name, site_url=site_url, site_username=site_username,
                                site_pass=site_pass):
                    printc("[cyan]Data entry successful.")
                else:
                    printc("[red]Something went wrong!")
            case '2':
                find_data()
            case '3':
                show_all()
            case '4':
                delete_data()
            case 'd':
                delete_all()
            case 'x':
                pc.logged_in = False
                return
            case 'q':
                quit_prog = True
                return
            case _:
                printc("[red]Invalid choice")
                pass


# Get necessary data from the user and return it
def get_data():
    while True:
        site_name = input("Enter name of the Site/Website: ").strip().capitalize()
        if site_name:
            # TODO: site_name to be checked to avoid duplicate entry
            if not pc.check_site(site_name):
                site_pass = getpass("Enter the site password: ")
                if site_name and site_pass == getpass("Retype your password: ") and site_pass != "":
                    break
                else:
                    printc("[red]Passwords didn't match or empty")
            else:
                printc("[red] Site already exists in your database")
                printc("[yellow]You may add numbers to the site-name to make a separate entry")
        else:
            printc("[bold red]Site/Website name can not be empty!")

    # Get optional data. Assign <empty> in case of no user input
    site_url = input("Enter the URL: ").strip() or "<empty>"
    site_username = input("Enter username for the site: ") or "<empty>"

    return [site_name, site_url, site_username, site_pass]


# Data to be retrieved using site name as search-term for the logged in user
def find_data():
    site_to_find = console.input("[cyan]Enter site name: ").strip().capitalize()
    if site_to_find:
        site_data = pc.find_entry(site_to_find)
        if site_data:
            display_data(site_data)
            time.sleep(1)
        else:
            printc("[red]Site is not in the database")
            time.sleep(1)
    else:
        printc("[bold red]Site name can not be empty")


# Show all data of the logged-in user
def show_all():
    site_data = pc.find_entry()
    if site_data:
        display_data(site_data)
        time.sleep(2)
    else:
        printc("[red]Nothing in the database!")
        time.sleep(1)


def display_data(data):
    table = Table(show_header=True, header_style="bold cyan")

    table.add_column("Site-name")
    table.add_column("URL")
    table.add_column("Username")
    table.add_column("Password", style="dim")

    for item in data:
        table.add_row(item[0], item[1], item[2], item[3])

    console.print(table)


def delete_data():
    site_to_delete = console.input("[red]Enter site name: ").strip().capitalize()
    if site_to_delete:
        site_data = pc.find_entry(site_to_delete)
        if site_data:
            if 'y' == console.input("[red]Are you sure? 'y' or 'n': ").lower():
                if pc.delete_entry(site_to_delete):
                    time.sleep(1)
                    printc(f"[bold white] {site_to_delete} deleted successfully from your records. ")
            else:
                printc("[green]Data not deleted.")
                time.sleep(0.5)
                return
        else:
            printc("[red]The site is not in the database")
            time.sleep(1)
    else:
        printc("[bold red]Site name can not be empty")


def delete_all():
    if pc.find_entry():
        ans = input("This will delete all your records.\nType 'Y' or 'N'. Are you sure? ").upper()

        if ans == 'Y' and 'Y' == console.input("[bold red]Are you sure? 'Y' or 'N': ").upper():
            if pc.delete_entry():
                time.sleep(1)
                printc("[red]All data deleted.")
            else:
                print("Data could not be deleted. You may try again.")
        else:
            printc("[bold green] Your data is safe. 💚")
    else:
        printc("[red]Nothing in the database")
        time.sleep(1)


if __name__ == "__main__":
    main()
