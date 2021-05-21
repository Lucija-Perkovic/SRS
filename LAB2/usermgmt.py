import argparse
import getpass
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import pickle

def add_user(username):
    exists = False
    users = []
    with open ("user_info/user_and_password.txt", "rb") as file:
        while True:
            try:
                # dodaj sve usere 
                users.append(pickle.load(file))
            except(EOFError):
                break
        for user in users:
            for name,pass1 in user[0].items():
                for name_salt,pass_salt in user[1].items():
                    username_pbk = PBKDF2(username.encode('utf-8').strip(), name_salt, 64, count=1000000, hmac_hash_module=SHA512)
                    # postoji li već username 
                    if username_pbk == name:
                        exists = True 
    if not exists:
        # ako ne postoji u text file-u onda dodaj, inače nemoj
        password = getpass.getpass(prompt='Password: ', stream=None)
        repeated_password = getpass.getpass(prompt='Repeat password: ', stream=None)
        # ako je lozinka jednaka onda nastavi
        if password == repeated_password:
            # salt
            salt_username = get_random_bytes(16)
            salt_password = get_random_bytes(16)
            username_pbk = PBKDF2(username.encode('utf-8').strip(), salt_username, 64, count=1000000, hmac_hash_module=SHA512)
            password_pbk = PBKDF2(password.encode('utf-8').strip(), salt_password, 64, count=1000000, hmac_hash_module=SHA512)
            user_dict = [{username_pbk:password_pbk}, {salt_username:salt_password}, {"force-password": 0}]
            with open ("user_info/user_and_password.txt", "ab") as file:
                # zapisi username u txt file
                pickle.dump(user_dict, file)
            print("User add successfuly added.")
        else:
            print("User add failed. Password mismatch.")

def change_pass(username):
    users = []
    with open ("user_info/user_and_password.txt", "rb") as file:
        while True:
            try:
                # dodaj sve usere 
                users.append(pickle.load(file))
            except(EOFError):
                break
        # kopija dictionarya da se moze manipulirati s njime
        copy_dict_users = users.copy()
        for user in users:
            for name,pass1 in user[0].items():
                for name_salt,pass_salt in user[1].items():
                    username_pbk = PBKDF2(username.encode('utf-8').strip(), name_salt, 64, count=1000000, hmac_hash_module=SHA512)
                    # postoji li provjeravani username
                    if username_pbk == name:
                        # brise se iz dictionarya
                        copy_dict_users.remove(user)
                        password = getpass.getpass(prompt='Password: ', stream=None)
                        repeated_password = getpass.getpass(prompt='Repeat password: ', stream=None)
                        # ako je lozinka jednaka onda nastavi
                        if password == repeated_password:
                            salt_username = get_random_bytes(16)
                            salt_password = get_random_bytes(16)
                            username_pbk = PBKDF2(username.encode('utf-8').strip(), salt_username, 64, count=1000000, hmac_hash_module=SHA512)
                            password_pbk = PBKDF2(password.encode('utf-8').strip(), salt_password, 64, count=1000000, hmac_hash_module=SHA512)
                            # dodaj promijenjeni username
                            user_dict = [{username_pbk:password_pbk}, {salt_username:salt_password}, {"force-password": 0}]
                            copy_dict_users.append(user_dict)
                            with open ("user_info/user_and_password.txt", "wb") as file:
                                for user in copy_dict_users:
                                    pickle.dump(user, file)       
                            print("Password change successful.")
                        else:
                            print("Password change failed. Password mismatch.")
def force_pass(username):
    users = []
    with open ("user_info/user_and_password.txt", "rb") as file:
        while True:
            try:
                users.append(pickle.load(file))
            except(EOFError):
                break
        copy_dict_users = users.copy()
        for user in users:
            for name,pass1 in user[0].items():
                for name_salt,pass_salt in user[1].items():
                    username_pbk = PBKDF2(username.encode('utf-8').strip(), name_salt, 64, count=1000000, hmac_hash_module=SHA512)
                    if username_pbk == name:
                        copy_dict_users.remove(user)
                        # force-password varijabla je postavljena
                        user_dict = [{username_pbk:pass1}, {name_salt:pass_salt}, {"force-password": 1}]
                        copy_dict_users.append(user_dict)
                        with open ("user_info/user_and_password.txt", "wb") as file:
                            for user in copy_dict_users:
                                pickle.dump(user, file)       
                        print("User will be requested to change password on next login.")
def delete_user(username):
    users = []
    with open ("user_info/user_and_password.txt", "rb") as file:
        while True:
            try:
                users.append(pickle.load(file))
            except(EOFError):
                break
        copy_dict_users = users.copy()
        for user in users:
            for name,pass1 in user[0].items():
                for name_salt,pass_salt in user[1].items():
                    username_pbk = PBKDF2(username.encode('utf-8').strip(), name_salt, 64, count=1000000, hmac_hash_module=SHA512)
                    if username_pbk == name:
                        # obrisi usera
                        copy_dict_users.remove(user)
                        with open ("user_info/user_and_password.txt", "wb") as file:
                            for user in copy_dict_users:
                                pickle.dump(user, file)       
                        print("User successfuly removed.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--add")
    parser.add_argument("--passwd")
    parser.add_argument("--forcepass")
    parser.add_argument("--delete")


    args = parser.parse_args()

    if args.add:
        username = args.add
        add_user(username)

    if args.passwd:
        username = args.passwd
        change_pass(username)

    if args.delete:
        username = args.delete
        delete_user(username)
    
    if args.forcepass:
        username = args.forcepass
        force_pass(username)
main()