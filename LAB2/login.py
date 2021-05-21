import argparse
import getpass
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import pickle

def login(username):
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
                    password = getpass.getpass(prompt='Password: ', stream=None)
                    password_pbk = PBKDF2(password.encode('utf-8').strip(), pass_salt, 64, count=1000000, hmac_hash_module=SHA512)
                    # provjeri jesi li username i lozinka uredu
                    if username_pbk == name and password_pbk == pass1:
                        for force, value in user[2].items():
                            # je li force-password prisutan?
                            if value == 1:
                                new_password = getpass.getpass(prompt='New password: ', stream=None)
                                repeat_new_password = getpass.getpass(prompt='Repeat new password: ', stream=None)
                                if new_password == repeat_new_password:
                                    copy_dict_users.remove(user)
                                    salt_username = get_random_bytes(16)
                                    salt_password = get_random_bytes(16)
                                    username_pbk = PBKDF2(username.encode('utf-8').strip(), salt_username, 64, count=1000000, hmac_hash_module=SHA512)
                                    password_pbk = PBKDF2(password.encode('utf-8').strip(), salt_password, 64, count=1000000, hmac_hash_module=SHA512)
                                    # promijeni password
                                    user_dict = [{username_pbk:password_pbk}, {salt_username:salt_password}, {"force-password": 0}]
                                    copy_dict_users.append(user_dict)
                                    with open ("user_info/user_and_password.txt", "wb") as file:
                                        for user in copy_dict_users:
                                            pickle.dump(user, file) 
                                    print("Login successful.") 
                                else:
                                    print("Password mismatch. Try again.")
                            else:
                                print("Login successful.")
                    else:
                        print("Username or password incorrect.")
                    




def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--login")

    args = parser.parse_args()
    if args.login:
        username = args.login
        login(username)

main()