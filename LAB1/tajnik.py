#!/usr/bin/env python

import argparse
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad


    

def init(password):
    salt = get_random_bytes(16)
    vault_key = PBKDF2(password.encode('utf-8').strip(), salt, 64, count=1000000, hmac_hash_module=SHA512)
    with open("files/salt.txt", "wb") as salt_file:
        salt_file.write(salt)
    with open("files/vault_key.txt", "wb") as file:
        file.write(vault_key)
    print("Password manager initialized.")

def put(master_password, webpage, password):
    with open("files/salt.txt", "rb") as salt_file:
        salt = salt_file.read()
    with open("files/vault_key.txt", "rb") as file:
        vault_key = file.read()

    hashed = PBKDF2(master_password.encode('utf-8').strip(), salt, 64, count=1000000, hmac_hash_module=SHA512)
    if hashed == vault_key:
        salt_webpage = get_random_bytes(16)
        webpage_pbkdf2 = PBKDF2(webpage.encode('utf-8').strip(), salt_webpage, 64, count=1000000, hmac_hash_module=SHA512 )
        with open("files/webpage.txt", "wb") as webpage_file:
            webpage_file.write(webpage_pbkdf2)
        with open("files/salt_webpage.txt", "wb") as salt_webpage_file:
            salt_webpage_file.write(salt_webpage)

        with open("files/password.txt", "rb") as password_file:
            password_read = password_file.read()
        with open("files/password_key.txt", "rb") as password_key_file:
            password_key = password_key_file.read()
        with open("files/password_iv.txt", "rb") as password_iv_file:
            password_iv = password_iv_file.read()

        aes_cbc = AES.new(key=password_key, mode=AES.MODE_CBC, IV=password_iv)
        stored_password = aes_cbc.decrypt(password_read)
        
        if unpad(stored_password,16).decode() == password:
            print("You already stored the same password for", webpage)
        else:
            iv = get_random_bytes(16)
            key = get_random_bytes(16)
            aes_cbc = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
            password_encoded = password.encode('utf-8').strip()
            password_cipher = aes_cbc.encrypt(pad(password_encoded,16))

            with open("files/password.txt", "wb") as password_file:
                password_file.write(password_cipher)
            with open("files/password_iv.txt", "wb") as password_iv_file:
                password_iv_file.write(iv)
            with open("files/password_key.txt", "wb") as password_key_file:
                password_key_file.write(key)
            print("Stored password for", webpage)
    else:
        print("Your master password isn't correct.")
    return

def get(master_password, webpage):
    with open("files/salt.txt", "rb") as salt_file:
        salt = salt_file.read()
    with open("files/vault_key.txt", "rb") as file:
        vault_key = file.read()

    hashed = PBKDF2(master_password.encode('utf-8').strip(), salt, 64, count=1000000, hmac_hash_module=SHA512)

    if hashed == vault_key:
        with open("files/salt_webpage.txt", "rb") as salt_webpage_file:
            salt_webpage = salt_webpage_file.read()
        with open("files/webpage.txt", "rb") as webpage_file:
            webpage_read = webpage_file.read()

        hashed_webpage = PBKDF2(webpage.encode('utf-8').strip(), salt_webpage, 64, count=1000000, hmac_hash_module=SHA512)
        if hashed_webpage == webpage_read:
            with open("files/password.txt", "rb") as password_file:
                password_read = password_file.read()
            with open("files/password_key.txt", "rb") as password_key_file:
                password_key = password_key_file.read()
            with open("files/password_iv.txt", "rb") as password_iv_file:
                password_iv = password_iv_file.read()

            aes_cbc = AES.new(key=password_key, mode=AES.MODE_CBC, IV=password_iv)
            password = aes_cbc.decrypt(password_read)
            print("Password for",webpage,"is:", unpad(password,16).decode())
        else:
            print("Webpage doesnt't exist.")
    else:
        print("Your master password isn't correct.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--init")
    parser.add_argument("--webpage")
    parser.add_argument("--password")
    parser.add_argument("--put")
    parser.add_argument("--get")

    args = parser.parse_args()
    if args.init:
        masterPassword = args.init
        init(masterPassword)
    if args.webpage and args.password and args.put:
        master_password = args.put
        webpage = args.webpage
        password = args.password
        put(master_password, webpage, password)
    if args.get and args.webpage:
        master_password = args.get
        webpage = args.webpage
        get(master_password, webpage)
    
main()