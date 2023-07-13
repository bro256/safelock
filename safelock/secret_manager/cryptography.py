import hashlib
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . models import PasswordEntry

from django.http import HttpRequest, JsonResponse

import random
import string

def generate_password(request: HttpRequest) -> JsonResponse:
    length = int(request.GET.get('length', 16))
    letters = request.GET.get('letters', 'true').lower() == 'true'
    numbers = request.GET.get('numbers', 'true').lower() == 'true'
    symbols = request.GET.get('symbols', 'true').lower() == 'true'

    characters = ''
    if letters:
        characters += string.ascii_letters
    if numbers:
        characters += string.digits
    if symbols:
        characters += string.punctuation

    password = ''.join(random.choice(characters) for _ in range(length))

    return JsonResponse({'password': password})


def derive_key(username, password):
    # Hash the username
    username_hash = hashlib.sha256(username.encode()).digest()

    # PBKDF2 parameters
    salt = username_hash[:16]  # Extract the first 16 bytes (128 bits) as the salt
    iterations = 600000
    key_length = 32 # bytes (256 bits)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations
    )

    # PBKDF2 to get derived key
    derived_key = kdf.derive(password.encode('utf-8'))

    ### FOR DEBUG ONLY!!!
    # print(f"KEY DERIVATION FUNCTION. Username: {username} Pass:{password} Salt: {salt} Derived key: {derived_key} Derived key in HEX (return): {derived_key.hex()}")

    return derived_key.hex()


def reencrypt_all_passwords(user, old_password, new_password):
    # Derive the old and new keys
    old_key = derive_key(user.username, old_password)
    new_key = derive_key(user.username, new_password)
    password_entries = PasswordEntry.objects.filter(owner=user)
    
    ### FOR DEBUG ONLY!!!
    #print(f"REENCRYPT FUNCTION. Old key bytes: {bytes.fromhex(old_key)} New key bytes: {bytes.fromhex(new_key)}")

    for password_entry in password_entries:
        password = decrypt_password(password_entry, old_key)
        encrypted_password, iv, auth_tag = encrypt_password(password, new_key)
        
        password_entry.encrypted_password = encrypted_password
        password_entry.encryption_iv = iv
        password_entry.auth_tag = auth_tag
        password_entry.save()


def decrypt_password(password_entry, key):
    cipher = Cipher(algorithms.AES(bytes.fromhex(key)), modes.GCM(password_entry.encryption_iv, password_entry.auth_tag))
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(password_entry.encrypted_password) + decryptor.finalize()
    
    ### FOR DEBUG ONLY!!!
    #decrypted_password_str = decrypted_password.decode('utf-8')
    #print(f"DECRYPTION. ID: Encrypted pass: {password_entry.encrypted_password} iv: {password_entry.encryption_iv} tag: {password_entry.auth_tag} decrypted pass: {decrypted_password} decrypted pass str: {decrypted_password_str}")
    
    return decrypted_password

def encrypt_password(password, key):
    encryption_iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(bytes.fromhex(key)), modes.GCM(encryption_iv))
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(password) + encryptor.finalize()
    auth_tag = encryptor.tag
    
    ### FOR DEBUG ONLY!!!
    #print(f"ENCRYPTION. Encrypted pass: {encrypted_password} iv: {iv} Tag: {auth_tag} decrypted pass: {decrypted_password} decrypted pass str: {decrypted_password_str}") 
    
    return encrypted_password, encryption_iv, auth_tag
    
    