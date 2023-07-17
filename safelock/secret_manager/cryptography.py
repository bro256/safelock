from . models import PasswordEntry
import hashlib
import os
import random
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.http import HttpRequest, JsonResponse


def generate_password(request: HttpRequest) -> JsonResponse:
    length = int(request.GET.get('length', 20))
    lowercase = request.GET.get('lowercase', 'true').lower() == 'true'
    uppercase = request.GET.get('uppercase', 'true').lower() == 'true'
    numbers = request.GET.get('numbers', 'true').lower() == 'true'
    symbols = request.GET.get('symbols', 'true').lower() == 'true'
    characters = ''
    if lowercase:
        characters += 'abcdefghijklmnopqrstuvwxyz'
    if uppercase:
        characters += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    if numbers:
        characters += '0123456789'
    if symbols:
        characters += '!"#$%&\'()*+-./:;<=>?@[\]^_`{|}~'

    if characters:
        password = ''.join(random.choice(characters) for _ in range(length))
    else:
        password = ''

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


def reencrypt_all_passwords(user, old_password_bytes, new_password_bytes):
    
    # Derive the old and new keys
    old_derived_key_hex = derive_key(user.username, old_password_bytes)
    new_derived_key_hex = derive_key(user.username, new_password_bytes)
    
    password_entries = PasswordEntry.objects.filter(owner=user)
    
    ### FOR DEBUG ONLY!!!
    #print(f"REENCRYPT FUNCTION. Old key bytes: {bytes.fromhex(old_derived_key_hex)} New key bytes: {bytes.fromhex(new_derived_key_hex)}")

    for password_entry in password_entries:

        # Decrypt the password
        password_bytes = decrypt_password(password_entry, old_derived_key_hex)

        # Encrypt the password and get encryption data
        encrypted_password, encryption_iv, auth_tag = encrypt_password(password_bytes, new_derived_key_hex)

        # Update instance encryption data
        password_entry.encrypted_password = encrypted_password
        password_entry.encryption_iv = encryption_iv
        password_entry.auth_tag = auth_tag
        password_entry.save()


def decrypt_password(password_entry, derived_key_hex):
    cipher = Cipher(algorithms.AES(bytes.fromhex(derived_key_hex)), modes.GCM(password_entry.encryption_iv, password_entry.auth_tag))
    decryptor = cipher.decryptor()
    password_bytes = decryptor.update(password_entry.encrypted_password) + decryptor.finalize()
    
    ### FOR DEBUG ONLY!!!
    #decrypted_password_str = decrypted_password.decode('utf-8')
    #print(f"DECRYPTION. ID: Encrypted pass: {password_entry.encrypted_password} iv: {password_entry.encryption_iv} tag: {password_entry.auth_tag} decrypted pass: {decrypted_password} decrypted pass str: {decrypted_password_str}")
    
    return password_bytes

def encrypt_password(password_bytes, derived_key_hex):
    encryption_iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(bytes.fromhex(derived_key_hex)), modes.GCM(encryption_iv))
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(password_bytes) + encryptor.finalize()
    auth_tag = encryptor.tag
    
    ### FOR DEBUG ONLY!!!
    #print(f"ENCRYPTION. Encrypted pass: {encrypted_password} iv: {iv} Tag: {auth_tag} decrypted pass: {decrypted_password} decrypted pass str: {decrypted_password_str}") 
    
    return encrypted_password, encryption_iv, auth_tag
    