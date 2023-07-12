# SafeLock - Django based secret manager
My first Python project related to cryptography.

## About
SafeLock is password manager designed to help you keep your online accounts safe and easily accessible. **The project is still in progress, so please do not use it in real environment yet.**
Securely manage and protect your passwords online with our SafeLock password manager. Our platform offers a convenient and reliable solution for storing, generating, and organizing your passwords in one secure location. With state-of-the-art encryption, your sensitive data remains safe from unauthorized access. Easily access your passwords anytime, anywhere, from any device, ensuring seamless login experiences across all your accounts. Take control of your online security and simplify your digital life with our online password manager, designed to safeguard your credentials and provide peace of mind.

### Installation

Install, create and activate venv:
```
$ sudo apt install python3-venv
$ python3 -m venv safelock/venv
$ cd safelock/
~/safelock$ source venv/bin/activate
```

Install all required libraries from `requirements.txt`:
```
~/safelock$ pip install -r requirements.txt
```

Make migrations and migrate:
```
$ python3 manage.py makemigrations
$ python3 manage.py migrate
```

Create superuser:
```
$ python3 manage.py createsuperuser
```

In the same folder as `settings.py` is located, create a new file `local_settings.py` and fill with your secret key, i.e.:
```
SECRET_KEY = 'put your secret key here'
```

## Cryptography

### Python cryptography libraries
- [Cryptography](https://cryptography.io/en/latest/) - the most beautiful and well-documented python library for cryptography

### Key derivation function
- PBKDF2
- Iterations: 600 000 (2023 OWASP recommendation)
- Salt: 128 bits (US National Institute of Standards and Technology (NIST) recommendation)
- Key length: 256 bits
- Implemented in accordance with official [Cryptography library KDF documentation](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/)

### Symmetric encryption
- Algorithm: AES-256
- Key length: 256 bits
- Mode: GCM (Galois/Counter Mode)
- Block size: 128 bits
- Authentication tag: 112 bits
- Initialization vector (IV): 96 bits, random, different for every record
- Implemented in accordance with official [Cryptography library Symetric Encryption documentation](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/)

### Hashing
- SHA-256
