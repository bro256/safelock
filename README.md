# SafeLock - Django based password manager
My first Python project related to cryptography.

## About
SafeLock is password manager designed to help you keep your online accounts safe and easily accessible.
Securely manage and protect your passwords online with our SafeLock password manager. Our platform offers a convenient and reliable solution for storing, generating, and organizing your passwords in one secure location. With state-of-the-art encryption, your sensitive data remains safe from unauthorized access. Easily access your passwords anytime, anywhere, from any device, ensuring seamless login experiences across all your accounts. Take control of your online security and simplify your digital life with our online password manager, designed to safeguard your credentials and provide peace of mind.

## Features
- **User Registration and Authentication.** Allows users to create an account and authenticate themselves securely.
- **Password Storage and Organization.** Provides the ability for users to store and organize their passwords securely in the password manager.
- **Password Generation.** Offers an advanced password generation feature that generates strong and unique passwords for users.
- **Encryption and Data Security.** Encrypts stored passwords to protect them from unauthorized access.
- **Cross-Platform Access.** Lets access passwords from desktops, laptops, and mobile devices.
- **Search.** Enables users to search their password entries.
- **Import and Export.** Allows users to import passwords from other password managers or export their data in CSV format for backup purposes.

### Installation
Install, create and activate venv:
```
sudo apt install python3-venv
python3 -m venv safelock/venv
cd safelock/
source venv/bin/activate
```

Install all required libraries from `requirements.txt`:
```
safelock$ pip install -r requirements.txt
```

Make migrations and migrate:
```
python3 manage.py makemigrations
python3 manage.py migrate
```

Create superuser:
```
$ python3 manage.py createsuperuser
```

In the same folder as `settings.py` is located, create a new file `local_settings.py` and fill with your secret key, i.e.:
```
SECRET_KEY = 'put your secret key here'
```
### Optional Settings
There are some settings in settings.py you can modify depending on your security requirements.

- Session Cookies
The `SESSION_COOKIE_AGE` setting in Django determines the age of the session cookie in seconds. It specifies the duration for which a user's session remains active.
By default, Django uses a session cookie that expires when the user's browser is closed. However, you can set a specific duration for the session cookie using the `SESSION_COOKIE_AGE` setting.
To configure the session cookie age, update the `SESSION_COOKIE_AGE` value in the Django project's settings.py file. For example, to set the session cookie age to 1 hour (3600 seconds), add the following line to your settings.py file:

```
# Session-related settings
SESSION_COOKIE_AGE = 3600
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
```

- Time Zone Configuration
This Django project uses the local time zone to handle time conversions and display time-related data accurately. The time zone is configured in the Django settings file (`settings.py`).
By default, the project is set to use the 'Europe/Vilnius' time zone, which corresponds to the local time zone in Vilnius, Lithuania.

```
TIME_ZONE = 'UTC'
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

### Random Generator:
- For initialization vectrors: Operating system’s provided random number generator, which is available as `os.urandom()`
- For random password generation: Python Random module, which is an in-built module of Python

### Passwords in database:
In the SafeLock passwords are encrypted to ensure their confidentiality. Here's an example of how encrypted passwords look like in database:
```
b'\xc7*@\xc3\x18\xab\xa5m\x15\x069?1=\x15h\xfc\x87\xcf'
b'\xb7\x8c\xa7g75\xbc\x19\xf9\xef\x84\xa2%yN0~\xf6\x82\xa7\x80\xee\xd87j'n\xbe\xa0\x8c\xaa\xc8'
b'\x1e\xcb\x10\x7f\xf8\x02g3\xdcO\xbf\x97\xee\xec\xb8Is\x9e\xfa\xdfV\xb4\xc8e\xbe+l\xf4\x9c\xf8\xe1'
```

## Contributing
Thank you for considering contributing to our project! We welcome contributions from the community to make our project better. To contribute, please follow these guidelines:
- Fork the repository and clone it locally.
- Create a new branch for your contribution:
```
git checkout -b feature/your-feature-name
```
- Make your desired changes, additions, or bug fixes.
- Commit your changes with clear and descriptive commit messages:
```
git commit -m "Add feature: your feature description"
```
- Push your changes to your forked repository:
```
git push origin feature/your-feature-name
```
- Open a pull request (PR) against the main branch of the original repository.
- Ensure your PR includes a clear description of the changes made, along with any necessary documentation or steps to test the changes.
- We review your contribution, provide feedback, and work with you to address any necessary changes.
- Once approved, your changes will be merged into the main repository. Congratulations on your contribution!

We appreciate your valuable contributions and look forward to working together to improve our project!
