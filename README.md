# P1_Criptografia

Secure Chat - Demo
Secure Chat is a simple web application for secure messaging, demonstrating the use of encryption, digital signatures, and key management techniques.

Introduction
Secure Chat provides a secure platform for users to communicate with each other while ensuring the confidentiality, integrity, and authenticity of their messages. It employs various cryptographic algorithms and protocols to achieve these security goals.

Features
Secure end-to-end messaging using symmetric and asymmetric encryption.
Digital signatures to verify the authenticity and integrity of messages.
Password-based key derivation for generating cryptographic keys.
Secure storage of private keys using passphrase-protected RSA key files.
User-friendly web interface for easy interaction and messaging.
Getting Started
To run the Secure Chat application locally, follow these steps:

Flask:
To install Flask, you can use pip, which is a package manager for Python. Open your terminal or command prompt and type the following command:
'pip install flask'
This command will download and install Flask and its dependencies.

PyCryptodome:
Similarly, you can install PyCryptodome using pip. Type the following command in your terminal or command prompt:
pip install pycryptodome
This will download and install PyCryptodome, which is a collection of cryptographic algorithms implemented in Python.

Cryptography:
To install the Cryptography library, use pip as well. Enter the following command in your terminal or command prompt:
pip install cryptography
This command will download and install the Cryptography library, which provides cryptographic recipes and primitives.

After executing these commands, Flask, PyCryptodome, and Cryptography will be installed on your system, and you'll be ready to run your project. Remember to execute these commands in your terminal or command prompt.

Clone the project repository to your local machine.
Navigate to the project directory.
Run the app.py script to start the Flask web server.
Access the application in your web browser at http://localhost:5000.


Usage
Login:
Access the web application URL from your browser: http://127.0.0.1:5000/
You will be redirected to the login page, where you'll be prompted to enter your user credentials.
If it's your first time using the application, you can register by creating a new account.
Secure Login:
You can log in securely using your secret passphrase, username, or private key.
Key Generation:
After logging in, you'll be directed to the main dashboard of the application.
From here, you can access the key generation section to create your RSA encryption keys.
Follow the on-screen instructions to securely generate your public and private keys.
Sending Messages:
Once you have your keys generated, you can start sending secure messages.
Select the option to start a new chat and choose the message recipient.
Type your message in the text field and select the option to encrypt before sending it.
Receiving Messages:
When you receive an encrypted message, you'll be notified and can view it in your inbox.
Use your private key to decrypt the message and securely read its content.
Contributing
If you'd like to contribute to Secure Chat, please follow these steps:

Fork the repository on GitHub.
Create a new branch for your feature or bug fix.
Implement your changes and test them thoroughly.
Submit a pull request to the main repository.
License
Secure Chat is licensed under the MIT License. See the LICENSE file for details.

