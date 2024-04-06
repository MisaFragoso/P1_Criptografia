# P1_Criptografia
First Project “Secure Communication Protocol Implementation” Cryptography 2024-2
1. Goal.
The goal of this project is to design and implement a secure communication protocol that
ensures confidentiality, integrity, and authentication of messages exchanged between two
entities. This protocol will use standardized algorithms for encryption (both symmetric and
asymmetric), hashing, and digital signature. The implementation will include a user-friendly
interface accessible via a web browser, allowing both users to use a password as a shared
secret, generate symmetric and asymmetric keys, securely store them, and send encrypted
and signed messages. The platform and programming language to be used will be decided
by you and your team.
2. Project Components
The project must contain the following components.
1. User Interface.
a. The web-based interface will prompt the user to input a password.
b. Upon password submission, the interface will generate asymmetric key pairs
(public and private keys).
c. It will provide options for users to securely store their private key.
2. Key Generation.
a. The protocol will utilize a password-based key derivation function (PBKDF) to
derive a symmetric encryption key from the user's password.
b. Asymmetric key pairs (public and private keys) will be generated using
standardized algorithms such as RSA or Elliptic Curve Cryptography (ECC).
3. Encryption.
a. The symmetric encryption algorithm (e.g., AES) will encrypt the message using
the derived symmetric key.
b. Asymmetric encryption will be used to encrypt the symmetric key, ensuring
confidentiality during transmission.
4. Hashing.
a. SHA-2 or SHA-3 hashing algorithms will be employed to generate a message
digest for integrity verification.
5. Digital Signature.
a. The sender will create a digital signature using their private key and attach it to
the message.
b. The recipient can verify the signature using the sender's public key to ensure
message authenticity and integrity.
6. Secure Storage.
a. Private keys will be securely stored using appropriate cryptographic
techniques, such as encryption with another derived key or utilizing secure key
storage mechanisms provided by the used programming language or platform.

7. Communication Protocol.
a. Define a simple communication protocol for message exchange between two
entities, including steps for key exchange, message transmission, and
verification.
3. Submission Requirements.
Students are required to submit the following deliverables that must be submitted on the
corresponding spaces on Canvas:
3.1 Technical Report. This report must include the following:
• Detailed documentation of the implemented protocol, including the rationale behind
algorithm choices and design decisions.
• Description of the implementation approach, highlighting any challenges faced and
their solutions.
• Explanation of how each component (encryption, hashing, signature) contributes to
ensuring confidentiality, integrity, and authentication.
• Discussion on security considerations and potential vulnerabilities, along with
mitigation strategies.
• Instructions for using the web-based interface and conducting test cases.
3.2 Source Code.
• All source code files implementing the protocol, including both client-side (web
interface) and server-side components.
• Code should be well-commented and organized for clarity and understanding.
3.3 A video presentation/demonstration.
• A video for presentation or demonstration of the project, showcasing the functionality
of the secure communication protocol.
4. Evaluation Criteria.
Projects will be evaluated based on the following criteria. The detailed rubrics can be found
on Canvas, associated to the spaces of submission.
Technical Report. Is the technical report comprehensive and well-structured, providing
insight into the implementation details and rationale?
Source Code.
Functionality. Does the protocol successfully provide confidentiality, integrity, and
authentication?
Security. Are appropriate cryptographic algorithms and techniques used to ensure security?

Usability. Is the web interface user-friendly and intuitive for key generation and message
exchange?
Code Quality. Is the source code well-written, documented, and adhering to best practices?
A video presentation/demonstration. Is the presentation clear, organized, and e^ectively
communicates the project's objectives and outcomes?
5. Conclusion.
This project will not only provide students with practical experience in implementing
cryptographic protocols but also deepen their understanding of security concepts such as
confidentiality, integrity, and authentication. Through this hands-on exercise, students will
gain valuable insights into the challenges and considerations involved in designing and
deploying secure communication systems.
