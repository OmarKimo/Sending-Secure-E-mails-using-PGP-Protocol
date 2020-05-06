# Sending Secure E-mails using PGP protocol
### The Detailed Steps of the protocol are as follows:
- Suppose Alice wants to send a secure e-mail to Bob, she should do the following steps:
1. Generate a random session key Ks and encrypt it using Bob’s public key using RSA algorithm.
2. Encrypt the plain text e-mail using DES with the session key Ks generated in step (1).
3. Send both the encrypted session key generated in step (1) Ks along with the encrypted email generated in step (2).
- On the receiver side, Bob should do the following steps upon receiving an-email from Alice:
1. Decrypt the received session key Ks, using Bob’s private key.
2. Use the retrieved session key to decrypt the received e-mail.
