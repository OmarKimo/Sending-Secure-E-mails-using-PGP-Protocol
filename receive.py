from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pyDes
import imaplib
import email
import re
import os


def getPrivateKey():
    keyPair = None
    if os.path.exists('keyPair.pem'):
        with open("keyPair.pem", "rb") as f:
            keyPair = RSA.importKey(f.read())
    if not keyPair:
        keyPair = RSA.generate(1024)
        with open('keyPair.pem', 'wb') as f:
            f.write(keyPair.exportKey('PEM'))
    return keyPair


def decryptKey(encrypted_key, privateKey):
    decryptor = PKCS1_OAEP.new(privateKey)
    return decryptor.decrypt(encrypted_key)


def decryptMessage(encrypted_message, key):
    key = key.to_bytes(8, "big")
    DES = pyDes.des(key, pyDes.CBC, IV=b"\0\0\0\0\0\0\0\0",
                    pad=None, padmode=pyDes.PAD_PKCS5)
    return DES.decrypt(encrypted_message, padmode=pyDes.PAD_PKCS5)


def extractMessage(encrypted_key, encrypted_message):
    privateKey = getPrivateKey()
    sessionKey = decryptKey(encrypted_key, privateKey)
    sessionKey = int.from_bytes(sessionKey, "big")
    return decryptMessage(encrypted_message, sessionKey)


def receiveEmail(email_address, password):
    with imaplib.IMAP4_SSL("imap.gmail.com") as connection:
        connection.login(email_address, password)
        connection.select('inbox')
        # get the messages that have "Security Project 01" in the subject
        _, data = connection.search(None, '(SUBJECT "Security Project 01")')
        # print(data)
        message = ""
        # get the latest message
        _, data = connection.fetch(data[0].split()[-1], "(RFC822)")
        # print(data)
        for response_part in data:
            if isinstance(response_part, tuple):
                msg = email.message_from_string(response_part[1].decode())
                message = msg.get_payload()[0].get_payload()
                break
        if not message:
            print("Error, there is no received message.")
            exit(-1)
        Key_Message = list(map(int, re.findall('[0-9]+', str(message))))
        lk = Key_Message[0]
        lm = Key_Message[2]
        intk = Key_Message[1]
        intm = Key_Message[3]
        return (intk.to_bytes(lk, "big"), intm.to_bytes(lm, "big"))


def main():
    print("Enter 'c' without quotes to enter your email and password through console, ")
    option = input(
        "or Enter 'f' without quotes to enter your email and password using a file: ")
    email = ""
    password = ""
    if option == 'f':
        print("You choose to enter your email and password using a file.")
        print("Note that the structure of the file must be as follows with each at a line:")
        print("Your_Email [example: omar.mohamed97@eng-st.cu.edu.eg]")
        print("Your_password")
        file_path = input("Enter the path of the file: ")
        try:
            with open(file_path, 'r') as f:
                email = f.readline().rstrip()
                password = f.readline().rstrip()
        except:
            print(
                "An error happen while reading from file,\nplease check the path and the structure of the file.")
            exit(-1)
    else:
        email = input("Enter your email address: ")
        password = input("Enter your password: ")
    #f = open("sample.txt", 'w+')
    received_email = receiveEmail(email, password)
    #f.write("received_email: {}\n".format(received_email))
    received_message = extractMessage(
        received_email[0], received_email[1]).decode("utf-8")
    print("Received message:\n" + received_message)


if __name__ == "__main__":
    main()
