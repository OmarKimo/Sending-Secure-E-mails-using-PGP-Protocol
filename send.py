from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pyDes
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import os
import random


def getPublicKey():
    keyPair = None
    if os.path.exists('keyPair.pem'):
        with open("keyPair.pem", "rb") as f:
            keyPair = RSA.importKey(f.read())
    if not keyPair:
        keyPair = RSA.generate(1024)
        with open('keyPair.pem', 'wb') as f:
            f.write(keyPair.exportKey('PEM'))
    return keyPair.publickey()


def generateKey():
    key = 0
    bits = (7, 8)   # 7 * 8 = 56
    for _ in range(bits[1]):
        key *= 2
        for _ in range(bits[0]):
            key *= 2
            key += random.randint(0, 1)
    return key


def encryptKey(key, publicKey):
    encryptor = PKCS1_OAEP.new(publicKey)
    return encryptor.encrypt(key.to_bytes(8, "big"))


def encryptMessage(message, key):
    key = key.to_bytes(8, "big")
    DES = pyDes.des(key, pyDes.CBC, IV=b"\0\0\0\0\0\0\0\0",
                    pad=None, padmode=pyDes.PAD_PKCS5)
    return DES.encrypt(message.encode())


def sendEmail(encrypted_key, encrypted_message, sender_email, sender_password, receiver_email):
    lk = len(encrypted_key)
    lm = len(encrypted_message)
    intk = int.from_bytes(encrypted_key, "big", signed=False)
    intm = int.from_bytes(encrypted_message, "big", signed=False)
    message = str(lk) + '-' + str(intk) + '-' + str(lm) + '-' + str(intm)
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = 'Security Project 01 - Omar AbdElkareem'
    msg.attach(MIMEText(message, 'plain'))
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", context=context) as connection:
        connection.login(sender_email, sender_password)
        connection.sendmail(sender_email, receiver_email, msg.as_string())
        print("E-mail Sent, congratulations ^_^")


def main():
    print("Enter 'c' without quotes to enter emails and your password through console, ")
    option = input(
        "or Enter 'f' without quotes to enter emails and your password using a file: ")
    sender_email = ""
    receiver_email = ""
    sender_password = ""
    message = ""
    if option == 'f':
        print("You chose to enter emails and the password using a file.")
        print("Note that the structure of the file must be as follows with each at a line:")
        print("Your_Email [example: omarkimo80@gmail.com]")
        print("Your_password")
        print("Receiver_Email [example: omar.mohamed97@eng-st.cu.edu.eg]")
        print("Your_message [example: 'Hello world', it can be multi line]")
        file_path = input("Enter the path of the file: ")
        try:
            with open(file_path, 'r') as f:
                sender_email = f.readline().rstrip()
                sender_password = f.readline().rstrip()
                receiver_email = f.readline().rstrip()
                message = ''.join(f.readlines()).rstrip()
        except:
            print(
                "An error happen while reading from file,\nplease check the path and the structure of the file.")
            exit(-1)
    else:
        sender_email = input("Enter your email address: ")
        sender_password = input("Enter your password: ")
        receiver_email = input("Enter receiver email address: ")
        message = input("Enter the message: ")
    #f = open("sample.txt", 'w')
    publicKey = getPublicKey()
    #f.write("Public Key: n - {} ,\ne - {}\n".format(publicKey.n, publicKey.e))
    sessionKey = generateKey()
    #f.write("Session Key: {}\n".format(sessionKey))
    #sessionKey = int.from_bytes(os.urandom(7), "big")
    encrypted_key = encryptKey(sessionKey, publicKey)
    #f.write("encrypted Key: {}\n".format(encrypted_key))
    encrypted_message = encryptMessage(message, sessionKey)
    #f.write("encrypted Message: {}\n".format(encrypted_message))
    sendEmail(encrypted_key, encrypted_message,
              sender_email, sender_password, receiver_email)


if __name__ == "__main__":
    main()
