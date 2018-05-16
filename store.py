import secrets
import numpy.random as rnd
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Cipher import AES
import base64
from Crypto.Hash import SHA256
import socket


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-s[-1]]

TCP_IP = 'localhost'
TCP_PORT = 19997
BUFFER_SIZE = 8192

class Store:
    def __init__(self):
        self.id = secrets.randbits(64)
        self.private_key = RSA.generate(1024)
        self.public_key = self.private_key.publickey()
        self.store_key = SHA256.new("mysecretpassword".encode('utf-8')).digest() #TODO generate session keys
        self.vendor_pk = RSA.generate(1024)
        self.store_register_with_vendor()

    def connect_to_vendor(self):
        self.vendor_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.vendor_sock.connect((TCP_IP, TCP_PORT))

    def store_register_with_vendor(self):
        self.connect_to_vendor()
        data = json.dumps({"action":"register_store","public_key": self.public_key.exportKey().decode('utf-8'), "store_id":self.id})
        resp = self.send_and_recieve(data.encode('utf-8'))
        self.store_key = self.private_key.decrypt(resp)

        self.get_vendor_pub_key()

    def get_vendor_pub_key(self):
        self.connect_to_vendor()
        data = json.dumps({"action":"get_public_key"})
        resp = self.send_and_recieve(data.encode('utf-8'))
        self.vendor_pk = RSA.importKey(resp)
        print("vendor pk: ", self.vendor_pk)


    def make_purchase(self, message, signature, purchases): # purchases is a list of tuples ("item", price in dollars)
        send_purchases = False
        transaction_number = secrets.randbits(64)
        obj = json.loads(message)
        if obj["send_history"] == "y":
            send_purchases = True

        price = 0
        for purchase in purchases:
            price += purchase[1]

        k = 1
        if send_purchases:
            purchase_history = purchases
        else:
            purchase_history = []
            price += rnd.triangular(-k,0,k)
            price = max(0, price) # no negative points
        print(price)
        M = {"m":message,"s":signature, "history":purchase_history, "action":"make_purchase", "price": price}
        resp = self.encrypt_sign_send(M)
        print(resp)

    def check_balance(self, message, signature):
        M = {"m":message,"s":signature, "action":"check_balance"}
        resp = self.encrypt_sign_send(M)
        print(self.decrypt(resp))

    def register_loyalty_card(self, message, signature):
        M = {"m":message,"s":signature, "action":"register_loyalty_card"}
        resp = self.encrypt_sign_send(M)
        if resp == b"OK":
            print("successfully registered!!")

    def spend_points(self, message, signature):
        M = {"m":message,"s":signature, "action":"spend_points"}
        resp = self.encrypt_sign_send(M)
        resp = json.loads(resp.decode('utf-8'))
        if self.verify_signature(resp["discount"], resp["sig"], self.vendor_pk):
            print("discount amt: ", resp)
        else:
            raise ValueError

    def encrypt_sign_send(self, m):
        m["store_id"] = self.id
        m = json.dumps(m)
        enc = self.encrypt(m)
        sig = self.sign(enc)

        self.connect_to_vendor()

        data = json.dumps({"enc":enc.decode('utf-8'), "sig":sig})
        resp = self.send_and_recieve(data.encode('utf-8'))

        return resp

    def send_and_recieve(self, m):
        self.vendor_sock.send(m)
        data = self.vendor_sock.recv(BUFFER_SIZE)
        return data

    def sign(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        hash = SHA256.new(message).digest()
        signature = self.private_key.sign(hash, '')
        return signature

    def verify_signature(self, message, signature, public_key):
        if isinstance(message, str):
            message = message.encode('utf-8')
        hash = SHA256.new(message).digest()
        return public_key.verify(hash, signature)

    def encrypt(self,m):
        raw = pad(m)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new( self.store_key, AES.MODE_CBC, iv )
        msg = iv + cipher.encrypt(raw)
        return base64.b64encode(msg)

    def decrypt(self,enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.store_key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))
