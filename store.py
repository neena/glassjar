import secrets
import numpy.random as rnd
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Cipher import AES
import base64
from Crypto.Hash import SHA256


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-s[-1]]

class Store:
    def __init__(self):
        self.id = secrets.randbits(64)
        self.private_key = RSA.generate(1024)
        self.public_key = self.private_key.publickey()
        self.store_key = SHA256.new("mysecretpassword".encode('utf-8')).digest() #TODO generate session keys

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

        M = json.dumps({"m":message,"s":signature, "history":purchase_history, "action":"make_purchase"})
        self.encrypt_sign_send(M)

    def check_balance(self, message, signature):
        M = {"m":message,"s":signature, "action":"check_balance"}
        self.encrypt_sign_send(M)

    def register_loyalty_card(self, message, signature):
        M = {"m":message,"s":signature, "action":"register_loyalty_card"}
        self.encrypt_sign_send(M)

    def spend_points(self, message, signature):
        M = {"m":message,"s":signature, "action":"spend_points"}
        self.encrypt_sign_send(M)

    def encrypt_sign_send(self, m):
        enc = self.encrypt(m)
        sig = self.sign(enc)

        # check everything is ok
        # TODO remove these before we release
        assert(self.decrypt(enc)==m.encode('utf-8'))
        assert(self.verify_signature(enc,sig))

    def sign(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        hash = SHA256.new(message).digest()
        signature = self.private_key.sign(hash, '')
        return signature

    def verify_signature(self, message, signature):
        if isinstance(message, str):
            message = message.encode('utf-8')
        hash = SHA256.new(message).digest()
        return self.public_key.verify(hash, signature)

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
