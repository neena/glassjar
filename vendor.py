import secrets
import numpy.random as rnd
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Cipher import AES
import base64
from Crypto.Hash import SHA256

dollar_to_points = 10
dollar_to_points_no_history = 5


class Vendor:
    def __init__(self):
        self.private_key = RSA.generate(1024)
        self.public_key = self.private_key.publickey()
        self.store_key = SHA256.new("mysecretpassword".encode('utf-8')).digest() #TODO generate session keys
        self.customers = {}


    def handle_make_purchase(self, message, signature):
        if verify_signature(message, signature):
            msg = decrypt(message)
            customer_loyalty_number = msg["loyalty_number"]
            price = msg["price"]
            points = lambda x: price*dollar_to_points_no_history if msg["history"] == [] else price*dollar_to_points
            customers[customer_loyalty_number] += points

    def handle_check_balance(self, message, signature):
        if verify_signature(message, signature):
            msg = decrypt(message)
            customer_loyalty_number = msg["loyalty_number"]
            balance = customers[customer_loyalty_number].points
            #TODO: make the message
            self.encrypt_sign_send(M)

    def handle_register_loyalty_card(self, message, signature):
        if verify_signature(message, signature):
            msg = decrypt(message)
            customers[msg["loyalty_number"]] = new CustomerData(msg["public_key"])

    def handle_spend_points(self, message, signature):
        if verify_signature(message, signature):
            msg = decrypt(message)
            customer_loyalty_number = msg["loyalty_number"]
            points = msg["spend_num_points"]
            discount = points*(1/dollar_to_points)
            customers[customer_loyalty_number] -= points




    def encrypt_sign_send(self, m):
        m["store_id"] = self.id
        m = json.dumps(m)
        enc = self.encrypt(m)
        sig = self.sign(enc)
        #TODO send

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
