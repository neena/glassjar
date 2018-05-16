import secrets
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
import json
from datetime import datetime


class Customer:
    def __init__(self):
        self.loyalty_number = secrets.randbits(64)
        self.private_key = RSA.generate(1024)
        self.public_key = self.private_key.publickey()

    def __str__(self):
        return "Loyalty number: {0}".format(self.loyalty_number)

    def generate_message(self, key="", text=""):
        timestamp = int(datetime.utcnow().timestamp())
        message = json.dumps({key: text, "timestamp": timestamp, "loyalty_number": self.loyalty_number})
        message = message.encode('utf-8')
        hash = SHA256.new(message).digest()
        signature = self.private_key.sign(hash, '')
        return (message, signature)

    def verify_message(self, message, signature):
        if isinstance(message, str):
            message = message.encode('utf-8')
        hash = SHA256.new(message).digest()
        return self.public_key.verify(hash, signature)
