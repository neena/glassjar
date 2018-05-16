import socket
import asyncore
from multiprocessing import Process
import atexit
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Cipher import AES
import base64
from Crypto.Hash import SHA256
import secrets
import numpy.random as rnd
from datetime import datetime
from customerdata import CustomerData


TCP_IP = 'localhost'
TCP_PORT = 19997
BUFFER_SIZE = 8192

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-s[-1]]


dollar_to_points = 10
dollar_to_points_no_history = 5

class Vendor:
	def __init__(self):
		self.private_key = RSA.generate(1024)
		self.public_key = self.private_key.publickey()
		self.store_key = SHA256.new("mysecretpassword".encode('utf-8')).digest() #TODO generate session keys
		self.customers = {}

		self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.soc.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
		self.soc.bind((TCP_IP, TCP_PORT))
		self.soc.listen()

		p = Process(target=self.listen_on_soc)

		p.start()


	def listen_on_soc(self):
		while True:
			conn, addr = self.soc.accept()
			print('Connection address:', addr)
			p = Process(target=self.connection_handler,args=(conn,))
			p.start()


	def connection_handler(self, conn):
		data = conn.recv(BUFFER_SIZE)
		enc, sig = json.loads(data.decode('utf-8'))
		json_obj = json.loads(self.decrypt(enc).decode('utf-8'))

		# TODO
		# store_public_key = self.store_public_keys[json_obj["store_id"]]
		# verify_signature(enc, store_public_key)

		action = json_obj["action"]
		customer_m = json_obj["m"]
		customer_sig = json_obj["s"]
		customer_json = json.loads(json_obj["m"])


		if int(datetime.utcnow().timestamp()) - customer_json["timestamp"] > 30:
			conn.close()
			return

		if action != "register_loyalty_card":
			customer = self.customers[customer_json["loyalty_number"]]
			if not self.verify_signature(customer_m, customer_sig, customer.public_key):
				raise ValueError

		if action == "register_loyalty_card":
			data = self.handle_register_loyalty_card(customer_json["loyalty_number"], customer_json["public_key"])

		conn.send(data)
		conn.close()
	#
	def handle_make_purchase(self, loyalty_number, price, history):
		points = lambda x: price*dollar_to_points_no_history if msg["history"] == [] else price*dollar_to_points
		customers[customer_loyalty_number].points += points
		# TODO add history to customers

		return b"OK"
	#
	# def handle_check_balance(self, message, signature):
	#     if verify_signature(message, signature):
	#         msg = decrypt(message)
	#         customer_loyalty_number = msg["loyalty_number"]
	#         balance = customers[customer_loyalty_number].points
	#         #TODO: make the message
	#         self.encrypt_sign_send(M)
	#
	def handle_register_loyalty_card(self, loyalty_number, pk):
		rsakey = RSA.importKey(pk.encode('utf-8'))
		self.customers[loyalty_number] = CustomerData(rsakey)
		return b"OK"
	#
	# def handle_spend_points(self, message, signature):
	#         msg = decrypt(message)
	#         customer_loyalty_number = msg["loyalty_number"]
	#         points = msg["spend_num_points"]
	#         discount = points*(1/dollar_to_points)
	#         customers[customer_loyalty_number] -= points




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
