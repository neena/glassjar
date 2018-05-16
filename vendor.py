import socket
import asyncore
from threading import Thread
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
		self.store_key = SHA256.new(Random.get_random_bytes(16)).digest() #TODO generate session keys
		self.customers = {}
		self.store_public_keys = {}

		self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.soc.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
		self.soc.bind((TCP_IP, TCP_PORT))
		self.soc.listen()

		p = Thread(target=self.listen_on_soc)

		p.start()


	def listen_on_soc(self):
		while True:
			conn, addr = self.soc.accept()
			p = Thread(target=self.connection_handler,args=(conn,))
			p.start()


	def connection_handler(self, conn):
		recieved_data = conn.recv(BUFFER_SIZE)
		recieved_data = json.loads(recieved_data.decode('utf-8'))

		if "action" in recieved_data:
			if recieved_data["action"] == "register_store":
				data = self.handle_register_store(recieved_data["store_id"], recieved_data["public_key"])
			elif recieved_data["action"] == "get_public_key":
				data = self.public_key.exportKey()
		else:
			enc = recieved_data["enc"]
			sig = recieved_data["sig"]
			json_obj = json.loads(self.decrypt(enc).decode('utf-8'))

			store_public_key = self.store_public_keys[json_obj["store_id"]]
			if not self.verify_signature(enc, sig, store_public_key):
				raise ValueError

			action = json_obj["action"]
			customer_m = json_obj["m"]
			customer_sig = json_obj["s"]
			customer_json = json.loads(json_obj["m"])

			data = "NO"


			if int(datetime.utcnow().timestamp()) - customer_json["timestamp"] > 30:
				conn.close()
				return
			print(action)
			if action != "register_loyalty_card":
				customer = self.customers[customer_json["loyalty_number"]]
				if not self.verify_signature(customer_m, customer_sig, customer.public_key):
					raise ValueError

			if action == "register_loyalty_card":
				data = self.handle_register_loyalty_card(customer_json["loyalty_number"], customer_json["public_key"])
			elif action == "make_purchase":
				data = self.handle_make_purchase(customer, json_obj["price"], json_obj["history"])
			elif action == "check_balance":
				data = self.handle_check_balance(customer)
			elif action == "spend_points":
				data = self.handle_spend_points(customer, customer_json["spend_num_points"])

		conn.send(data)
		conn.close()
	#
	def handle_register_store(self, store_id, public_key):
		rsakey = RSA.importKey(public_key.encode('utf-8'))
		self.store_public_keys[store_id] = rsakey
		return rsakey.encrypt(self.store_key, 32)[0]

	def handle_make_purchase(self, customer, price, history):
		if history == []:
			points = price*dollar_to_points_no_history
		else:
			points = price*dollar_to_points
		customer.points += points
		for item, cost in history:
			if item in customer.purchases:
				customer.purchases[item] += 1
			else:
				customer.purchases[item] = 1
		print(customer.purchases)
		# print("you got points!! ", customer.points)

		return b"OK"
	#
	def handle_check_balance(self, customer):
	    return self.encrypt(str(customer.points))

	def handle_register_loyalty_card(self, loyalty_number, pk):
		rsakey = RSA.importKey(pk.encode('utf-8'))
		self.customers[loyalty_number] = CustomerData(rsakey, loyalty_number)
		return b"OK"
	#
	def handle_spend_points(self, customer, num_points):
		if num_points > customer.points:
			num_points = customer.points
		discount = num_points*(1/dollar_to_points)
		customer.points -= num_points
		discount = str(discount)
		sig = self.sign(discount)

		return json.dumps({"sig":sig, "discount":discount}).encode('utf-8')

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

	def make_results_differentially_private(self, results, epsilon=2):
		dp_results = []
		la = len(results)/(len(self.customers)*epsilon)
		for result in results:
			dp_results.append(result + rnd.laplace(0, la))
		return dp_results

	def get_dp_counting_queries(self, queries):
	# list of queries. queries are lists
	# eg. ["OR", x, y] => customers who bought x or y
	# eg. ["AND", a, b, c] => customers who bought a and b and c
		results = [0]*len(queries)
		for customer in self.customers:
			for i in range(0,len(queries)):
				query = queries[i]
				if query[0] == "OR":
					for item in query[1:]:
						if item in customer.purchases:
							results[i] += 1
							break
				elif query[0] == "AND":
					results[i] += 1
					for item in query[1:]:
						if item not in customer.purchases:
							results[i] -= 1
							break
		for i in range(0,len(queries)):
			results[i] = results[i]/len(self.customers)

		return self.make_results_differentially_private(results)
