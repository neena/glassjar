import socket
import asyncore
from multiprocessing import Process
import atexit
import json


TCP_IP = 'localhost'
TCP_PORT = 19997
BUFFER_SIZE = 8192

class Vendor:
    def __init__(self):
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
      print(enc)
      conn.send(data)
      conn.close()

    def handle_make_purchase(self, message, signature):
        #TODO
        pass

    def handle_check_balance(self, message, signature):
        #TODO
        pass

    def handle_register_with_vendor(self, message, signature):
        # TODO
        pass

    def handle_spend_points(self, message, signature):
        #TODO
        pass
