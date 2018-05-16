import secrets
import numpy.random as rnd
import json

class Store:
    def __init__(self):
        self.id = secrets.randbits(64)

    def make_purchase(self, message, signature, purchases): # purchases is a list of tuples ("item", price in dollars)
        # this should happen all at once and the whole communication should be signed
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

        M = {"m":message,"s":signature, "history":purchase_history}
        # TODO encrypt
        # TODO sign
        # TODO send

    def check_balance(self, message, signature):
        #TODO
        pass

    def register_with_vendor(self, message, signature):
        # TODO
        pass

    def spend_points(self, message, signature):
        #TODO
        pass
