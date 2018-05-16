from customer import Customer
from store import Store
from vendor import Vendor
from time import sleep

c = Customer()
v = Vendor()
sleep(1)
s = Store()

msg, sig = c.get("public_key")
s.register_loyalty_card(msg, sig)
# s.make_purchase(*resp, [("apples",1)])
