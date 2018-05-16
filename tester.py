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

resp = c.get("send_history")
s.make_purchase(*resp, [("apples",1)])

resp = c.get("")
s.check_balance(*resp)

resp = c.get("spend_num_points")
s.spend_points(*resp)
