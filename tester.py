from customer import Customer
from store import Store
from vendor import Vendor
from time import sleep

c = Customer()
resp = c.get("send_history")

v = Vendor()
sleep(1)
s = Store()
s.make_purchase(*resp, [("apples",1)])
