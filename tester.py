from customer import Customer
from store import Store

c = Customer()
resp = c.get("send_history")

s = Store()
s.make_purchase(*resp, [("apples",1)])
