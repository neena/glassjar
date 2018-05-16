from customer import Customer
from store import Store

c = Customer()
m, sig = c.generate_message("send_history","y")

s = Store()
s.make_purchase(m, sig, [("apples",1)])
