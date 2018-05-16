class CustomerData():
	def __init__(self, public_key, loyalty_number):
		self.loyalty_number = loyalty_number
		self.public_key = public_key
		self.purchases = {}
		self.points = 0
