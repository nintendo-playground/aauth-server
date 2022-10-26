
from Crypto.PublicKey import RSA

key = RSA.generate(2048)

print(key.export_key().decode())
print()
print(key.public_key().export_key().decode())
