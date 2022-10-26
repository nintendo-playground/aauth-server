
from Crypto.PublicKey import RSA
import base64
import json
import uuid
import time
import os


def encode(number):
	length = (number.bit_length() + 7) // 8
	data = number.to_bytes(length, "big")
	return base64.b64encode(data, b"-_").rstrip(b"=").decode()

def update():
	if os.path.isfile("instance/private.json"):
		with open("instance/private.json") as f:
			data = json.load(f)
		
		age = int(time.time()) - data["timestamp"]
		if age < 86400:
			time.sleep(86400 - age)
	
	keys = []
	if os.path.isfile("instance/public/keys"):
		with open("instance/public/keys") as f:
			keys = json.load(f)["keys"]
	
	rsa = RSA.generate(2048)
	key = {
		"kty": "RSA",
		"e": encode(rsa.e),
		"n": encode(rsa.n),
		"alg": "RS256",
		"use": "sig",
		"kid": str(uuid.uuid4())
	}
	keys = [key] + keys[:2]
	
	private_key = {
		"kid": key["kid"],
		"data": rsa.export_key().decode(),
		"timestamp": int(time.time())
	}
	with open("instance/private.json", "w") as f:
		json.dump(private_key, f, separators=(",", ":"))
	with open("instance/public/keys", "w") as f:
		json.dump({"keys": keys}, f, separators=(",", ":"))


while True:
	update()
