
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from flask import Blueprint, Response, redirect, render_template, request, session
import secrets
import random
import struct


bp = Blueprint("certificates", __name__)


with open("instance/ticket_private_key.pem", "rb") as f:
	CAKEY = RSA.import_key(f.read())


def generate_certificate(key_generation, flags, device_id, title_id, account_id):
	issuer = "Root-CA00000003-XS00000021"
	if flags & 0x20: # No idea what this means
		issuer = "Root-CA00000003-XS00000024"
	
	# Let's hope that we don't get collisions here
	rom_id = random.randint(0x0100000000000000, 0x0100FFFFFFFFFFFF)
	
	ticket = issuer.encode() + bytes(0x40 - len(issuer))
	ticket += secrets.token_bytes(256) # Title key, we don't care
	ticket += bytes([2, 1, 0, 0, 0, key_generation, flags])
	ticket += bytes(9)
	ticket += struct.pack("<QQ", rom_id, device_id)
	ticket += struct.pack(">QQ", title_id, key_generation)
	ticket += struct.pack("<QQ", account_id, 0x2C0)
	
	sha = SHA256.new(ticket)
	signature = pkcs1_15.new(CAKEY).sign(sha)
	
	data = struct.pack("<I", 0x10004)
	data += signature + bytes(0x3C)
	return data + ticket


@bp.route("/certs", methods=["GET", "POST"])
def certificates():
	if "admin" not in session: return redirect("/login")
	
	if request.method == "POST":
		keygen = int(request.form["keygen"])
		flags = int(request.form["flags"])
		device_id = int(request.form["device_id"], 16)
		title_id = int(request.form["title_id"], 16)
		account_id = int(request.form["account_id"], 16)
		
		cert = generate_certificate(keygen, flags, device_id, title_id, account_id)
		
		response = Response(cert)
		response.headers.set("Content-Disposition", "attachment", filename="%016X.bin" %title_id)
		return response
	return render_template("certificates.html")
