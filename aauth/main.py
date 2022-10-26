
from Crypto.Util.Padding import unpad
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

from cachetools import cached, TTLCache
from flask import Flask, Response, request

from common import db

import datetime
import secrets
import string
import struct
import base64
import uuid
import time
import json
import jwt
import os

import logging
logger = logging.getLogger(__name__)


app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)


CLIENT_ID = "8f849b5d34778d8e"
SEED = bytes.fromhex("c0b274259082ddcbb929253c6cb6de")


with open("instance/rsa_private_key.pem", "rb") as f:
	RSA_PRIVATE_KEY = RSA.import_key(f.read())
with open("instance/ticket_public_key.pem", "rb") as f:
	TICKET_PUBLIC_KEY = RSA.import_key(f.read())


class AAuthError:
	OK = 0
	DEVICE_TOKEN_EXPIRED = 103
	ROMID_BANNED = 105
	UNAUTHORIZED_APPLICATION = 106
	SERVICE_CLOSED = 109
	APPLICATION_UPDATE_REQUIRED = 111
	INTERNAL_SERVER_ERROR = 112
	GENERIC = 118
	REGION_MISMATCH = 121


ERROR_MESSAGES = {
	AAuthError.DEVICE_TOKEN_EXPIRED: "Device token expired.",
	AAuthError.ROMID_BANNED: "ROM ID has been banned.",
	AAuthError.UNAUTHORIZED_APPLICATION: "Unauthorized application.",
	AAuthError.SERVICE_CLOSED: "Service closed.",
	AAuthError.APPLICATION_UPDATE_REQUIRED: "Application update is required.",
	AAuthError.INTERNAL_SERVER_ERROR: "Internal Server Error.",
	AAuthError.GENERIC: "Invalid parameter in request.",
	AAuthError.REGION_MISMATCH: "Region mismatch."
}

ERROR_STATUS = {
	AAuthError.DEVICE_TOKEN_EXPIRED: 400,
	AAuthError.ROMID_BANNED: 400,
	AAuthError.UNAUTHORIZED_APPLICATION: 400,
	AAuthError.SERVICE_CLOSED: 400,
	AAuthError.APPLICATION_UPDATE_REQUIRED: 400,
	AAuthError.INTERNAL_SERVER_ERROR: 500,
	AAuthError.GENERIC: 400,
	AAuthError.REGION_MISMATCH: 400
}


@cached(TTLCache(maxsize=1, ttl=600))
def get_jwt_key():
	with open("instance/private.json") as f:
		return json.load(f)


client = jwt.PyJWKClient(os.environ["DAUTH_JKU"])


def make_error(code):
	error = {"code": "%04i" %code, "message": ERROR_MESSAGES[code]}
	return {"errors": [error]}, ERROR_STATUS[code]

def check_token(token):
	issuer = os.environ["DAUTH_ISS"]
	try:
		jwk = client.get_signing_key_from_jwt(token)
		payload = jwt.decode(token, jwk.key, ["RS256"], audience=CLIENT_ID, issuer=issuer)
		return AAuthError.OK, payload
	except jwt.exceptions.ExpiredSignatureError:
		return AAuthError.DEVICE_TOKEN_EXPIRED, None
	except Exception:
		return AAuthError.GENERIC, None

def is_banned(rom_id):
	now = datetime.datetime.now()
	query = db.Ban.query
	query = query.filter(db.Ban.rom_id == rom_id)
	query = query.filter((db.Ban.start == None) | (db.Ban.start <= now))
	query = query.filter((db.Ban.end == None) | (db.Ban.end > now))
	return query.first() is not None

def verify_digital(app, token, cert, cert_key):
	try:
		cert = base64.b64decode(cert + b"==", b"-_")
		cert_key = base64.b64decode(cert_key + b"==", b"-_")
		
		rsa = PKCS1_OAEP.new(RSA_PRIVATE_KEY, SHA256)
		key = rsa.decrypt(cert_key)
		
		aes = AES.new(key, AES.MODE_CBC, iv=bytes(16))
		cert = unpad(aes.decrypt(cert), 16)
		
		if len(cert) != 0x2C0:
			return AAuthError.GENERIC
		if struct.unpack_from("<I", cert)[0] != 0x10004:
			return AAuthError.GENERIC
		if any(cert[0x104:0x140]):
			return AAuthError.GENERIC
		
		sha = SHA256.new(cert[0x140:])
		pkcs1_15.new(TICKET_PUBLIC_KEY).verify(sha, cert[4:0x104])
	except Exception:
		return AAuthError.GENERIC
	
	rom_id, device_id = struct.unpack_from("<QQ", cert, 0x290)
	title_id = struct.unpack_from(">Q", cert, 0x2A0)[0]
	if title_id != int(app.application_id, 16) or device_id != int(token["sub"], 16):
		return AAuthError.GENERIC
	if is_banned("%016x" %rom_id):
		return AAuthError.ROMID_BANNED
	return AAuthError.OK

@app.route("/v1/time")
def time_route():
	timestamp = int(time.time() * 1000)
	ip = request.headers["X-Forwarded-For"]
	
	text = "%s\n%s" %(timestamp, ip)
	
	response = Response(text, mimetype="text/plain")
	response.headers["X-NINTENDO-UNIXTIME"] = str(timestamp)
	response.headers["X-NINTENDO-GLOBAL-IP"] = ip
	return response

@app.route("/v3/challenge")
def challenge():
	token = request.form.get("device_auth_token", "")
	error, info = check_token(token)
	if error != AAuthError.OK:
		return make_error(error)
	return {
		"value": base64.b64encode(secrets.token_bytes(16), b"-_"),
		"seed": base64.b64encode(SEED, b"-_")
	}

def application_auth_token(version):
	error, info = check_token(request.form.get("device_auth_token", ""))
	if error != AAuthError.OK:
		return make_error(error)
	
	media_type = request.form.get("media_type", "")
	application_id = request.form.get("application_id", "")
	application_version = request.form.get("application_version", "")
	if len(application_id) != 16 or any(c not in string.hexdigits for c in application_id):
		return make_error(AAuthError.GENERIC)
	if len(application_version) != 8 or any(c not in string.hexdigits for c in application_version):
		return make_error(AAuthError.GENERIC)
	
	app = db.Application.query.filter_by(application_id=application_id).first()
	if media_type == "NO_CERT":
		if app is None or not app.allow_no_cert:
			return make_error(AAuthError.UNAUTHORIZED_APPLICATION)
	elif media_type == "SYSTEM":
		if app is None or not app.system_title:
			return make_error(AAuthError.GENERIC)
	elif media_type == "DIGITAL":
		if app is None:
			return make_error(AAuthError.GENERIC)
		cert = request.form.get("cert", "")
		cert_key = request.form.get("cert_key", "")
		
		error = verify_digital(app, info, cert, cert_key)
		if error != AAuthError.OK:
			return make_error(error)
	elif media_type == "GAMECARD":
		# Gamecards are not supported
		return make_error(AAuthError.GENERIC)
	
	if app.service_closed:
		return make_error(AAuthError.SERVICE_CLOSED)
	
	version = int(application_version[:4], 16)
	if version < app.application_version:
		return make_error(AAuthError.APPLICATION_UPDATE_REQUIRED)
	
	opp = app.online_play_policy
	ph = app.policy_handler
	
	iat = int(time.time())
	payload = {
		"sub": app.application_id,
		"exp": iat + 86400,
		"iat": iat,
		"iss": os.environ["AAUTH_ISS"],
		"jti": str(uuid.uuid4()),
		"nintendo": {
			"ai": app.application_id,
			"av": application_version[:4],
			"at": iat,
			"edi": secrets.token_hex(16),
			"opp": opp
		}
	}
	
	if app.flags & db.ApplicationFlags.SYSTEM_TITLE:
		payload["nintendo"]["di"] = info["sub"]
		payload["nintendo"]["sn"] = info["nintendo"]["sn"]
		payload["nintendo"]["pc"] = info["nintendo"]["pc"]
		payload["nintendo"]["dt"] = info["nintendo"]["dt"]
		payload["nintendo"]["ist"] = info["nintendo"]["ist"]
	
	payload["nintendo"]["opp"] = opp
	if opp == "MEMBERSHIP_REQUIRED":
		payload["nintendo"]["ph"] = ph
	
	key = get_jwt_key()
	headers = {
		"jku": os.environ["AAUTH_JKU"],
		"kid": key["kid"]
	}
	
	token = jwt.encode(payload, key["data"], "RS256", headers)
	response = {
		"expires_in": 86400,
		"application_auth_token": token,
		"settings": [], # TODO
		"online_play_policy": opp
	}
	if opp == "MEMBERSHIP_REQUIRED":
		response["policy_handler"] = ph
	return response


v2_hash = "44cd4221f90742b5f37a4948b37dacf024d0bb14dde86db0af20ec300a36a0fe"

app.add_url_rule("/v2-%s/application_auth_token" %v2_hash, "v2_aauth", lambda: application_auth_token(2), methods=["POST"])
app.add_url_rule("/v3/application_auth_token", "v3_aauth", lambda: application_auth_token(3), methods=["POST"])

app.register_error_handler(400, lambda e: make_error(AAuthError.GENERIC))
app.register_error_handler(403, lambda e: make_error(AAuthError.GENERIC))
app.register_error_handler(404, lambda e: make_error(AAuthError.GENERIC))
app.register_error_handler(405, lambda e: make_error(AAuthError.GENERIC))
app.register_error_handler(500, lambda e: make_error(AAuthError.INTERNAL_SERVER_ERROR))
