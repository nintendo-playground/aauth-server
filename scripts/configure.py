
import secrets

env = {
	"COMPOSE_PROJECT_NAME": input("Project name: "),
	"DAUTH_ISS": input("Issuer (dauth): "),
	"AAUTH_ISS": input("Issuer (aauth): "),
	"DAUTH_JKU": input("JKU (dauth): "),
	"AAUTH_JKU": input("JKu (aauth): "),
	"AAUTH_PORT": input("Port (aauth): "),
	"ACERT_PORT": input("Port (acert): "),
	"AADMIN_PORT": input("Port (aadmin): "),
	"AADMIN_USERNAME": input("Username (aadmin): "),
	"AADMIN_PASSWORD": input("Password (aadmin): "),
	
	"AADMIN_SECRET_KEY": secrets.token_hex(16)
}

env = "".join("%s=%s\n" %(key, value) for key, value in env.items())

with open(".env", "w") as f:
	f.write(env)
