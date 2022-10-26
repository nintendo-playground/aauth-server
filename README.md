This is the source code for the application authentication server, including an admin panel. Documentation is available [here](https://github.com/kinnay/nintendoclients/wiki/AAuth-Server).

Example configuration for localhost:
```
COMPOSE_PROJECT_NAME: 
DAUTH_ISS: dauth-lp1.ndas.srv.nintendo-playground.com
DAUTH_JKU: https://dcert-lp1.ndas.srv.nintendo-playground.com/keys
AAUTH_ISS: aauth-localhost
AAUTH_JKU: http://localhost:10001/keys
AAUTH_PORT: 10000
ACERT_PORT: 10001
AADMIN_PORT: 10002
AADMIN_USERNAME: test
AADMIN_PASSWORD: test
```

Before starting the service, the following files must be placed into the `instance` folder (create it if it does not exist):
* `rsa_private_key.pem`: the private key that is used to decrypt the `cert_key` parameter in authentication requests for digital titles.
* `ticket_private_key.pem`: the private key that is used to sign certificates for digital titles. This is used by the admin panel.
* `ticket_public_key.pem`: the public key that is used to verify certificates for digital titles.

For convenience, `scripts/generate_keys.py` generates a public and private key and prints them to stdout.
