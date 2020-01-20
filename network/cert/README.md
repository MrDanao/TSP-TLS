Certificat et clé privée RSA et ECDSA par défaut utilisés par les serveurs TLS.

RSA :

```
$ openssl req -x509 -newkey rsa:2048 -keyout rsa_key.pem -out rsa_cert.pem -days 365 -nodes
```

ECDSA :

```
$ openssl ecparam -out ecdsa_key.pem -name prime256v1 -genkey
$ openssl req -new -key ecdsa_key.pem -x509 -nodes -days 365 -out ecdsa_cert.pem
```