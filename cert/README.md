Certificat et clé privé par défaut utilisés par le serveur TLS. Générés à l'aide de la commande suivante (sur l'hôte) :

```
$ openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```