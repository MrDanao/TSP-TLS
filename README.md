# Projet TLS

## Requirements

- docker-ce
- docker-compose

## Quelques détails

- Dockerfile (`generic-openssl/Dockerfile`): Alpine / Paquets : openssl, curl.
- 1 réseau `tls`. L'hôte fournit le bridge, ayant une interface réseau sur ce réseau, elle sera utilisée pour les captures de trames avec Wireshark.
- 1 container `server`, directement lancé comme serveur OpenSSL. Buildé depuis le Dockerfile. Connecté au réseau `tls`.
- 1 container `client` qui peut servir de client OpenSSL ou HTTP/S avec cURL. Buildé depuis le Dockerfile. Connecté au réseau `tls`.
- Certificat TLS et clé privé par défault utilisés par le container `server`, dans `cert/`.
- Output des secrets TLS dans `keylog/key.log`. Notamment utilisé pour déchiffrer les messages HTTPS (ou autre) avec Wireshark.

## Use

```
$ docker-compose build
$ docker-compose up -d
```

## bac à sable

- HTTPS Client vers Server :

```
$ docker exec -it server curl https://server
```

Le serveur OpenSSL est lancé avec le paramètre `-keylogfile`. Dès la première connexion TLS, le fichier `keylog/key.log` (sur l'hôte) peut être exploité par Wireshark pour déchiffrer les messages HTTPS.

- Wireshark (sur l'hôte) :

Lancer Wireshark. Onglet Editer > Préférences > Protocols > SSL > (Pre)-Master-Secret log filename = le fichier `keylog/key.log`. Valider. Sélectionner la bonne interface sur laquelle capturer, exemple : `br-012345abcdef`.

Un exemple de capture avec un message HTTPS déchiffré :

![HTTPS déchiffré](img/wireshark_https_dechiffre.png)
