# Projet TLS

## Requirements

- docker-ce
- docker-compose
- python3
- virtualenv

## Quelques détails

### Dockerfile

1 Dockerfile par version d'OpenSSL :
- `docker-openssl/1.0.2t/Dockerfile`
- `docker-openssl/1.1.0l/Dockerfile`
- `docker-openssl/1.1.1d/Dockerfile`

### Docker-Compose

- 1 réseau `tls`. L'hôte fournit le bridge, ayant une interface réseau sur ce réseau, elle sera utilisée pour les captures de trames avec Wireshark.
- 1 container `server-102t`, directement lancé comme serveur OpenSSL 1.0.2t.
- 1 container `server-110l`, directement lancé comme serveur OpenSSL 1.1.0l.
- 1 container `server-111d`, directement lancé comme serveur OpenSSL 1.1.1d.
- 1 container `client-102t` qui peut servir de client OpenSSL 1.0.2t ou HTTPS avec cURL.
- 1 container `client-110l` qui peut servir de client OpenSSL 1.1.0l ou HTTPS avec cURL.
- 1 container `client-111d` qui peut servir de client OpenSSL 1.1.1d ou HTTPS avec cURL.
- Certificat et clé privé par défault utilisés par les containers `server-*`, dans `cert/`.
- Output des secrets TLS dans `keylog/key.log`. Notamment utilisé pour déchiffrer les messages HTTPS (ou autre) avec Wireshark.

Tous les containers sont connectés au réseau `tls`.

## Use

```
$ docker-compose build
$ docker-compose up -d
```

## bac à sable

### HTTPS Client vers Server

```
$ docker exec -it client-102t curl -k https://server-102t
$ docker exec -it client-102t openssl s_client -connect server-111d:443
```

Le serveur OpenSSL 1.1.1d est lancé avec le paramètre `-keylogfile`. Dès la première connexion TLS, le fichier `keylog/key.log` (sur l'hôte) peut être exploité par Wireshark pour déchiffrer les messages HTTPS.

- Wireshark (sur l'hôte) :

Lancer Wireshark. Onglet Editer > Préférences > Protocols > SSL > (Pre)-Master-Secret log filename = le fichier `keylog/key.log`. Valider. Sélectionner la bonne interface sur laquelle capturer, exemple : `br-012345abcdef`.

Un exemple de capture avec un message HTTPS déchiffré :

![HTTPS déchiffré](img/wireshark_https_dechiffre.png)

Pour les versions d'OpenSSL 1.0.2t et 1.1.0l, l'extraction des keylogs n'est pas implémentée. Il est possible de les obtenir depuis `client-102t` ou `client-110l` avec les exemples suivants en utilisant cURL :

```
$ SSLKEYLOGFILE=./secrets.keylog curl -k https://server-102t
$ SSLKEYLOGFILE=./secrets.keylog curl -k https://server-111d
```

### Automatisation de l'exécution des sessions TLS

Dans le dossier `scripts/`.

Le script Python `main.py` permet d'établir des sessions TLS vers tous les serveurs OpenSSL depuis chaque client OpenSSL.

Pour le moment ce script récupère seulement la sortie standard des clients et les écrit dans le dossier `results/`.

```
$ cd scripts/
$ virtualenv -p python3 ~/.venv/tsp-tls
$ source ~/.venv/tsp-tls/bin/activate
$ pip install -r requirements.txt
$ chmod +x main.py
$ ./main.py
```

:satisfied: :hand: A revoir : la commande `docker exec -it ...` semble donner davantage de logs (session TLS pas totalement établie à l'aide de Python?)...