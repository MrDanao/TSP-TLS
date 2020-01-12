# Projet TLS @TelecomSudParis

## Requirements

- docker-ce
- docker-compose
- python3
- virtualenv
- wireshark >= 3.2.0

## Dossier `network/`

Pour établir le réseau de plusieurs serveurs et clients OpenSSL.

### Dockerfile

1 Dockerfile par version d'OpenSSL :
- `docker-openssl/1.0.2t/Dockerfile`
- `docker-openssl/1.0.2u/Dockerfile`
- `docker-openssl/1.1.0l/Dockerfile`
- `docker-openssl/1.1.1d/Dockerfile`

### Docker-Compose

- 1 réseau `tls-nework`. L'hôte fournit le bridge, ayant une interface réseau sur ce réseau, elle sera utilisée pour les captures de trames avec Wireshark.
- 1 container `server-102t`, directement lancé comme serveur OpenSSL 1.0.2t.
- 1 container `server-102u`, directement lancé comme serveur OpenSSL 1.0.2u.
- 1 container `server-110l`, directement lancé comme serveur OpenSSL 1.1.0l.
- 1 container `server-111d`, directement lancé comme serveur OpenSSL 1.1.1d.
- 1 container `client-102t` qui peut servir de client OpenSSL 1.0.2t ou HTTPS avec cURL.
- 1 container `client-102u` qui peut servir de client OpenSSL 1.0.2u ou HTTPS avec cURL.
- 1 container `client-110l` qui peut servir de client OpenSSL 1.1.0l ou HTTPS avec cURL.
- 1 container `client-111d` qui peut servir de client OpenSSL 1.1.1d ou HTTPS avec cURL.
- Certificat et clé privé par défault utilisés par les containers `server-*`, dans `cert/`.

Tous les containers sont attachés au réseau `tls-network`.

### Use

```
$ docker-compose build
$ docker-compose up -d
```

## Dossier `app/`

On y trouve l'application Flask ainsi que la base de données. La base de données est populée par le script `REPO/scripts/main.py`. Voir la section `Dossier scripts/`.

Source code dans `app/src/`.
Dump de la base de données dans `db/dump/`.

### Use

Builder et lancer l'application Flask et la base de données MySQL :

```
$ docker-compose build
$ docker-compose up -d
```

Ce docker-compose lance :
- container `tls-app` attaché aux réseaux `tls-app` et `tls-db`
- container `tls-db` attaché au réseau `tls-db` seulement

Afficher et suivre le debug de l'application Flask :

```
$ docker logs -f tls-app
```

### Client MySQL dans le container `tls-app`

Le container `tls-app` n'a pas besoin de connaître l'adresse IP du container `tls-db`. L'usage du host "tls-db" suffit.

Les containers `tls-app` et `tls-db` se partagent les variables d'environnement suivantes : `MYSQL_ROOT_PASSWORD`, `MYSQL_DATABASE`, `MYSQL_USER` et `MYSQL_PASSWORD`. Le container `tls-app` peut alors réutiliser ces variables d'environnement pour configurer son client MySQL, ainsi se connecter à la base de données de `tls-db`.

## Dossier `scripts/`

Le script Python `main.py` permet d'établir des sessions TLS vers tous les serveurs OpenSSL depuis chaque client OpenSSL, pour chaque version de TLS et ciphers supportés.

Le script fournit pour chaque session dans le dossier `results/` :
- logs de session
- fichier de capture de trames
- fichier de capture de trames déchiffrée si la session a été correctement établie
- secrets TLS si la session a été correctement établie

Les données de chaque session sont insérées dans une base de données MySQL. Voir la section `Dossier app/`.

### Use

La base de données MySQL doit être up and running :

```
$ cd REPO/app/
$ docker-compose up -d
```

Les client et serveurs OpenSSL doivent être up and running :

```
$ cd REPO/network/
$ docker-compose up -d
```

Préparation de l'environnement virtuel Python :

```
$ cd REPO/scripts/
$ virtualenv -p python3 ~/.venv/tsp-tls
$ source ~/.venv/tsp-tls/bin/activate
$ pip install -r requirements.txt
```

Donner les droits de capture par Scapy pour Python et Tcpdump :

```
$ which python3
~/.venv/tsp-tls/bin/python3
$ sudo setcap cap_net_raw=eip ~/.venv/tsp-tls/bin/python3
$ which tcpdump
/usr/sbin/tcpdump
$ sudo setcap cap_net_raw=eip /usr/sbin/tcpdump
```

Lancer le script Python :

```
$ chmod +x main.py
$ ./main.py
```