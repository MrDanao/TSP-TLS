#!/usr/bin/env python

import os
import docker


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def list_openssl_versions(path="../docker-openssl"):
    """Liste les versions d'OpenSSL utilisées avec le formatage adapté sans les points.

    Args:
        path: Chemin des Dockerfile pour chaque version, par défaut ../docker-openssl.

    Returns:
        Liste des version OpenSSL utilisées, sans les points : 111d pour 1.1.1d.
    """
    versions = []

    for v in os.listdir(path):
        v = v.replace(".", "")
        versions.append(v)

    versions.sort()

    return versions


def exec_tls_session(docker_client, openssl_client_version, openssl_server_version, tls_version, cipher):
    """Exécute une session TLS d'un client OpenSSL d'une version donnée vers un server OpenSSL d'une version donnée.

    Args:
        docker_client: Client Docker.
        openssl_client_version: Version OpenSSL du client sans les points.
        openssl_server_version: Version OpensSSL du serveur sans les points.
        tls_version: Version de TLS utilisée.
        cipher: Nom du cipher utilisé.

    Returns:
        Exit code et sortie standard de l'exécution de la session TLS.
    """
    container = docker_client.containers.get("client-" + openssl_client_version)

    if tls_version == "1_3":
        if "111" in openssl_client_version:
            res = container.exec_run(cmd="openssl s_client -connect server-" + openssl_server_version + ":443 -ciphersuites " + cipher + " -tls" + tls_version + " -keylogfile tls.secrets")
        else:
            res = container.exec_run(
                cmd="openssl s_client -connect server-" + openssl_server_version + ":443 -ciphersuites " + cipher + " -tls" + tls_version)
    else:
        res = container.exec_run(cmd="openssl s_client -connect server-" + openssl_server_version + ":443 -cipher " + cipher + " -tls" + tls_version)

    status = res.exit_code
    stdout = res.output.decode("utf-8")

    return status, stdout


def tls_session_passed(session):
    """Donne le status de la session TLS.

    Args:
        session: Exit code et sortie standard de l'exécution de la session TLS.

    Returns:
        True si la session TLS passed, sinon False.
    """
    tls_session_exit_code = session[0]

    if tls_session_exit_code == 0:
        return True
    else:
        return False


def write_tls_session_logs(session, openssl_client_version, openssl_server_version, tls_version, cipher):
    """Ecrit les logs d'une sessions TLS dans un fichier.

    Args:
        session: Exit code et sortie standard de l'exécution de la session TLS.
        openssl_client_version: Version OpenSSL du client sans les points.
        openssl_server_version: Version OpensSSL du serveur sans les points.
        tls_version: Version TLS de utilisée.
        cipher: Nom du cipher utilisé.

    Returns:
        None
    """
    path = "results/client_" + openssl_client_version + "/server_" + openssl_server_version + "/tls" + tls_version + "/"
    tls_session_stdout = session[1]

    filename = cipher + ".log "

    if not os.path.exists(path):
        os.makedirs(path)

    f = open(path + filename, "w+")
    f.write(tls_session_stdout)

    return None


def get_ciphers(docker_client, openssl_client_version, tls_version):
    """Donne la liste des ciphers supportés.

    Args:
        docker_client: Client Docker.
        openssl_client_version: Version OpenSSL du client sans les points.
        tls_version: Version TLS de utilisée.

    Returns:
        Liste de ciphers.
    """
    container = docker_client.containers.get("client-" + openssl_client_version)

    if "102" in openssl_client_version:
        res = container.exec_run(cmd="openssl ciphers -tls" + tls_version)
    else:
        res = container.exec_run(cmd="openssl ciphers -s -tls" + tls_version)

    stdout = res.output.decode("utf-8").rstrip('\n')
    ciphers = stdout.split(":")

    return ciphers


def get_tls_versions(openssl_version):
    """Donne la liste des versions de TLS supportées.

    Args:
        openssl_version: Version d'OpenSSL.

    Returns:
        Liste des versions de TLS.
    """
    tls_versions = []

    if "102" in openssl_version:
        tls_versions = ["1"]
    elif "110" in openssl_version:
        tls_versions = ["1", "1_1", "1_2"]
    elif "111" in openssl_version:
        tls_versions = ["1", "1_1", "1_2", "1_3"]

    return tls_versions


def get_tls_session_secrets(docker_client, session, openssl_client_version, tls_version):
    """Donne les secrets d'une session TLS.

    Args:
        docker_client: Client Docker.
        session: Exit code et sortie standard de l'exécution de la session TLS.
        openssl_client_version: Version OpenSSL du client sans les points.
        tls_version: Version TLS de utilisée.

    Returns:
        Secrets d'une session TLS avec le bon format.
    """
    formatted_tls_secrets = "None"

    if tls_session_passed(session):
        if tls_version == "1_3":
            if "111" in openssl_client_version:
                container = docker_client.containers.get("client-" + openssl_client_version)
                res = container.exec_run(cmd="cat tls.secrets")
                formatted_tls_secrets = res.output.decode("utf-8")
                container.exec_run(cmd="rm tls.secrets")
        else:
            logs = session[1]
            session_id = ""
            master_key = ""
            for line in logs.split("\n"):
                if "Session-ID:" in line:
                    session_id = line.replace(" ", "").split(":")[1]
                elif "Master-Key:" in line:
                    master_key = line.replace(" ", "").split(":")[1]
                formatted_tls_secrets = "RSA Session-ID:" + session_id + " Master-Key:" + master_key + "\n"

    return formatted_tls_secrets


def write_tls_session_secrets(tls_secrets, openssl_client_version, openssl_server_version, tls_version, cipher):
    """Ecrit les secrets d'une session TLS avec le bon format dans un fichier.

    Args:
        tls_secrets: Secrets d'une session TLS avec le bon format.
        openssl_client_version: Version OpenSSL du client sans les points.
        openssl_server_version: Version OpensSSL du serveur sans les points.
        tls_version: Version TLS de utilisée.
        cipher: Nom du cipher utilisé.

    Returns:
        None
    """
    path = "results/client_" + openssl_client_version + "/server_" + openssl_server_version + "/tls" + tls_version + "/"
    filename = cipher + ".secrets"

    if not os.path.exists(path):
        os.makedirs(path)

    f = open(path + filename, "w+")
    f.write(tls_secrets)

    return None


def main():

    openssl_versions = list_openssl_versions("../docker-openssl")
    docker_client = docker.from_env()

    for c in openssl_versions:
        tls_versions = get_tls_versions(c)
        for tls_version in tls_versions:
            ciphers = get_ciphers(docker_client, c, tls_version)
            for cipher in ciphers:
                for s in openssl_versions:
                    session = exec_tls_session(docker_client, c, s, tls_version, cipher)
                    write_tls_session_logs(session, c, s, tls_version, cipher)
                    if tls_session_passed(session):
                        tls_secrets = get_tls_session_secrets(docker_client, session, c, tls_version)
                        write_tls_session_secrets(tls_secrets, c, s, tls_version, cipher)
                    print("[" + bcolors.OKGREEN + "DONE" + bcolors.ENDC + "] Client " + c + " | Server " + s + " | TLS " + tls_version + " | " + cipher)


if __name__ == '__main__':
    main()

