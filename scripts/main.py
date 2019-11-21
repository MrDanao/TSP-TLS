#!/usr/bin/env python

import os
import docker


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

    return versions


def exec_tls_session(docker_client, openssl_client_version, openssl_server_version):
    """Exécute une session TLS d'un client OpenSSL d'une version donnée vers un server OpenSSL d'une version donnée.

    Args:
        docker_client: Client Docker.
        openssl_client_version: Version OpenSSL du client sans les points.
        openssl_server_version: Version OpensSSL du serveur sans les points.

    Returns:
        Chaîne de caractères de la sortie standard de l'exécution de la session TLS.
    """
    container = docker_client.containers.get("client-" + openssl_client_version)
    res = container.exec_run(cmd="openssl s_client -connect server-" + openssl_server_version + ":443")
    stdout = res.output.decode("utf-8")

    return stdout


def write_tls_session_logs(logs, openssl_client_version, openssl_server_version):
    """Ecrit les logs d'une sessions TLS dans un fichier.

    Args:
        logs: Chaîne de caractères de la sortie standard de l'exécution de la session TLS.
        openssl_client_version: Version OpenSSL du client sans les points.
        openssl_server_version: Version OpensSSL du serveur sans les points.

    Returns:
        None
    """
    path = "results/"
    filename = openssl_client_version + "_to_" + openssl_server_version

    f = open(path + filename, "w+")
    f.write(logs)

    return None


def main():

    openssl_versions = list_openssl_versions("../docker-openssl")

    client = docker.from_env()

    for c in openssl_versions:
        for s in openssl_versions:
            tls = exec_tls_session(client, c, s)
            write_tls_session_logs(tls, c, s)


if __name__ == '__main__':
    main()

