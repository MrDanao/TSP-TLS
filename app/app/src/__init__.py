from flask import Flask, render_template, request, send_from_directory
from flask_mysqldb import MySQL
import os

app = Flask(__name__)

app.config["MYSQL_HOST"] = "db"
app.config["MYSQL_DB"] = os.environ['MYSQL_DATABASE']
app.config["MYSQL_PASSWORD"] = os.environ['MYSQL_PASSWORD']
app.config["MYSQL_USER"] = os.environ['MYSQL_USER']
mysql = MySQL(app)

UPLOADS_DIRECTORY = "downloads"

if not os.path.exists(UPLOADS_DIRECTORY):
    os.makedirs(UPLOADS_DIRECTORY)

# def get_db():
#    db = sqlite3.connect( 'example.db', detect_types=sqlite3.PARSE_DECLTYPES)
#    cursor = db.cursor()
#    return cursor

def get_db():
   
   cursor = mysql.connection.cursor()
   return cursor

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        versions = get_version_client()
        client = request.form['client']
        server = request.form['serveur']
        tls_version = result_tls_version(request.form['client'], request.form['serveur'])
        data = result_ciphers_name(request.form['client'], request.form['serveur'], tls_version)
        
        return render_template('index.html', client=client, server=server, version=versions, tls_version=tls_version, data=data)
        
    else:
        versions = get_version_client()
        return render_template('index.html', version=versions)

@app.route('/uploads/<path:path>', methods=['GET'])
def download(path):

    return send_from_directory(UPLOADS_DIRECTORY, path)
      
def get_version_client():
    db_l = get_db()
    db_l.execute('''SELECT DISTINCT openssl_client_version FROM sessions''')
    data = db_l.fetchall()
    version = []
    for client in data:
        version.append(client[0])
    return version


def result_tls_version(client, serveur):
    db_l = get_db()
    query = "SELECT DISTINCT tls_version FROM sessions WHERE openssl_client_version=%s AND openssl_server_version=%s ORDER BY tls_version DESC"
    val = (client, serveur)
    db_l.execute(query, val)
    result = db_l.fetchall()
    tls_version = []
    for datas in result:
        for data in datas:
            tls_version.append(data) 
    return tls_version

def result_ciphers_name(client, serveur, tls_version):
    data_all = []
    for tls in tls_version:
        r_data = []
        db_l = get_db()
        query = "SELECT cipher, log, original_capture, decrypted_capture, tls_secrets, result  FROM sessions WHERE openssl_client_version=%s AND openssl_server_version=%s AND tls_version=%s"
        val = (client, serveur, tls)
        db_l.execute(query, val)
        result = db_l.fetchall()

        for resultat in result:
            data = {}
            data["CIPHER"] = resultat[0]
            data["LOG"] = resultat[1]
            data["OR_CAPT"] = resultat[2]
            data["DCRYPT_CAPT"] = resultat[3]
            data["TLS_SECRET"] = resultat[4]
            data["RESULT"] = resultat[5]
            r_data.append(data)
        
        data_all.append(r_data)
    return data_all


if __name__ == '__main__':
    app.run()
