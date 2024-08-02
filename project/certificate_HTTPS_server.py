import flask
import threading
import os, signal

response_header = "application/octet-stream"

def Cert_Server_Thread( host, port, cert_file, priv_key_file):
    app = flask.Flask(__name__)

    @app.route('/')
    def hello():
        with open(cert_file, 'rb') as cert, open(priv_key_file, 'rb') as key:
            certificate = cert.read()
            private_key = key.read()
            return certificate

    app.run(host=host, port=port, ssl_context=(cert_file, priv_key_file))

class MyCERTServer:
    def __init__(self, HOST, PORT, cert_file, key_file):
        self.HOST = HOST
        self.PORT = PORT
        self.cert_file = cert_file
        self.priv_key_file = key_file

    def add_token(self, token):
        new_tokens = self.valid_tokens + [token] 
        self.valid_tokens = new_tokens

    def start(self):
        print(f"starting certificate server at {self.HOST}:{self.PORT}")
        thread = threading.Thread(target=Cert_Server_Thread, args=( self.HOST, self.PORT, self.cert_file, self.priv_key_file), daemon=True)
        thread.start()
        return thread
