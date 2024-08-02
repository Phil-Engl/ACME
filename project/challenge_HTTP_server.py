import flask
import threading
import os, signal

well_known_prefix = '/.well-known/acme-challenge/<token>'
response_header = "application/octet-stream"

def HTTP_Thread( host, port, valid_tokens, Thumbprint):
    app = flask.Flask(__name__)
    @app.route('/.well-known/acme-challenge/<token>', methods=['GET'])
    def reply(token):
        if token in valid_tokens:
            id_auth = str(token + "." + Thumbprint)
            response = flask.Response(id_auth)
            response.headers['Content-Type'] = response_header
            return response

        if token == "shutdown":
            print("Shutting down http server... \n")
            os.kill(os.getpid(), signal.SIGINT)

    app.run(host=host, port=port)

class MyHTTPServer:
    def __init__(self, HOST, PORT, Thumbprint):
        self.well_known_prefix = '/.well-known/acme-challenge/<token>'
        self.response_header = "application/octet-stream"
        self.HOST = HOST
        self.PORT = PORT
        self.Thumbprint = Thumbprint
        self.valid_tokens = []


    def add_token(self, token):
        new_tokens = self.valid_tokens + [token]
        self.valid_tokens = new_tokens

    def start(self):
        print(f"starting http server at {self.HOST}:{self.PORT}")
        thread = threading.Thread(target=HTTP_Thread, args=( self.HOST, self.PORT, self.valid_tokens, self.Thumbprint), daemon=True)
        thread.start()
        return thread
