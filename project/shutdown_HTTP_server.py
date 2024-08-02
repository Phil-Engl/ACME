import flask
import threading
import os, signal

response_header = "application/octet-stream"

def Terminator_Thread( host, port):
    app = flask.Flask(__name__)

    @app.route('/')
#try:
    def shutdown():
        print("Shutting down stuff... \n")
        os.kill(os.getpid(), signal.SIGINT)
        response = flask.Response("killed")
        response.headers['Content-Type'] = response_header
        return response

    app.run(host=host, port=port)
    #except Exception as e:
    #    print("done here...")

class MyTerminator:
    def __init__(self, HOST, PORT):
        self.HOST = HOST
        self.PORT = PORT


    def start(self):
        print(f"starting terminator at {self.HOST}:{self.PORT}")
        
        thread = threading.Thread(target=Terminator_Thread, args=( self.HOST, self.PORT), daemon=True)
        thread.start()
        return thread
