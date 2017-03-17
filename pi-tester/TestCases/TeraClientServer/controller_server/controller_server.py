import socket
import os
import cgi
import pdb

import BaseHTTPServer
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

CURRENT_FILE_PATH = os.path.dirname(__file__)


class MyHandle(BaseHTTPRequestHandler):

    def do_GET(self):
        self.gauth_client_html_page = os.path.join(CURRENT_FILE_PATH, 'gauth_client.html')
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        with open(self.gauth_client_html_page, 'rb') as f:
            self.wfile.write(f.read())

    def do_POST(self):
        if self.path == '/token':
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': self.headers['Content-Type']
                    }
            )

            with open('token.txt', 'wb') as f:
                f.write(form['token'].value)

            self.send_response(200)
            self.end_headers()
            self.wfile.write("Done")


class MyHTTPServer(BaseHTTPServer.HTTPServer):
    def server_bind(self):
        BaseHTTPServer.HTTPServer.server_bind(self)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def run_server(
        server_class=MyHTTPServer,
        handler_class=BaseHTTPServer.BaseHTTPRequestHandler):
    
    # ipv4 = '172.16.31.145'
    ipv4 = '127.0.0.1'
    server_address = (ipv4, 7070)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

if __name__ == '__main__':
    run_server(server_class=MyHTTPServer, handler_class=MyHandle)
