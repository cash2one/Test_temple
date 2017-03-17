"""
Fake GAuth server

localhost:8082 - Fake ArkFlex U server

Support Methods:
POST /api/account
"""
import socket
import os
import sys
import cgi
import pdb
import json
import re
import logging
import traceback

import fcntl
import struct
import BaseHTTPServer
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler


logging.basicConfig(filename='fake_arkflex.log', level=logging.DEBUG)
CURRENT_FILE_PATH = os.path.dirname(__file__)


class FakeArkFlexHandle(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        test_data = {
            'test1': 'test',
            'usage': 1
        }
        self.wfile.write(json.dumps(test_data))
        print self.path

    def available_path(self, path):
        return True if re.search(path, self.path) else False

    def do_DELETE(self):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                'REQUEST_METHOD': 'DELETE',
                # 'CONTENT_TYPE': self.headers['Content-Type']
            }
        )
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        result = {
            "result": True,
            "msg": "Fake ArkFlex Server U",
            "data": {
                "url": "todo",
                "headers": "headers"
            }
        }
        # pdb.set_trace()
        self.wfile.write(json.dumps(result))

    def do_POST(self):
        if self.path == '/api/account':
            # form = cgi.FieldStorage(
            #     fp=self.rfile,
            #     headers=self.headers,
            #     environ={
            #         'REQUEST_METHOD': 'POST',
            #         'CONTENT_TYPE': self.headers['Content-Type']
            #         }
            # )

            length = int(self.headers.getheader('content-length'))
            postvars = cgi.parse_qs(
                self.rfile.read(length),
                keep_blank_values=1)
            print postvars.keys()[0]
            # user_email = json.loads(postvars.keys()[0])['email']

            result = {
                "account_id": "hopebay",
                "password": "fakepassword",
                "access_key": "access_key",
                "secret_key": "secret_key"
            }

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result))

        else:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write('Payload is empty')

    def do_PUT(self):
        # for /api/account/<account name>
        if re.search('/api/account/.+', self.path):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "result": True,
                "password": ""
            }))


class FakeArkFlexServer(BaseHTTPServer.HTTPServer):

    def server_bind(self):
        BaseHTTPServer.HTTPServer.server_bind(self)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def run_server(
        server_class=BaseHTTPServer.HTTPServer,
        handler_class=BaseHTTPServer.BaseHTTPRequestHandler):

    # TODO templary design
    try:
        # ipv4 = socket.gethostbyname('localhost')
        ipv4 = get_ip_address('eth0')
        # ipv4 = '192.168.63.137'
        server_address = (ipv4, 5000)
        httpd = server_class(server_address, handler_class)
        print 'fake arkflex server start...'
        print(ipv4, 5000)
        httpd.serve_forever()
    except socket.error as e:
        print str(e)
    except:
        traceback.print_exc()


if __name__ == '__main__':
    run_server(server_class=FakeArkFlexServer, handler_class=FakeArkFlexHandle)
