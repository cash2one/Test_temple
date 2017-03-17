"""
Fake Swift server

localhost:8080 - Fake Swift server

Support Methods:
POST /api/account
"""
import socket
import sys
import os
import cgi
import pdb
import json
from time import gmtime, strftime
import time

import fcntl
import struct
import BaseHTTPServer
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading


CURRENT_FILE_PATH = os.path.dirname(__file__)


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):

        # ipv4 = '192.168.63.137'
        # ipv4 = socket.gethostbyname('fake.backend')
        ipv4 = get_ip_address('eth0')
        # ipv4 = socket.gethostbyname(socket.gethostname())
        url = 'http://' + ipv4 + ':8080/swift/v1'

        delay_time = 0.472

        if self.path == '/auth/v1.0':

            # Case : for auth
            # url = 'http://' + socket.gethostbyname('fake.backend') + ':8080/swift/v1'
            storage_token = 'AUTH_rgwtk190000003030355451435244413644373a30303554514352444136443776484ce20829c398038e7457a647b41601dfa74228a0f8380ae8940f0f950917704fbe33'
            req_id = 'tx0000000000000001b8442-0057566900-b5a954-default'

            self.send_response(200)
            # self.send_header('Connection', 'keep-alive')
            self.send_header('Server', 'swift')
            self.send_header('X-Storage-Url', url)
            self.send_header('X-Storage-Token', storage_token)
            # self.send_header('x-amz-request-id', req_id)
            self.send_header('X-Auth-Token', 'auth-token')
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write('{"result": True,"code": 200}')

        elif '/swift/v1/' in self.path and 'data_' in self.path:

            # Case : for cache is old

            time.sleep(delay_time)

            obj_data_name = self.path.split('/')[-1]
            inode = obj_data_name.split('_')[1]

            with open(str(CURRENT_FILE_PATH) + '/../test_data/data/' +inode+'/'+ obj_data_name, 'rb') as f:
                content = f.read()
            self.send_response(201)
            self.send_header('Date', strftime("%a, %d %b %Y %X GMT", gmtime()))
            # self.send_header('Connection', 'keep-alive')
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('X-Timestamp', '1472018760')
            # self.send_header('X-Trans-Id', req_id)
            self.send_header('Content-Range', 'bytes 0-0/15')
            # self.set_header('Content-Length', '0')
            self.send_header('Last-Modified', 'Wed, 08 Jun 2016 07:59:15 GMT')
            self.send_header('etag', '78c69168d31dfd3c9fc8618815bcf0d7')
            self.send_header('Content-Type', 'binary/octet-stream')
            self.end_headers()
            self.wfile.write(str(content))

        elif '/swift/v1/' in self.path and 'meta_198' in self.path:

            # Case : for cache is old

            time.sleep(delay_time)

            meta_data = self.path.split('/')[-1]

            with open(str(CURRENT_FILE_PATH) + '/../test_data/meta/' + meta_data, 'rb') as f:
                content = f.read()

            self.send_response(200)
            self.send_header('Date', strftime("%a, %d %b %Y %X GMT", gmtime()))
            # self.send_header('Connection', 'keep-alive')
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('X-Timestamp', '1472118760')
            # self.send_header('X-Trans-Id', req_id)
            self.send_header('Content-Range', 'bytes 0-0/15')
            # self.set_header('Content-Length', '0')
            self.send_header('Last-Modified', 'Wed, 08 Jun 2016 07:59:15 GMT')
            self.send_header('etag', '78c69168d31dfd3c9fc8618815bcf0d7')
            self.send_header('Content-Type', 'binary/octet-stream')
            self.end_headers()
            self.wfile.write(str(content))

        elif '/swift/v1/' in self.path and 'meta_' in self.path:

            # Case : get all meta data

            time.sleep(delay_time)

            meta_data = self.path.split('/')[-1]

            with open(str(CURRENT_FILE_PATH) + '/../test_data/meta/' + meta_data, 'rb') as f:
                content = f.read()

            self.send_response(200)
            self.send_header('Date', strftime("%a, %d %b %Y %X GMT", gmtime()))
            # self.send_header('Connection', 'keep-alive')
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('X-Timestamp', '1472018760')
            # self.send_header('X-Trans-Id', req_id)
            self.send_header('Content-Range', 'bytes 0-0/15')
            # self.set_header('Content-Length', '0')
            self.send_header('Last-Modified', 'Wed, 08 Jun 2016 07:59:15 GMT')
            self.send_header('etag', '78c69168d31dfd3c9fc8618815bcf0d7')
            self.send_header('Content-Type', 'binary/octet-stream')
            self.end_headers()
            self.wfile.write(str(content))

        elif '/swift/v1/' in self.path and 'FSmgr_backup' in self.path:

            # Case : get FSmgr_backup data
            meta_data = self.path.split('/')[-1]

            with open(str(CURRENT_FILE_PATH) + '/../test_data/FSmgr_backup', 'rb') as f:
                content = f.read()

            self.send_response(200)
            self.send_header('Date', strftime("%a, %d %b %Y %X GMT", gmtime()))
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('X-Timestamp', '1472018760')
            # self.send_header('Connection', 'keep-alive')
            # self.send_header('X-Trans-Id', req_id)
            self.send_header('Content-Range', 'bytes 0-0/15')
            # self.set_header('Content-Length', '0')
            self.send_header('Last-Modified', 'Wed, 08 Jun 2016 07:59:15 GMT')
            self.send_header('etag', '78c69168d31dfd3c9fc8618815bcf0d7')
            self.send_header('Content-Type', 'binary/octet-stream')
            self.end_headers()
            self.wfile.write(str(content))

        elif '/swift/v1/' in self.path and 'FSstat' in self.path:

            # Case : get FSmgr_backup data
            meta_data = self.path.split('/')[-1]

            with open(str(CURRENT_FILE_PATH) + '/../test_data/'+meta_data, 'rb') as f:
                content = f.read()

            self.send_response(200)
            self.send_header('Date', strftime("%a, %d %b %Y %X GMT", gmtime()))
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('X-Timestamp', '1472018760')
            # self.send_header('Connection', 'keep-alive')
            # self.send_header('X-Trans-Id', req_id)
            self.send_header('Content-Range', 'bytes 0-0/15')
            # self.set_header('Content-Length', '0')
            self.send_header('Last-Modified', 'Wed, 08 Jun 2016 07:59:15 GMT')
            self.send_header('etag', '78c69168d31dfd3c9fc8618815bcf0d7')
            self.send_header('Content-Type', 'binary/octet-stream')
            self.end_headers()
            self.wfile.write(str(content))

        else:

            self.send_response(200)
            self.send_header('Server', 'swift')
            self.send_header('X-Storage-Url', url)
            self.send_header('X-Storage-Token', 'storage-token')
            self.send_header('X-Timestamp', '1472018760')
            self.send_header('X-Auth-Token', 'auth-token')
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write('{"result": Fl,"code": 200}')

    def do_PUT(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({
            "result": True,
            "code": 200
        }))

    def do_POST(self):
        if self.path == '/auth/v1.0':

            # For response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "result": True,
                "code": 200
            }))

        else:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write('{"result":True,"code":400}')


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def run_server(
        server_class=ThreadingMixIn,
        handler_class=HTTPServer):

    ipv4 = get_ip_address('eth0')
    server_address = (ipv4, 8080)
    httpd = ThreadedHTTPServer(server_address, handler_class)
    print 'fake swift server start...'
    print server_address
    httpd.serve_forever()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

if __name__ == '__main__':
    # server = ThreadedHTTPServer(('localhost', 8081), Handler)
    # print 'Starting server, use <Ctrl-C> to stop'
    # server.serve_forever()
    run_server((ThreadingMixIn, HTTPServer), Handler)
