#!/usr/bin/env python

import sys
import argparse
import magic
from pathlib import Path
from ipaddress import ip_address
from functools import cached_property
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qsl, urlparse
from threading import Lock
import ssl
import json
from pprint import pprint

class Data:
    __data = {
            "lock_msg": [
                "423: Locked",
                "423: Unlocked",
                "409: Conflict"
            ],
            "lock": False,
            "defaults": {
                "version": 4
            }
        }
    __data['data'] = __data['defaults']

    # This is the thread lock and data['lock'] is the hashicorp lock
    __lock = Lock()

    @classmethod
    def set(self, name, data):
        with self.__lock:
            self.__data[name] = data

    @classmethod
    def get(self, *args):
        with self.__lock:
            collection = self.__data
            for el in args:
                if type(collection) == dict:
                    if el in collection.keys():
                        tmp = collection[el]
                        collection = tmp
                    else:
                        return f"""Undefined [{el}] in [{"][".join(parts)}]"""
                elif type(collection) == list:
                    elint = int(el)
                    if elint <= len(collection):
                        tmp = collection[elint]
                        collection = tmp
                    else:
                        return f"""Undefined [{el}] in [{"][".join(parts)}]"""
            return collection

class Handler(BaseHTTPRequestHandler):

    @cached_property
    def url(self):
        return urlparse(self.path)

    @cached_property
    def query_data(self):
        return dict(parse_qsl(self.url.query))

    @cached_property
    def post_data(self):
        content_length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(content_length)

    @cached_property
    def form_data(self):
        return dict(parse_qsl(self.post_data.decode("UTF-8")))

    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
    def return_data(self, data):
        self._set_headers()
        self.wfile.write(json.dumps(data).encode("UTF-8"))
        pprint(data)

    def lock_handler(self, current: bool):
        if Data.get('lock') != current:
            self.send_response(405)
            print("Lock contention\n")
        else:
            Data.set('lock', {True: False, False: True}[current])
            self.return_data(Data.get('lock_msg', int(Data.get('lock'))))

    def do_HEAD(self):
        pprint("head", self.headers)
        self._set_headers()

    def do_GET(self):
        pprint("head", self.headers)
        self.return_data(Data.get('data'))

    def do_POST(self):
        pprint("head", self.headers)
        Data.set('data', json.loads(
            self.rfile.read(
                int(self.headers.get('Content-Length'))
            ).decode("UTF-8")))
        self.return_data(Data.get('data'))

    def do_DELETE(self):
        pprint("head", self.headers)
        Data.set('data', Data.get('defaults'))
        self.return_data(Data.get('data'))

    def do_LOCK(self):
        self.lock_handler(False)

    def do_UNLOCK(self):
        self.lock_handler(True)

def run(ip, port, cert, priv, passwd):
    host_str = ""
    if cert is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.load_cert_chain(certfile=cert, keyfile=priv, password=passwd)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        host_str = "https://"
    else:
        print("HTTP only - no SSL")
        host_str = "http://"

    host_str += f"{ip}:{port}"
    print(f"Starting terraform http backend on: {host_str}")
    server = ThreadingHTTPServer((str(ip), port), Handler)
    server.serve_forever()

def tf_file(file, proto, ip, port, cert, client_cert, client_priv):

    out = [
            'data "terraform_remote_state" "http" {',
            'backend = "http"',
            'config = {',
            f'  address        = "{proto}{ip}:{port}',
            f'  lock_address   = "{proto}{ip}:{port}',
            f'  unlock_address = "{proto}{ip}:{port}',
        ]

    if cert is not None:
        out.push(f'  client_ca_certificate_pem = "{cert}')

    if client_cert is not None and client_priv is not None:
        out.push(f'  client_certificate_pem = "{client_cert}')
        out.push(f'  client_private_key_pem = "{client_priv}')

    out.push('}')

    fd = open(file, 'w')
    fd.write(out.join("\n"))
    fd.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Terraform http backend example server")
    parser.add_argument("ip", nargs='?', default="127.0.0.1", type=ip_address, help="IP address to bind server to")
    parser.add_argument("port", nargs='?', default="8888", type=int, help="Port to bind server to")
    parser.add_argument("cert", nargs='?', type=Path, help="Path to the x509 cert")
    parser.add_argument("priv", nargs='?', type=Path, help="Path to the x509 private key")
    parser.add_argument("passwd", nargs='?', default='', help="Password to use for the x509 certificate (default is blank)")
    args = parser.parse_args()

    if args.port not in range(1, 65535):
        print(f"Invalid port [{args.port}] must be between 1 and 65535", file=sys.stderr)
        parser.print_help(sys.stderr)
        sys.exit(1)

    run(args.ip, args.port, args.cert, args.priv, args.passwd)
