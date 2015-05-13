#!/usr/bin/env python

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant 
#  of patent rights can be found in the PATENTS file in the same directory.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import os
import signal
import ssl
import sys

# Create a simple TLS/HTTP server.
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

class RealSimpleHandler(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
 
    def do_GET(self):
        print("[DEBUG] RealSimpleHandler::get")
        self._set_headers()
        self.wfile.write('{"foo": "bar"}')
 
    def do_HEAD(self):
        print("[DEBUG] RealSimpleHandler::head")
        self._set_headers()
        
    def do_POST(self):
        print("[DEBUG] RealSimpleHandler::post")
        # Doesn't do anything with posted data
        self._set_headers()
        self.wfile.write('{"foo": "bar"}')

def handler(signum, frame):
    sys.exit(0)

if __name__ == '__main__':
    SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(description=(
        "osquery python https server for client TLS testing."
    ))
    parser.add_argument(
        "--tls", default=False, action="store_true",
        help="Wrap the HTTP server socket in TLS."
    )

    parser.add_argument(
        "--persist", default=False, action="store_true",
        help="Wrap the HTTP server socket in TLS."
    )

    parser.add_argument(
        "--cert", metavar="CERT_FILE",
        default=SCRIPT_DIR + "/test_server.pem",
        help="TLS server cert."
    )
    parser.add_argument(
        "--key", metavar="PRIVATE_KEY_FILE",
        default=SCRIPT_DIR + "/test_server.key",
        help="TLS server cert private key."
    )

    parser.add_argument(
        "port", metavar="PORT", type=int,
        help="Bind to which local TCP port."
    )

    ARGS = parser.parse_args()

    if not ARGS.persist:
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(5)

    httpd = HTTPServer(('localhost', ARGS.port), RealSimpleHandler)
    if ARGS.tls:
        httpd.socket = ssl.wrap_socket(
            httpd.socket,
            ssl_version=ssl.PROTOCOL_SSLv23,
            certfile=ARGS.cert,
            keyfile=ARGS.key,
            server_side=True)
        print("[DEBUG] Starting TLS/HTTPS server on TCP port: %d" % ARGS.port)
    else:
        print("[DEBUG] Starting HTTP server on TCP port: %d" % ARGS.port)
    httpd.serve_forever()
