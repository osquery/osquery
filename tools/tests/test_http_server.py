#!/usr/bin/env python

#  Copyright (c) 2014-present, Facebook, Inc.
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
import base64
import json
import os
import random
import ssl
import string
import sys
import thread
import threading

# Create a simple TLS/HTTP server.
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from urlparse import parse_qs

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
ENABLE_SIGNING = False
HOST_UUID = "A0000000-0111-5555-BBBB-666666666666"
UUID_SIGNING = False
COUNTER_MODE = True
SIGNING_KEY = None
QUERY_COUNTER = 0
if ENABLE_SIGNING:
    # Imports for signing
    import ecdsa
    import hashlib
    with open(SCRIPT_DIR + "/strict_test_key.pem", "r") as fh:
        SIGNING_KEY = ecdsa.SigningKey.from_pem(fh.read())


EXAMPLE_CONFIG = {
    "schedule": {
        "tls_proc": {"query": "select * from processes", "interval": 1},
    },
    "node_invalid": False,
}

# A 'node' variation of the TLS API uses a GET for config.
EXAMPLE_NODE_CONFIG = EXAMPLE_CONFIG
EXAMPLE_NODE_CONFIG["node"] = True

EXAMPLE_DISTRIBUTED = {
    "queries": {
        "info": "select * from osquery_info",
        "flags": "select * from osquery_flags",
    }
}

EXAMPLE_DISTRIBUTED_DISCOVERY = {
    "queries": {
        "windows_info": "select * from system_info",
        "darwin_chrome_ex": "select users.username, ce.* from users join chrome_extensions ce using (uid)",
    },
    "discovery": {
        "windows_info": "select * from os_version where platform='windows'",
        "darwin_chrome_ex": "select * from os_version where platform='darwin'"
    }
}

EXAMPLE_DISTRIBUTED_ACCELERATE = {
    "queries": {
        "info": "select * from osquery_info",
    },
    "accelerate" : "60"
}

EXAMPLE_CARVE = {
    "queries": {
        "test_carve" : "select * from forensic_carve where path='/tmp/afile.txt' and carve = 1"
    }
}

TEST_GET_RESPONSE = {
    "foo": "baz",
    "config": "baz",
}

TEST_POST_RESPONSE = {
    "foo": "bar",
}

NODE_KEYS = [
    "this_is_a_node_secret",
    "this_is_also_a_node_secret",
]

FAILED_ENROLL_RESPONSE = {
    "node_invalid": True
}

ENROLL_RESPONSE = {
    "node_key": "this_is_a_node_secret"
}

RECEIVED_REQUESTS = []
FILE_CARVE_DIR = '/tmp/'
FILE_CARVE_MAP = {}

def debug(response):
    print("-- [DEBUG] %s" % str(response))
    sys.stdout.flush()
    sys.stderr.flush()

ENROLL_RESET = {
    "count": 1,
    "max": 3,
}

class RealSimpleHandler(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        debug("RealSimpleHandler::get %s" % self.path)
        self._set_headers()
        if self.path == '/config':
            self.config(request, node=True)
        else:
            self._reply(TEST_GET_RESPONSE)

    def do_HEAD(self):
        debug("RealSimpleHandler::head %s" % self.path)
        self._set_headers()

    def do_POST(self):
        debug("RealSimpleHandler::post %s" % self.path)
        self._set_headers()
        content_len = int(self.headers.getheader('content-length', 0))
        request = json.loads(self.rfile.read(content_len))
        debug("Request: %s" % str(request))

        if self.path == '/enroll':
            self.enroll(request)
        elif self.path == '/config':
            self.config(request)
        elif self.path == '/log':
            self.log(request)
        elif self.path == '/distributed_read':
            self.distributed_read(request)
        elif self.path == '/distributed_write':
            self.distributed_write(request)
        elif self.path == '/test_read_requests':
            self.test_read_requests()
        elif self.path == '/carve_init':
            self.start_carve(request)
        elif self.path == '/carve_block':
            self.continue_carve(request)
        else:
            self._reply(TEST_POST_RESPONSE)

    def enroll(self, request):
        '''A basic enrollment endpoint'''

        # This endpoint expects an "enroll_secret" POST body variable.
        # Over TLS, this string may be a shared secret value installed on every
        # managed host in an enterprise.

        # Alternatively, each client could authenticate with a TLS client cert.
        # Then, access to the enrollment endpoint implies the required auth.
        # A generated node_key is still supplied for identification.
        self._push_request('enroll', request)
        if ARGS.use_enroll_secret and ENROLL_SECRET != request["enroll_secret"]:
            self._reply(FAILED_ENROLL_RESPONSE)
            return
        self._reply(ENROLL_RESPONSE)

    def config(self, request, node=False):
        '''A basic config endpoint'''

        # This endpoint responds with a JSON body that is the entire config
        # content. There is no special key or status.

        # Authorization is simple authentication (the ability to download the
        # config data) using a "valid" node_key. Validity means the node_key is
        # known to this server. This toy server delivers a shared node_key,
        # imagine generating a unique node_key per enroll request, tracking the
        # generated keys, and asserting a match.

        # The osquery TLS config plugin calls the TLS enroll plugin to retrieve
        # a node_key, then submits that key alongside config/logger requests.
        self._push_request('config', request)
        if "node_key" not in request or request["node_key"] not in NODE_KEYS:
            self._reply(FAILED_ENROLL_RESPONSE)
            return

        # This endpoint will also invalidate the node secret key (node_key)
        # after several attempts to test re-enrollment.
        ENROLL_RESET["count"] += 1
        if ENROLL_RESET["count"] % ENROLL_RESET["max"] == 0:
            ENROLL_RESET["first"] = 0
            self._reply(FAILED_ENROLL_RESPONSE)
            return
        if node:
            self._reply(EXAMPLE_NODE_CONFIG)
            return
        self._reply(EXAMPLE_CONFIG)

    def distributed_read(self, request):
        '''A basic distributed read endpoint'''
        if "node_key" not in request or request["node_key"] not in NODE_KEYS:
            self._reply(FAILED_ENROLL_RESPONSE)
            return
        if ENABLE_SIGNING:
            global QUERY_COUNTER, SIGNING_KEY
            signed_distributed = EXAMPLE_DISTRIBUTED
            signed_distributed['signatures'] = {}
            for query in signed_distributed['queries']:
                sign_str = signed_distributed['queries'][query]
                if UUID_SIGNING:
                    sign_str += "\n"+HOST_UUID
                if COUNTER_MODE:
                    sign_str += "\n"+str(QUERY_COUNTER)
                sig = base64.standard_b64encode(SIGNING_KEY.sign(sign_str, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der))
                signed_distributed['signatures'][query] = sig
                QUERY_COUNTER += 1
            self._reply(signed_distributed)
        else:
            self._reply(EXAMPLE_DISTRIBUTED)

    def distributed_write(self, request):
        '''A basic distributed write endpoint'''
        self._reply({})

    def log(self, request):
        self._reply({})

    def test_read_requests(self):
        # call made by unit tests to retrieve the entire history of requests 
        # made by code under test. Used by unit tests to verify that the code
        # under test made the expected calls to the TLS backend
        self._reply(RECEIVED_REQUESTS)

    def start_carve(self, request):
        sid = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
        FILE_CARVE_MAP[sid] = {
            'block_count': int(request['block_count']),
            'block_size': int(request['block_size']),
            'blocks_received' : {},
            'carve_size': int(request['carve_size']),
            'carve_guid': request['carve_id'],
        }
        self._reply({'session_id' : sid})

    def continue_carve(self, request):
        # Do we already have this block
        if request['block_id'] in FILE_CARVE_MAP[request['session_id']]['blocks_received']:
            return
        # Store block data
        FILE_CARVE_MAP[request['session_id']]['blocks_received'][int(request['block_id'])] = request['data']
        # Do we still need more blocks
        if len(FILE_CARVE_MAP[request['session_id']]['blocks_received']) < FILE_CARVE_MAP[request['session_id']]['block_count']:
            return
        f = open(FILE_CARVE_DIR+FILE_CARVE_MAP[request['session_id']]['carve_guid']+'.tar', 'wb')
        for x in range(0, FILE_CARVE_MAP[request['session_id']]['block_count']):
            f.write(base64.standard_b64decode(FILE_CARVE_MAP[request['session_id']]['blocks_received'][x]))
        f.close()
        FILE_CARVE_MAP[request['session_id']] = {}


    def _push_request(self, command, request):
        # Archive the http command and the request body so that unit tests
        # can retrieve it later for verification purposes
        request['command'] = command
        RECEIVED_REQUESTS.append(request)
        
    def _reply(self, response):
        debug("Replying: %s" % (str(response)))
        self.wfile.write(json.dumps(response))


def handler():
    debug("Shutting down HTTP server via timeout (%d) seconds." 
          % (ARGS.timeout))
    thread.interrupt_main()

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
        "--timeout", default=10, type=int,
        help="If not persisting, exit after a number of seconds"
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
        "--ca", metavar="CA_FILE",
        default=SCRIPT_DIR + "/test_server_ca.pem",
        help="TLS server CA list for client-auth."
    )

    parser.add_argument(
        "--use_enroll_secret", action="store_true",
        default=True,
        help="Require an enrollment secret for node enrollment"
    )
    parser.add_argument(
        "--enroll_secret", metavar="SECRET_FILE",
        default=SCRIPT_DIR + "/test_enroll_secret.txt",
        help="File containing enrollment secret"
    )

    parser.add_argument(
        "port", metavar="PORT", type=int,
        help="Bind to which local TCP port."
    )

    ARGS = parser.parse_args()

    ENROLL_SECRET = ""
    if ARGS.use_enroll_secret:
        try:
            with open(ARGS.enroll_secret, "r") as fh:
                ENROLL_SECRET = fh.read().strip()
        except IOError as e:
            print("Cannot read --enroll_secret: %s" % str(e))
            exit(1)

    if not ARGS.persist:
        timer = threading.Timer(ARGS.timeout, handler)
        timer.start()

    httpd = HTTPServer(('localhost', ARGS.port), RealSimpleHandler)
    if ARGS.tls:
        if 'SSLContext' in vars(ssl):
            ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ctx.load_cert_chain(ARGS.cert, keyfile=ARGS.key)
            ctx.load_verify_locations(capath=ARGS.ca)
            ctx.options ^= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        else:
            httpd.socket = ssl.wrap_socket(httpd.socket,
                                           ca_certs=ARGS.ca,
                                           ssl_version=ssl.PROTOCOL_SSLv23,
                                           certfile=ARGS.cert,
                                           keyfile=ARGS.key,
                                           server_side=True)
        debug("Starting TLS/HTTPS server on TCP port: %d" % ARGS.port)
    else:
        debug("Starting HTTP server on TCP port: %d" % ARGS.port)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
