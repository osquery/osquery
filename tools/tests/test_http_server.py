#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import argparse
import base64
import json
import os
import random
import ssl
import string
import sys
import _thread
import threading

# Create a simple TLS/HTTP server.
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

# Script run directory, used for default values
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

# Default values for global variables
HTTP_SERVER_USE_TLS = False
HTTP_SERVER_PERSIST = False
HTTP_SERVER_TIMEOUT = 10
HTTP_SERVER_VERBOSE = False
HTTP_SERVER_CERT = "test_server.pem"
HTTP_SERVER_KEY = "test_server.key"
HTTP_SERVER_CA = "test_server_ca.pem"
HTTP_SERVER_USE_ENROLL_SECRET = True
HTTP_SERVER_ENROLL_SECRET = "test_enroll_secret.txt"

# Global accessor value for arguments passed to the server
ARGS = None

EXAMPLE_CONFIG = {
    "schedule": {
        "tls_proc": {
            "query": "select * from processes",
            "interval": 1
        },
    },
    "node_invalid": False,
}

EXAMPLE_ATC_CONFIG = {
    "schedule": {
        "tls_proc": {"query": "select * from processes", "interval": 10},
    },
    "auto_table_construction" : {
        "quarantine_items" : {
          "query" : "SELECT LSQuarantineEventIdentifier as id, LSQuarantineAgentName as agent_name, LSQuarantineAgentBundleIdentifier as agent_bundle_identifier, LSQuarantineTypeNumber as type, LSQuarantineDataURLString as data_url,LSQuarantineOriginURLString as origin_url, LSQuarantineSenderName as sender_name, LSQuarantineSenderAddress as sender_address, LSQuarantineTimeStamp as timestamp from LSQuarantineEvent",
          "path" : "/Users/%/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
          "columns" : ["path", "id", "agent_name", "agent_bundle_identifier"]
        }
    },
    "node_invalid": False,
}

EXAMPLE_EMPTY_CONFIG = {
    "schedule": {
        "tls_proc": {
            "query": "select * from processes",
            "interval": 1
        },
    },
    "node_invalid": False,
}

# A 'node' variation of the TLS API uses a GET for config.
EXAMPLE_NODE_CONFIG = EXAMPLE_CONFIG
EXAMPLE_NODE_CONFIG["node"] = True

EXAMPLE_DISTRIBUTED = {
    "queries": {
        "info": "select count(1) from osquery_info",
        "flags": "select count(1) from osquery_flags",
    }
}

EXAMPLE_DISTRIBUTED_DISCOVERY = {
    "queries": {
        "windows_info":
        "select * from system_info",
        "darwin_chrome_ex":
        "select users.username, ce.* from users join chrome_extensions ce using (uid)",
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
    "accelerate": "60"
}

EXAMPLE_CARVE = {
    "queries": {
        "test_carve":
        "select * from carves where path='/tmp/rook.stl' and carve = 1"
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

FAILED_ENROLL_RESPONSE = {"node_invalid": True}

ENROLL_RESPONSE = {"node_key": "this_is_a_node_secret"}

RECEIVED_REQUESTS = []
FILE_CARVE_DIR = '/tmp/'
FILE_CARVE_MAP = {}


def debug(response):
    if ARGS['verbose']:
        print("-- [DEBUG] %s" % str(response))
        sys.stdout.flush()
        sys.stderr.flush()


ENROLL_RESET = {
    "count": 1,
    "max": 3,
}

TIMEOUT_TIMER = None

class RealSimpleHandler(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.protocol_version = self.request_version
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')

    def do_GET(self):
        reset_timeout()
        debug("RealSimpleHandler::get %s" % self.path)
        self._set_headers()
        if self.path == '/config':
            self.config(request, node=True)
        else:
            self._reply(TEST_GET_RESPONSE)

    def do_HEAD(self):
        reset_timeout()
        debug("RealSimpleHandler::head %s" % self.path)
        self._set_headers()
        self.send_header('Content-Length', 0)
        self.end_headers()

    def do_POST(self):
        reset_timeout()
        debug("RealSimpleHandler::post %s" % self.path)
        self._set_headers()
        content_len = int(self.headers.get('content-length', 0))

        body = self.rfile.read(content_len)
        request = json.loads(body)

        # This contains a base64 encoded block of a file printing to the screen
        # slows down carving and makes scroll back a pain
        if (self.path != "/carve_block"):
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
        if ARGS['use_enroll_secret'] and HTTP_SERVER_ENROLL_SECRET != request["enroll_secret"]:
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

    # Initial endpoint, used to start a carve request
    def start_carve(self, request):
        # The osqueryd agent expects the first endpoint to return a
        # 'session id' through which they'll communicate in future POSTs.
        # We use this internally to connect the request to the person
        # who requested the carve, and to prepare space for the data.
        sid = ''.join(
            random.choice(string.ascii_uppercase + string.digits)
            for _ in range(10))

        # The agent will send up the total number of expected blocks, the
        # size of each block, the size of the carve overall, and the carve GUID
        # to identify this specific carve. We check all of these numbers
        # against predefined maximums to ensure that agents aren't able
        # to DOS our endpoints, and that carves are a reasonable size.
        FILE_CARVE_MAP[sid] = {
            'block_count': int(request['block_count']),
            'block_size': int(request['block_size']),
            'blocks_received': {},
            'carve_size': int(request['carve_size']),
            'carve_guid': request['carve_id'],
        }

        # Lastly we let the agent know that the carve is good to start,
        # and send the session id back
        self._reply({'session_id': sid})

    # Endpoint where the blocks of the carve are received, and
    # susequently reassembled.
    def continue_carve(self, request):
        # First check if we have already received this block
        if request['block_id'] in FILE_CARVE_MAP[request['session_id']][
                'blocks_received']:
            return

        # Store block data to be reassembled later
        FILE_CARVE_MAP[request['session_id']]['blocks_received'][int(
            request['block_id'])] = request['data']

        # Are we expecting to receive more blocks?
        if len(FILE_CARVE_MAP[request['session_id']]['blocks_received']
               ) < FILE_CARVE_MAP[request['session_id']]['block_count']:
            return

        # If not, let's reassemble everything
        out_file_name = FILE_CARVE_DIR + FILE_CARVE_MAP[request['session_id']]['carve_guid']

        # Check the first four bytes for the zstd header. If not no
        # compression was used, it's an uncompressed .tar
        if (base64.standard_b64decode(FILE_CARVE_MAP[request['session_id']][
                'blocks_received'][0])[0:4] == b'\x28\xB5\x2F\xFD'):
            out_file_name += '.zst'
        else:
            out_file_name += '.tar'
        f = open(out_file_name, 'wb')
        for x in range(0,
                       FILE_CARVE_MAP[request['session_id']]['block_count']):
            f.write(
                base64.standard_b64decode(FILE_CARVE_MAP[request['session_id']]
                                          ['blocks_received'][x]))
        f.close()
        debug("File successfully carved to: %s" % out_file_name)
        FILE_CARVE_MAP[request['session_id']] = {}

    def _push_request(self, command, request):
        # Archive the http command and the request body so that unit tests
        # can retrieve it later for verification purposes
        request['command'] = command
        RECEIVED_REQUESTS.append(request)

    def _reply(self, response):
        debug("Replying: %s" % (str(response)))
        response_bytes = json.dumps(response).encode()

        if self.protocol_version == "HTTP/1.1":
            self.send_header('Content-Length', len(response_bytes))

        self.end_headers()
        self.wfile.write(response_bytes)


def handler():
    debug("Shutting down HTTP server via timeout (%d) seconds." %
          (ARGS['timeout']))
    _thread.interrupt_main()

def reset_timeout():
    if ARGS['persist']:
        return

    global TIMEOUT_TIMER

    if TIMEOUT_TIMER:
        TIMEOUT_TIMER.cancel()

    TIMEOUT_TIMER = threading.Timer(ARGS['timeout'], handler)
    TIMEOUT_TIMER.start()


def run_http_server(bind_port=80, **kwargs):
    global HTTP_SERVER_ENROLL_SECRET
    global ARGS
    ARGS = kwargs
    if ARGS['use_enroll_secret']:
        try:
            with open(ARGS['enroll_secret'], "r") as fh:
                HTTP_SERVER_ENROLL_SECRET = fh.read().strip()
        except IOError as e:
            print("Cannot read --enroll_secret: %s" % str(e))
            exit(1)

    reset_timeout()

    httpd = HTTPServer(('localhost', bind_port), RealSimpleHandler)
    if ARGS['tls']:
        httpd.socket = ssl.wrap_socket(
            httpd.socket,
            ca_certs=ARGS['ca'],
            ssl_version=ssl.PROTOCOL_SSLv23,
            certfile=ARGS['cert'],
            keyfile=ARGS['key'],
            server_side=True)
        debug("Starting TLS/HTTPS server on TCP port: %d" % bind_port)
    else:
        debug("Starting HTTP server on TCP port: %d" % bind_port)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=("osquery python https server for client TLS testing."))
    parser.add_argument(
        "--tls",
        default=HTTP_SERVER_USE_TLS,
        action="store_true",
        help="Wrap the HTTP server socket in TLS.")

    parser.add_argument(
        "--persist",
        default=HTTP_SERVER_PERSIST,
        action="store_true",
        help="Create a persistent HTTP connection.")
    parser.add_argument(
        "--timeout",
        default=HTTP_SERVER_TIMEOUT,
        type=int,
        help="If not persisting, exit after a number of seconds")
    parser.add_argument(
        '--verbose',
        default=HTTP_SERVER_VERBOSE,
        action='store_true',
        help='Output version/debug messages')

    parser.add_argument(
        "--cert",
        metavar="CERT_FILE",
        default=None,
        help="TLS server cert.")
    parser.add_argument(
        "--key",
        metavar="PRIVATE_KEY_FILE",
        default=None,
        help="TLS server cert private key.")
    parser.add_argument(
        "--ca",
        metavar="CA_FILE",
        default=None,
        help="TLS server CA list for client-auth.")

    parser.add_argument(
        "--use_enroll_secret",
        action="store_true",
        default=HTTP_SERVER_USE_ENROLL_SECRET,
        help="Require an enrollment secret for node enrollment")
    parser.add_argument(
        "--enroll_secret",
        metavar="SECRET_FILE",
        default=None,
        help="File containing enrollment secret")
    parser.add_argument(
        "--test-configs-dir",
        required=True,
        help="Directory where the script will search for configuration files it needs")

    parser.add_argument(
        "port", metavar="PORT", type=int, help="Bind to which local TCP port.")

    args = parser.parse_args()

    if args.cert is None:
        args.cert = "%s/%s" % (args.test_configs_dir, HTTP_SERVER_CERT)

    if args.key is None:
        args.key = "%s/%s" % (args.test_configs_dir, HTTP_SERVER_KEY)

    if args.ca is None:
        args.ca = "%s/%s" % (args.test_configs_dir, HTTP_SERVER_CA)

    if args.enroll_secret is None:
        args.enroll_secret =  "%s/%s" % (args.test_configs_dir, HTTP_SERVER_ENROLL_SECRET)

    nonempty_args = {
        k: v
        for k, v in vars(args).items() if v is not None
    }

    run_http_server(nonempty_args['port'], **nonempty_args)
