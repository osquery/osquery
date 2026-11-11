#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined in the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

import base64
import http.client
import json
import pathlib
import sys
import tempfile
import threading
import unittest
from http.server import HTTPServer

import test_http_server


class CarveBlockResponseTests(unittest.TestCase):
    def test_carve_blocks_are_acknowledged_and_reassembled(self):
        with tempfile.TemporaryDirectory() as output_dir:
            test_http_server.ARGS = {"persist": True, "verbose": False}
            test_http_server.FILE_CARVE_DIR = output_dir + "/"
            test_http_server.FILE_CARVE_MAP.clear()

            server = HTTPServer(("127.0.0.1", 0), test_http_server.RealSimpleHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def post(path, payload):
                connection = http.client.HTTPConnection(
                    "127.0.0.1", server.server_port, timeout=3
                )
                try:
                    connection.request(
                        "POST",
                        path,
                        json.dumps(payload),
                        {"Content-Type": "application/json", "Connection": "close"},
                    )
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    return json.loads(response.read())
                finally:
                    connection.close()

            try:
                response = post(
                    "/carve_init",
                    {
                        "block_count": 2,
                        "block_size": 4,
                        "carve_size": 8,
                        "carve_id": "fixture",
                    },
                )
                block = {
                    "session_id": response["session_id"],
                    "block_id": 0,
                    "data": base64.b64encode(b"abcd").decode(),
                }

                self.assertEqual(post("/carve_block", block), {})
                self.assertEqual(post("/carve_block", block), {})

                block.update(
                    block_id=1, data=base64.b64encode(b"efgh").decode()
                )
                self.assertEqual(post("/carve_block", block), {})
                self.assertEqual(
                    (pathlib.Path(output_dir) / "fixture.tar").read_bytes(),
                    b"abcdefgh",
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == "__main__":
    sys.argv = [sys.argv[0], "-v"]
    unittest.main()
