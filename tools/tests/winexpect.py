#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

"""
    A Windows specific implementation of REPLWrapper from pexpect.

    As no good implementation exists, we roll our own generic class that
    handles all of the necessary functionality for our integration tests to
    run on Windows systems.
"""

import os
import shlex
import subprocess
import threading
import time

try:
    from Queue import Queue, Empty
except ImportError:
    # TODO: Get on all python3
    from queue import Queue, Empty


class REPLWrapper(object):
    def __init__(self,
                 proc,
                 orig_prompt,
                 prompt_change,
                 continuation_prompt='',
                 timeout=2):
        self.child = proc
        self.prompt = orig_prompt
        self.prompt_change = prompt_change
        self.continuation_prompt = continuation_prompt
        self.timeout = timeout

    # We currently only support 1 query at a time.
    def run_command(self, command):
        res = ''
        command = command.strip()
        if not command:
            return res
        try:
            command = command + '\r\n'
            self.child.proc.stdin.write(command.encode())
            self.child.proc.stdin.flush()

            # Wait for stderr/stdout to populate for at most timeout seconds
            for i in range(self.timeout):
                if not self.child.out_queue.empty():
                    break
                time.sleep(1)
            while not self.child.out_queue.empty():
                l = self.child.out_queue.get_nowait().decode()
                res += l

        except Exception as e:
            print('[-] Failed to communicate with client: {}'.format(e))
        return res.encode()


class WinExpectSpawn(object):
    def __init__(self, command='', cwd=None, env=None):
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        kwargs = dict(
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=env)
        kwargs['startupinfo'] = si
        kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP

        argv = shlex.split(command, posix=False)
        self.proc = subprocess.Popen(argv, **kwargs)

        # Spawn a new thread for "non-blocking" reads.
        self.out_queue = Queue()
        self.stdout_thread = threading.Thread(
            target=self.read_pipe, args=(self.proc.stdout, self.out_queue))
        self.stdout_thread.daemon = True
        self.stdout_thread.start()

        # TODO: Figure out how to get stderr as well as stdout
        #self.stderr_thread = threading.Thread(target=self.read_pipe,
        #                        args=(self.proc.stderr, self.out_queue))
        #self.stderr_thread.daemon = True
        #self.stderr_thread.start()

    # Thread worker used to insert stderr/stdout into a thread-safe queue
    def read_pipe(self, out, queue):
        for l in iter(out.readline, b''):
            queue.put(l)
        out.close()
