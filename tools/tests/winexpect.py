#!/usr/bin/env python

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.


"""
    A Windows specific implementation of REPLWrapper from pexpect.

    As no good implementation exists, we roll our own generic class that
    handles all of the necessary functionality for our integration tests to
    run on Windows systems.
"""

import os
import shlex
import subprocess

import multiprocessing # TODO: Needed? For threaded read?
import tempfile
import threading
import time

# TODO: Get on all python3
try:
    from Queue import Queue, Empty
except ImportError:
    from queue import Queue, Empty  # python 3.x

# TODO: Error checking and shit.
#class WinREPLWrapper(object):
class REPLWrapper(object):
    def __init__(self, proc, orig_prompt, prompt_change, continuation_prompt='', timeout=2):
        self.child = proc
        self.prompt = orig_prompt
        self.prompt_change = prompt_change
        self.continuation_prompt = continuation_prompt
        self.timeout=timeout

    # We currently only support 1 query at a time.
    #
    # .communicate only reads until end of file, so it's closing after
    # each call to `run_command`. So, rather than communicate, we leverage
    # the stdin.write, stdout.read, and stderr.read, albeit python recommends
    # that we don't do this as it can enduce deadlocking.
    # TODO: We should implement some mechanism to check for deadlocks.
    #
    # Warning Use communicate() rather than .stdin.write, .stdout.read or
    # .stderr.read to avoid deadlocks due to any of the other OS pipe buffers
    # filling up and blocking the child process.
    def run_command(self, command):
        res = ''
        # Entering just white space should be a return
        if(command == ' '):
            return res
        try:
            # Execute the command
            self.child.proc.stdin.write(command + '\r\n')
            self.child.proc.stdin.flush()

            # Wait for stderr/stdout to be populated for at most timeout seconds
            for i in xrange(self.timeout):
                if not self.child.out_queue.empty():
                    break
                time.sleep(1)

            while not self.child.out_queue.empty():
                l = self.child.out_queue.get_nowait()
                print('[+] Adding result: {}'.format(l))
                res += l

        except Exception as e:
            print('[-] Failed to communicate with client: {}'.format(e))
        return res

class WinExpectSpawn(object):
    # TODO: Any other Popen values needed.
    def __init__(self, command='', cwd=None, env=None):
        self.io_lock = multiprocessing.Lock()
        self.stderr_lock = multiprocessing.Lock()

        print('[+] command: {}'.format(command))

        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        kwargs = dict(bufsize=1, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
              cwd=cwd, env=env)
        kwargs['startupinfo'] = si
        kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP

        argv = shlex.split(command, posix=False)
        self.proc = subprocess.Popen(argv, **kwargs)

        # Spawn a new thread for "non-blocking" reads.
        self.out_queue = Queue()
        self.stdout_thread = threading.Thread(target=self.read_pipe,
                                args=(self.proc.stdout, self.out_queue))
        self.stdout_thread.daemon = True
        self.stdout_thread.start()

        self.stderr_thread = threading.Thread(target=self.read_pipe,
                                args=(self.proc.stderr, self.out_queue))
        self.stderr_thread.daemon = True
        self.stderr_thread.start()

    # Thread worker function used to insert stderr/stdout into a thread-safe queue
    def read_pipe(self, out, queue):
        for l in iter(out.readline, b''):
            queue.put(l)
        out.close()
