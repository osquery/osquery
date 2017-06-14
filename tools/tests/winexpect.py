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

import shlex
import subprocess

# TODO: Error checking and shit.
#class WinREPLWrapper(object):
class REPLWrapper(object):
    def __init__(self, proc, orig_prompt, prompt_change, continuation_prompt=''):
        self.child = proc
        self.prompt = orig_prompt
        self.prompt_change = prompt_change
        self.continuation_prompt = continuation_prompt

    # We currently only support 1 query at a time.
    def run_command(self, command):
        ret = self.child.proc.communicate(command)
        if(ret[1] != None):
            print('[-] Query failed with stderr: {}'.format(ret[1]))
        return ret[0]










class WinExpectSpawn(object):
    # TODO: Any other Popen values needed.
    def __init__(self, command='', cwd=None, env=None):
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        kwargs = dict(bufsize=0, stdin=subprocess.PIPE,
              stderr=subprocess.STDOUT, stdout=subprocess.PIPE,
              cwd=cwd, env=env)
        kwargs['startupinfo'] = si
        kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP

        argv = shlex.split(command, posix=False)
        self.proc = subprocess.Popen(argv, **kwargs)
        self.pid = self.proc.pid
