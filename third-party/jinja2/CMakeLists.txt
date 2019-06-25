# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(jinja2Main)
  set(name "jinja2")
  set(base_url "https://s3.amazonaws.com/osquery-packages/third-party/pre-built/none")
  set(file_name "Jinja2-2.10-py2.py3-none-any.whl")

  # Original SHA1 was f14bb3e5021b2b0605dcd4865ac539cde04fe856
  set(hash "74c935a1b8bb9a3947c50a54766a969d4846290e1e788ea44c1392163723c3bd")

  importRemotePythonModule("${name}" "${base_url}" "${file_name}" "${hash}")
endfunction()

jinja2Main()
