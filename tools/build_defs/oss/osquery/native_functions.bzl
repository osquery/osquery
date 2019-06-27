# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

osquery_native = native

osquery_read_config = osquery_native.read_config

osquery_cxx_library = osquery_native.cxx_library

osquery_prebuilt_cxx_library = osquery_native.prebuilt_cxx_library

osquery_prebuilt_cxx_library_group = osquery_native.prebuilt_cxx_library_group

osquery_cxx_binary = osquery_native.cxx_binary

osquery_cxx_test = osquery_native.cxx_test

def osquery_custom_set_generic_kwargs(_):
    pass
