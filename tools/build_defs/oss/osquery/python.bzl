load("//tools/build_defs/oss/osquery:native.bzl", "osquery_native")

def osquery_python_library(**kwargs):
    osquery_native.python_library(**kwargs)

def osquery_python_binary(**kwargs):
    osquery_native.python_binary(**kwargs)

def osquery_prebuilt_python_library(**kwargs):
    osquery_native.prebuilt_python_library(**kwargs)
