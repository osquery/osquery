def osquery_get_os():
    if native.host_info().os.is_linux:
        return "linux"
    elif native.host_info().os.is_macos:
        return "macos"
    elif native.host_info().os.is_freebsd:
        return "freebsd"
    elif native.host_info().os.is_windows:
        return "windows"
    return "unknown"

def osquery_get_arch():
    if native.host_info().arch.is_x86_64:
        return "x86_64"
    return "unknown"

def osquery_get_current_platform():
    return "{}-{}".format(osquery_get_os(), osquery_get_arch())

def osquery_target(target):
    return "//{}".format(
        target,
    )

def osquery_genrule(**kwargs):
    native.genrule(**kwargs)

def osquery_filegroup(**kwargs):
    native.filegroup(**kwargs)

def osquery_http_archive(**kwargs):
    native.http_archive(**kwargs)
