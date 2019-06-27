# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

_S3_BASE_URL = "https://s3.amazonaws.com/osquery-packages"

_S3_BASE_DIR = "third-party"

_S3_PREBUILT_DIR = _S3_BASE_DIR + "/lib"

def osquery_tp_prebuilt_cxx_archive(
        name,
        version,
        build,
        platform,
        archive_type,
        sha256sum):
    archive_name = "{}-{}-{}.{}".format(
        name,
        version,
        build,
        archive_type,
    )

    s3_path = "{}/{}/none/{}".format(
        _S3_PREBUILT_DIR,
        platform,
        archive_name,
    )

    s3_url = "{}/{}".format(
        _S3_BASE_URL,
        s3_path,
    )

    target_name = "{}_{}_{}_pre_built_archive".format(
        name,
        version,
        platform,
    )

    native.http_archive(
        name = target_name,
        sha256 = sha256sum,
        type = archive_type,
        urls = [
            s3_url,
        ],
    )

    return target_name

def osquery_tp_source_cxx_archive(
        name,
        version,
        archive_type,
        sha256sum):
    archive_name = "{}-{}.{}".format(
        name,
        version,
        archive_type,
    )

    s3_path = "{}/{}/{}".format(
        _S3_SOURCe_DIR,
        archive_name,
    )

    s3_url = "{}/{}".format(
        _S3_BASE_URL,
        s3_path,
    )

    target_name = "{}_{}_source_archive".format(
        name,
        version,
    )

    native.http_archive(
        name = target_name,
        sha256 = sha256sum,
        type = archive_type,
        urls = [
            s3_url,
        ],
    )

    return target_name

def osquery_tp_prebuilt_python_archive(
        name,
        filename,
        platform,
        sha1sum):
    if platform == "none":
        s3_path = "{}/{}/{}".format(
            _S3_PREBUILT_DIR,
            platform,
            filename,
        )
    else:
        s3_path = "{}/{}/none/{}".format(
            _S3_PREBUILT_DIR,
            platform,
            filename,
        )

    s3_url = "{}/{}".format(
        _S3_BASE_URL,
        s3_path,
    )

    target_name = "{}_{}_file".format(name, filename)

    native.remote_file(
        name = target_name,
        out = filename,
        sha1 = sha1sum,
        url = s3_url,
    )

    return target_name
