/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/linux/bpf/serializers.h>

#include <fcntl.h>

#ifndef MAX_HANDLE_SZ
#define MAX_HANDLE_SZ 128
#endif

namespace osquery {

const ParameterListMap kParameterListMap = {
    {"connect",
     {{"fd",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"uservaddr",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Buffer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       "addrlen"},

      {"addrlen",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"accept",
     {{"fd",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"upeer_sockaddr",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Buffer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       "upeer_addrlen"},

      {"upeer_addrlen",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::IntegerPtr,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       4U}}},

    {"accept4",
     {{"fd",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"upeer_sockaddr",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Buffer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       "upeer_addrlen"},

      {"upeer_addrlen",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::IntegerPtr,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       4U},

      {"flags",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"bind",
     {{"fd",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"umyaddr",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Buffer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       "addrlen"},

      {"addrlen",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"clone",
     {{"clone_flags",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"newsp",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"parent_tidptr",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::IntegerPtr,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       8U},

      {"child_tidptr",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::IntegerPtr,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       8U},

      {"tls",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"execve",
     {{"filename",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       {}},

      {"argv",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Argv,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       10U},

      {"envp",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"execveat",
     {{"fd",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"filename",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       {}},

      {"argv",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Argv,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       10U},

      {"envp",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"flags",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"name_to_handle_at",
     {{"dfd",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"name",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       {}},

      {"handle",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Buffer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       static_cast<std::size_t>(8U + MAX_HANDLE_SZ)},

      {"mnt_id",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::IntegerPtr,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       8U},

      {"flag",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"creat",
     {{"pathname",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       {}},

      {"mode",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"mknod",
     {{"filename",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       {}},

      {"mode",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"dev",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"mknodat",
     {{"dfd",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"filename",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       {}},

      {"mode",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"dev",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"open",
     {{"filename",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       {}},

      {"flags",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"mode",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"openat",
     {{"dfd",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"filename",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       {}},

      {"flags",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"mode",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"openat2",
     {{"dfd",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"filename",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       {}},

      {"how",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Buffer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       "usize"},

      {"usize",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"open_by_handle_at",
     {{"mountdirfd",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U},

      {"handle",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Buffer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       static_cast<std::size_t>(8U + MAX_HANDLE_SZ)},

      {"flags",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"chdir",
     {{"filename",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::String,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::Out,
       {}}}},

    {"fchdir",
     {{"fd",
       tob::ebpfpub::IFunctionTracer::Parameter::Type::Integer,
       tob::ebpfpub::IFunctionTracer::Parameter::Mode::In,
       8U}}},

    {"vfork", {}},
    {"fork", {}},
};

} // namespace osquery
