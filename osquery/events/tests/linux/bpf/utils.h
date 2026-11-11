/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/linux/bpf/iprocesscontextfactory.h>

namespace osquery {

void setFileDescriptor(ProcessContext& process_context,
                       int fd,
                       bool close_on_exec,
                       const std::string& path);

void setFileDescriptor(ProcessContextMap& process_context_map,
                       pid_t process_id,
                       int fd,
                       bool close_on_exec,
                       const std::string& path);

void setSocketDescriptor(ProcessContext& process_context,
                         int fd,
                         bool close_on_exec,
                         int domain,
                         int type,
                         int protocol,
                         const std::string& local_address,
                         std::uint16_t local_port,
                         const std::string& remote_address,
                         std::uint16_t remote_port);

void setSocketDescriptor(ProcessContextMap& process_context_map,
                         pid_t process_id,
                         int fd,
                         bool close_on_exec,
                         int domain,
                         int type,
                         int protocol,
                         const std::string& local_address,
                         std::uint16_t local_port,
                         const std::string& remote_address,
                         std::uint16_t remote_port);

bool validateFileDescriptor(const ProcessContext& process_context,
                            int fd,
                            bool close_on_exec,
                            const std::string& path);

bool validateFileDescriptor(const ProcessContextMap& process_context_map,
                            pid_t process_id,
                            int fd,
                            bool close_on_exec,
                            const std::string& path);

bool validateSocketDescriptor(const ProcessContext& process_context,
                              int fd,
                              bool close_on_exec,
                              int domain,
                              int type,
                              int protocol,
                              const std::string& local_address,
                              std::uint16_t local_port,
                              const std::string& remote_address,
                              std::uint16_t remote_port);

bool validateSocketDescriptor(const ProcessContextMap& process_context_map,
                              pid_t process_id,
                              int fd,
                              bool close_on_exec,
                              int domain,
                              int type,
                              int protocol,
                              const std::string& local_address,
                              std::uint16_t local_port,
                              const std::string& remote_address,
                              std::uint16_t remote_port);

} // namespace osquery
