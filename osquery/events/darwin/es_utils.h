/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/flags.h>
#include <osquery/events/darwin/endpointsecurity.h>
#include <osquery/logger/logger.h>

namespace osquery {

std::string getEsNewClientErrorMessage(const es_new_client_result_t r);
std::string getPath(const es_process_t* p);
std::string getSigningId(const es_process_t* p);
std::string getTeamId(const es_process_t* p);
std::string getStringFromToken(es_string_token_t* t);
std::string getStringFromToken(const es_string_token_t* t);
std::string getCwdPathFromPid(pid_t pid);
std::string getCDHash(const es_process_t* p);
void getProcessProperties(const es_process_t* p,
                          const EndpointSecurityEventContextRef& ec);
} // namespace osquery