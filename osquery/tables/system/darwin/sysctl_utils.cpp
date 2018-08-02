/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <sys/sysctl.h>
#include <sys/time.h>

#include <osquery/filesystem.h>
#include <osquery/tables.h>

// ifdef __APPLE__
#include <mach/machine/vm_param.h>
#include <mach/machine/vm_types.h>
#include <mach/mach_types.h>

#include "osquery/tables/system/posix/sysctl_utils.h"

namespace osquery {
namespace tables {

#define CTL_DEBUG_ITERATE 2
#define CTL_DEBUG_DESCRIPTION 1
#define CTL_DEBUG_TYPE 4

#ifndef CTLTYPE
#define CTLTYPE 0xf
#define CTLTYPE_NODE 1
#define CTLTYPE_INT 2
#define CTLTYPE_STRING 3
#define CTLTYPE_QUAD 4
#define CTLTYPE_OPAQUE 5
#define CTLTYPE_STRUCT CTLTYPE_OPAQUE
#endif

// If the debug iteration fails, prevent endless lookups.
#define MAX_CONTROLS 1024

const std::vector<std::string> kControlNames{
    "", "kern", "vm", "vfs", "net", "debug", "hw", "machdep", "user"};

const std::vector<std::string> kControlTypes{
    "", "node", "int", "string", "quad", "opaque", "struct"};
const std::vector<std::string> kOpaqueTypes{
  "S_clockinfo", "S_loadavg", "S_timeval", "S_xswusage", "T_dev_t", "S_quads"};

void opaquePushback(QueryData& results,
                    Row& r,
                    std::string& opaque_name,
                    std::string opaque_cv,
                    const std::string& var){
    r["name"] = opaque_name + "." + var;
    r["current_value"] = opaque_cv;
    results.push_back(r);
  };

void opaqueControlInfo(QueryData& results, Row& r, std::string& opaque_name, char* response, std::string& value){
  std::string opaque_cv;
  if (value.compare("S,clockinfo") == 0) {
      struct clockinfo *ci = (struct clockinfo*) response;
      opaque_cv = std::to_string(ci->hz);
      opaquePushback(results, r, opaque_name, opaque_cv, "hz");
      opaque_cv = std::to_string(ci->tick);
      opaquePushback(results, r, opaque_name, opaque_cv, "tick");
      opaque_cv = std::to_string(ci->tickadj);
      opaquePushback(results, r, opaque_name, opaque_cv, "tickadj");
      opaque_cv = std::to_string(ci->profhz);
      opaquePushback(results, r, opaque_name, opaque_cv, "profhz");
      opaque_cv = std::to_string(ci->stathz);
      opaquePushback(results, r, opaque_name, opaque_cv, "stathz");
    }
  else if (value.compare("S,timeval") == 0) {
      struct timeval *tv = (struct timeval*) response;
      opaque_cv = INTEGER((long)tv->tv_sec);
      opaquePushback(results, r, opaque_name, opaque_cv, "sec");
      opaque_cv = INTEGER((long)tv->tv_usec);
      opaquePushback(results, r, opaque_name, opaque_cv, "usec");
    }
  else if (value.compare("S,loadavg") == 0) {
      struct loadavg *tv = (struct loadavg*) response;
      opaque_cv = INTEGER((double)tv->ldavg[0]/(double)tv->fscale);
      opaquePushback(results, r, opaque_name, opaque_cv, "ldavg0");
      opaque_cv = INTEGER((double)tv->ldavg[1]/(double)tv->fscale);
      opaquePushback(results, r, opaque_name, opaque_cv, "ldavg1");
      opaque_cv = INTEGER((double)tv->ldavg[2]/(double)tv->fscale);
      opaquePushback(results, r, opaque_name, opaque_cv, "ldavg2");
    }
  else if (value.compare("S,xsw_usage") == 0) {
      struct xsw_usage *xsu = (struct xsw_usage*) response;
      opaque_cv = INTEGER((double)xsu->xsu_total/(1024.0 * 1024.0));
      opaquePushback(results, r, opaque_name, opaque_cv, "xsu_total");
      opaque_cv = INTEGER((double)xsu->xsu_used/(1024.0 * 1024.0));
      opaquePushback(results, r, opaque_name, opaque_cv, "xsu_used");
      opaque_cv = INTEGER((double)xsu->xsu_avail/(1024.0 * 1024.0));
      opaquePushback(results, r, opaque_name, opaque_cv, "xsu_avail");
      opaque_cv = xsu->xsu_encrypted ? "(encrypted)" : "";
      opaquePushback(results, r, opaque_name, opaque_cv, "xsu_encrypted");
    }
  else if (value.compare("T,dev_t") == 0) {
      dev_t *d = (dev_t*) response;
      opaque_cv = INTEGER(major(*d));
      opaquePushback(results, r, opaque_name, opaque_cv, "major");
      opaque_cv = INTEGER(minor(*d));
      opaquePushback(results, r, opaque_name, opaque_cv, "minor");
    }
  else if (value.compare("Q") == 0) {
      int64_t i = *(int64_t *) response;
      opaque_cv = INTEGER(i);
      opaquePushback(results, r, opaque_name, opaque_cv, "i");
  }
  else{
      results.push_back(r);
  }

}

void genControlInfo(int* oid,
                    size_t oid_size,
                    QueryData& results,
                    const std::map<std::string, std::string>& config) {
  Row r;
  if (oid_size == 0) {
    return;
  }

  r["oid"] = stringFromMIB(oid, oid_size);
  // Request the description (the canonical name) for the MIB.
  char response[CTL_MAX_VALUE] = {0};
  size_t response_size = CTL_MAX_VALUE;

  int request[CTL_MAXNAME + 2] = {0, CTL_DEBUG_DESCRIPTION};
  memcpy(request + 2, oid, oid_size * sizeof(int));
  if (sysctl(request, oid_size + 2, response, &response_size, 0, 0) != 0) {
    return;
  }

  r["name"] = std::string(response);
  if (oid[0] > 0 && oid[0] < static_cast<int>(kControlNames.size())) {
    r["subsystem"] = kControlNames[oid[0]];
  }

  // Now request structure type.
  response_size = CTL_MAX_VALUE;
  request[1] = CTL_DEBUG_TYPE;
  if (sysctl(request, oid_size + 2, response, &response_size, 0, 0) != 0) {
    // Cannot request MIB type (int, string, struct, etc).
    return;
  }

  size_t oid_type = 0;
  if (response_size > 0) {
    oid_type = ((size_t)response[0] & CTLTYPE);
    if ((oid_type == 0 || oid_type == CTLTYPE_INT) && response_size > 4) {
      // For whatever reason, macOS defines fewer CTLTYPE's than BSD, and
      // sometimes uses the format character instead of (or in addition to)
      // the CTLTYPE to specify the type. Here we detect a few such cases and
      // map them to CTLTYPE's.
      // TODO: Both CTLTYPE_INT and CTLTYPE_QUAD can be specified as unsigned
      // using a similar method.
      char type_char = response[4];
      switch (type_char) {
      case 'I':
        oid_type = CTLTYPE_INT;
        break;
      case 'L':
        if (sizeof(long) == sizeof(long long)) {
          oid_type = CTLTYPE_QUAD;
        } else if (sizeof(long) == sizeof(int)) {
          oid_type = CTLTYPE_INT;
        }
        break;
      case 'S':
        oid_type = CTLTYPE_STRUCT;
        break;
      case 'Q':
        oid_type = CTLTYPE_QUAD;
        break;
        // Otherwise leave the type as it was; we have no additional knowledge
      }
    }
    if (oid_type < kControlTypes.size()) {
      r["type"] = kControlTypes[oid_type];
    }
  }

  // Finally request MIB value.
  if (oid_type > CTLTYPE_NODE && oid_type < CTLTYPE_OPAQUE) {
    size_t value_size = 0;
    sysctl(oid, oid_size, 0, &value_size, 0, 0);

    if (value_size > CTL_MAX_VALUE) {
      // If the value size is larger than the max value, limit.
      value_size = CTL_MAX_VALUE;
    }

    sysctl(oid, oid_size, response, &value_size, 0, 0);
    if (oid_type == CTLTYPE_INT) {
      unsigned int value;
      memcpy(&value, response, sizeof(int));
      r["current_value"] = INTEGER(value);
    } else if (oid_type == CTLTYPE_STRING) {
      r["current_value"] = std::string(response);
    } else if (oid_type == CTLTYPE_QUAD) {
      unsigned long long value;
      memcpy(&value, response, sizeof(unsigned long long));
      r["current_value"] = INTEGER(value);
    }
  }

  // If this MIB was set using sysctl.conf add the value.
  if (config.count(r.at("name")) > 0) {
    r["config_value"] = config.at(r["name"]);
  }


  // Logic for OPAQUE expansion
  if (oid_type == CTLTYPE_STRUCT) {
    auto value = std::string(response+4);
    size_t value_size = 0;
    sysctl(oid, oid_size, 0, &value_size, 0, 0);

    if (value_size > CTL_MAX_VALUE) {
      // If the value size is larger than the max value, limit.
      value_size = CTL_MAX_VALUE;
    }

    sysctl(oid, oid_size, response, &value_size, 0, 0);
    std::string opaque_name = r["name"];
    opaqueControlInfo(results, r, opaque_name, response, value);
  }
  else {
    results.push_back(r);
  }

}

void genControlInfoFromName(const std::string& name, QueryData& results,
                    const std::map<std::string, std::string>& config) {
  int request[CTL_DEBUG_MAXID + 2] = {0};
  size_t oid_size = CTL_DEBUG_MAXID;
  if (sysctlnametomib(name.c_str(), request, &oid_size) != 0) {
    // MIB lookup failed.
    return;
  }

  genControlInfo((int*)request, oid_size, results, config);
}

void genAllControls(QueryData& results,
                    const std::map<std::string, std::string>& config,
                    const std::string& subsystem) {
  int subsystem_limit = 0;
  if (subsystem.size() != 0) {
    // If a subsystem was provided, limit the enumeration.
    auto it = std::find(kControlNames.begin(), kControlNames.end(), subsystem);
    if (it == kControlNames.end()) {
      // Subsystem is not known.
      return;
    }
    subsystem_limit = std::distance(kControlNames.begin(), it);
  }

  // Use the request to retrieve the MIB vector.
  int request[CTL_DEBUG_MAXID + 2] = {0, CTL_DEBUG_ITERATE};
  size_t request_size = 3;

  // Write the OID into an integer vector to request the name/value.
  int response[CTL_DEBUG_MAXID + 2] = {0};
  size_t response_size = 0;

  // Start iterating from OID=1 if no subsystem was provided.
  request[2] = (subsystem_limit == 0) ? 1 : subsystem_limit;
  size_t num_controls = 0;
  while (num_controls++ < MAX_CONTROLS) {
    // This will walk the MIBs, requesting the 'next' in the response.
    response_size = sizeof(request);
    if (sysctl(request, request_size, response, &response_size, 0, 0) != 0) {
      // Request failed, unhandled serious error.
      break;
    }

    if (subsystem_limit != 0 && response[0] != subsystem_limit) {
      // The OID search was limited to a subsystem.
      break;
    }

    response_size /= sizeof(int);
    genControlInfo(response, response_size, results, config);

    // Set the data for the next OID request.
    memcpy(request + 2, response, CTL_DEBUG_MAXID * sizeof(int));
    request_size = response_size + 2;
  }
}
}
}
