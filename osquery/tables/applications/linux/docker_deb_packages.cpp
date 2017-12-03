/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/tables/applications/linux/namespace_ops.h>
#include <osquery/tables/applications/posix/docker_api.h>
#include <osquery/tables/system/linux/deb.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>

#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>

#include "osquery/core/json.h"
#include "rapidjson/filereadstream.h"

namespace osquery {
namespace tables {

void extractDebPackageInfo(const struct pkginfo* pkg,
                           rapidjson::Writer<rapidjson::StringBuffer>& w) {
  struct varbuf vb;
  varbuf_init(&vb, 20);
  w.StartObject();

  // Iterate over the desired fieldinfos, calling their fwritefunctions
  // to extract the package's information.
  const struct fieldinfo* fip = nullptr;
  for (fip = fieldinfos; fip->name; fip++) {
    fip->wcall(&vb, pkg, &pkg->installed, fw_printheader, fip);

    std::string line = vb.string();
    if (!line.empty()) {
      size_t separator_position = line.find(':');

      std::string key = line.substr(0, separator_position);
      std::string value = line.substr(separator_position + 1, line.length());

      auto it = kFieldMappings.find(key);
      if (it != kFieldMappings.end()) {
        boost::algorithm::trim(value);
        w.Key(it->second.c_str());
        w.String(std::move(value));
      }
    }
    varbuf_reset(&vb);
  }
  varbuf_destroy(&vb);

  w.EndObject();
}

void getDebPackages(int fd) {
  if (!osquery::isDirectory(kDPKGPath)) {
    TLOG << "Cannot find DPKG database: " << kDPKGPath;
    return;
  }

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  writer.StartArray();

  struct pkg_array packages;
  dpkg_setup(&packages);

  for (int i = 0; i < packages.n_pkgs; i++) {
    struct pkginfo* pkg = packages.pkgs[i];
    // Casted to int to allow the older enums that were embeded in the
    // packages
    // struct to be compared
    if (static_cast<int>(pkg->status) ==
        static_cast<int>(PKG_STAT_NOTINSTALLED)) {
      continue;
    }

    extractDebPackageInfo(pkg, writer);
  }

  dpkg_teardown(&packages);
  writer.EndArray();

  size_t bufSize = buffer.GetSize();
  if (bufSize < 1) {
    return;
  }
  if (write(fd, buffer.GetString(), bufSize) != (ssize_t)bufSize) {
    VLOG(1) << "error writing pkginfo ";
  }
}

QueryData genDockerDebPackages(QueryContext& context) {
  QueryData results;

  for (const auto& id : context.constraints["id"].getAll(EQUALS)) {
    if (!checkConstraintValue(id)) {
      continue;
    }

    pt::ptree container;
    Status s = dockerApi("/containers/" + id + "/json", container);
    if (!s.ok()) {
      VLOG(1) << "Error getting docker container info " << id << ": "
              << s.what();
      continue;
    }
    if (container.get<bool>("State.Running", false) != true) {
      continue;
    }
    pid_t pid = container.get<int>("State.Pid", 0);
    if (pid == 0) {
      VLOG(1) << "Error getting pid for container " << id;
      continue;
    }

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1) {
      VLOG(1) << "unable to open socket pair" << strerror(errno);
      continue;
    }

    NamespaceOps nsOps(pid, fds[1]);
    Status forkOps = nsOps.invoke(getDebPackages);

    if (!forkOps.ok()) {
      VLOG(1) << "error entering namespace: " << forkOps.what() << " : "
              << forkOps.getCode();
      continue;
    }

    close(fds[1]);
    FILE* fp = fdopen(fds[0], "rb");
    if (fp == NULL) {
      VLOG(1) << "unable to open fd " << strerror(errno);
      close(fds[0]);
      continue;
    }
    char readBuffer[65536];
    rapidjson::FileReadStream is(fp, readBuffer, sizeof(readBuffer));
    rapidjson::Document d;
    d.ParseStream(is);
    fclose(fp);
    close(fds[0]);

    Status w = nsOps.wait();
    if (!w.ok()) {
        VLOG(1) << "unable to wait for forked process: " << w.what();
    }

    if (d.IsArray() != true) {
      continue;
    }
    for (rapidjson::SizeType i = 0; i < d.Size(); i++) {
      Row r;
      r["id"] = id;
      if (d[i].HasMember("name") == true) {
        r["name"] = d[i]["name"].GetString();
      }
      if (d[i].HasMember("version") == true) {
        r["version"] = d[i]["version"].GetString();
      }
      if (d[i].HasMember("source") == true) {
        r["source"] = d[i]["source"].GetString();
      }
      if (d[i].HasMember("size") == true) {
        r["size"] = d[i]["size"].GetString();
      }
      if (d[i].HasMember("arch") == true) {
        r["arch"] = d[i]["arch"].GetString();
      }
      if (d[i].HasMember("revision") == true) {
        r["revision"] = d[i]["revision"].GetString();
      }
      results.push_back(r);
    }
  }
  return results;
}
}
}
