/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sys/socket.h>
#include <sys/types.h>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/applications/linux/namespace_ops.h"
#include "osquery/tables/applications/posix/docker_api.h"
#include "osquery/tables/system/linux/deb.h"

#include <boost/algorithm/string.hpp>
#include <rapidjson/filereadstream.h>

namespace osquery {
namespace tables {

const size_t kBuffSize {65536};

void extractDebPackageInfo(const struct pkginfo* pkg,
                           rapidjson::Writer<rapidjson::StringBuffer>& w) {
  struct varbuf vb;
  varbuf_init(&vb, 20);
  w.StartObject();

  // Iterate over the desired fieldinfos, calling their fwritefunctions
  // to extract the package's information.
  for (const struct fieldinfo& fip : kfieldinfos) {
    fip.wcall(&vb, pkg, &pkg->installed, fw_printheader, &fip);

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

void getDebPackages(const int fd) {
  if (!osquery::isDirectory(kDPKGPath)) {
    TLOG << "cannot find DPKG database: " << kDPKGPath;
    return;
  }

  auto dropper = DropPrivileges::get();
  dropper->dropTo("nobody");

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  writer.StartArray();

  struct pkg_array packages;
  dpkg_setup(&packages);

  const auto* pk = packages.pkgs;
  for (const auto& pkg : boost::make_iterator_range(pk, pk + packages.n_pkgs)) {
    // Casted to int to allow the older enums that were embeded in the
    // packages struct to be compared
    if (static_cast<int>(pkg->status) !=
        static_cast<int>(PKG_STAT_NOTINSTALLED)) {
      extractDebPackageInfo(pkg, writer);
    }
  }

  dpkg_teardown(&packages);
  writer.EndArray();

  const auto bufSize = buffer.GetSize();
  if (bufSize >= 1 && write(fd, buffer.GetString(), bufSize) != static_cast<ssize_t>(bufSize)) {
      TLOG << "error writing pkginfo " << strerror(errno);
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
      TLOG << "error getting docker container info " << id << ": "
              << s.what();
      continue;
    }
    if (!container.get<bool>("State.Running", false)) {
      continue;
    }
    pid_t pid = container.get<int>("State.Pid", 0);
    if (pid == 0) {
      TLOG << "error getting pid for container " << id;
      continue;
    }

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1) {
      TLOG << "unable to open socket pair" << strerror(errno);
      continue;
    }

    NamespaceOps nsOps(pid, fds[1]);
    Status iv = nsOps.invoke(getDebPackages);
    if (!iv.ok()) {
      TLOG << "error entering namespace: " << iv.what();
      close(fds[0]);
      close(fds[1]);
      continue;
    }

    close(fds[1]);
    auto fp = fdopen(fds[0], "rb");
    if (fp == nullptr) {
      TLOG << "unable to open fd " << strerror(errno);
      close(fds[0]);
      auto k = nsOps.kill();
      if (!k.ok()) {
        TLOG << "unable to terminate foked process " << k.what();
      }
      continue;
    }
    std::vector<char> readBuffer(kBuffSize);
    rapidjson::FileReadStream is(fp, &readBuffer[0], readBuffer.size());
    rapidjson::Document doc;
    doc.ParseStream(is);
    fclose(fp);
    close(fds[0]);

    auto wait = nsOps.wait();
    if (!wait.ok()) {
      TLOG << "unable to wait for forked process: " << wait.what();
    }

    if (!doc.IsArray()) {
      continue;
    }
    for (rapidjson::SizeType i = 0; i < doc.Size(); i++) {
      Row r;
      r["id"] = id;
      if (doc[i].HasMember("name")) {
        r["name"] = doc[i]["name"].GetString();
      }
      if (doc[i].HasMember("version")) {
        r["version"] = doc[i]["version"].GetString();
      }
      if (doc[i].HasMember("source")) {
        r["source"] = doc[i]["source"].GetString();
      }
      if (doc[i].HasMember("size")) {
        r["size"] = doc[i]["size"].GetString();
      }
      if (doc[i].HasMember("arch")) {
        r["arch"] = doc[i]["arch"].GetString();
      }
      if (doc[i].HasMember("revision")) {
        r["revision"] = doc[i]["revision"].GetString();
      }
      results.push_back(r);
    }
  }
  return results;
}
}
}
