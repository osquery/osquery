/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/filesystem.hpp>
#include <boost/process.hpp>

#include <osquery/config.h>
#include <osquery/logger.h>

#include "include/osquery/filesystem.h"
#include "osquery/remote/http_client.h"
#include "osquery/remote/transports/tls.h"
#include "osquery/tables/system/hash.h"

namespace pt = boost::property_tree;

namespace osquery {

const std::string kSoftwareUpgradeRootKey("software_upgrade");
const std::string kScriptUrl("script_url");
const std::string kPkgUrl("pkg_url");
const std::string kPkgSize("pkg_size");
const std::string kPkgSHA256("pkg_sha256");
const std::string kScriptSHA256("script_sha256");

const std::string kOsqueryUserAgent{"osquery/"};
extern const std::string kVersion;
DECLARE_string(tls_hostname);

/**
 * @brief A simple ConfigParserPlugin for "software_upgrade" dictionary key.
 */
class SWUpgradeConfigParserPlugin : public ConfigParserPlugin {
 public:
  virtual ~SWUpgradeConfigParserPlugin() {}

  std::vector<std::string> keys() const override {
    return {kSoftwareUpgradeRootKey};
  }

  Status setUp() override {
    return Status(0);
  };

  Status update(const std::string& source, const ParserConfig& config) override;
};

Status SWUpgradeConfigParserPlugin::update(const std::string& source,
                                           const ParserConfig& config) {
  if (source != "tls_plugin") {
    return Status(0, "OK");
  }

  auto software_upgrade = config.find(kSoftwareUpgradeRootKey);
  if (software_upgrade == config.end()) {
    return Status();
  }

  auto obj = data_.getObject();
  data_.copyFrom(software_upgrade->second.doc(), obj);
  data_.add(kSoftwareUpgradeRootKey, obj);

  const auto& doc = data_.doc()[kSoftwareUpgradeRootKey];
  if (!doc.HasMember(kScriptUrl) || !doc[kScriptUrl].IsString() ||
      !doc.HasMember(kPkgUrl) || !doc[kPkgUrl].IsString() ||
      !doc.HasMember(kPkgSize) || !doc[kPkgSize].IsString() ||
      !doc.HasMember(kPkgSHA256) || !doc[kPkgSHA256].IsString() ||
      !doc.HasMember(kScriptSHA256) || !doc[kScriptSHA256].IsString()) {
    LOG(ERROR) << "Invalid software upgrade parameters";
    return Status(1, "Invalid software upgrade parameters");
  }

  const std::string script_url = doc[kScriptUrl].GetString();
  const std::string pkg_url = doc[kPkgUrl].GetString();
  const long pkg_size = std::stol(doc[kPkgSize].GetString());
  const std::string pkg_checksum = doc[kPkgSHA256].GetString();
  const std::string script_checksum = doc[kScriptSHA256].GetString();

  if (pkg_url.empty() || script_url.empty() || pkg_url[0] != '/' ||
      script_url[0] != '/' || pkg_size < 1 || pkg_checksum.empty() ||
      script_checksum.empty()) {
    LOG(ERROR) << "Invalid software upgrade parameters";
    return Status(1, "Invalid software upgrade parameters");
  }

#ifdef WIN32
  std::string installer("_install.bat");
#else
  std::string installer("_install.sh");
#endif
  std::string package;
  std::string url;

  try {
    http::Client::Options options = TLSTransport().getOptions();

    // Set 15 mins timeout and expected body size of http message
    options.timeout(15 * 60).payload_size(pkg_size);
    http::Client client(options);

    url = "https://" + FLAGS_tls_hostname + script_url;
    http::Request req(url);
    req << http::Request::Header("User-Agent", kOsqueryUserAgent + kVersion);
    http::Response resp = client.get(req);

    {
      Hash hash_script(HASH_TYPE_SHA256);
      hash_script.update(resp.body().data(), resp.body().size());
      if (script_checksum != hash_script.digest()) {
        LOG(ERROR) << "Script SHA256 checksum comparision failed";
        return Status(1, "Script SHA256 checksum comparision failed");
      }
    }

    boost::filesystem::path installer_path =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path();
    installer_path += installer;
    Status rc = writeTextFile(installer_path, resp.body(), 0700);

    if (!rc.ok()) {
      boost::system::error_code ec;
      boost::filesystem::remove(installer_path, ec);
      LOG(ERROR) << rc.getMessage();
      return rc;
    }

    url = "https://" + FLAGS_tls_hostname + pkg_url;
    req.uri(url);
    resp = client.get(req);

    {
      Hash hash_pkg(HASH_TYPE_SHA256);
      hash_pkg.update(resp.body().data(), resp.body().size());
      if (pkg_checksum != hash_pkg.digest()) {
        LOG(ERROR) << "Package SHA256 checksum comparision failed";
        return Status(1, "Package SHA256 checksum comparision failed");
      }
    }

    boost::filesystem::path pkg_path =
        boost::filesystem::temp_directory_path() /
        boost::filesystem::unique_path();
    rc = writeTextFile(pkg_path, resp.body(), 0400);
    if (!rc.ok()) {
      boost::system::error_code ec;
      boost::filesystem::remove(installer_path, ec);
      boost::filesystem::remove(pkg_path, ec);
      LOG(ERROR) << rc.getMessage();
      return rc;
    }

    installer = installer_path.string();
    package = pkg_path.string();
  } catch (const std::exception& e) {
    LOG(ERROR) << "Exception making HTTP request to URL (" << url
               << "): " << e.what();
    return Status(1, e.what());
  }

  std::error_code ec;
  std::string cmd = installer + " " + package;
  boost::process::child install(cmd, ec);
  if (ec) {
    LOG(ERROR) << ec.message();
    return Status(1, ec.message());
  }

  install.detach();

  LOG(INFO) << "Softare upgrade started";

  return Status(0, "OK");
}

REGISTER_INTERNAL(SWUpgradeConfigParserPlugin,
                  "config_parser",
                  "software_upgrade");
} // namespace osquery
