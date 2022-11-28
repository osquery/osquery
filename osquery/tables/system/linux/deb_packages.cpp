/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/linux/idpkgquery.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

namespace {

// From the documentation: this directory contains many files that give
// information about status of installed or uninstalled packages
const std::string kAdminDir{"/var/lib/dpkg"};

void logError(Logger& logger,
              const std::string& message,
              const Error<IDpkgQuery::ErrorCode>& error,
              const std::string& admindir) {
  auto error_code = error.getErrorCode();

  const auto& error_description =
      IDpkgQuery::getErrorCodeDescription(error_code);

  logger.log(google::GLOG_ERROR,
             "deb_packages: " + message + ": " + error_description +
                 " (admindir='" + admindir + "')");
}

} // namespace

QueryData genDebPackagesImpl(QueryContext& context, Logger& logger) {
  std::vector<std::string> admindir_list{};

  if (context.hasConstraint("admindir", EQUALS)) {
    for (const auto& admindir :
         context.constraints["admindir"].getAll(EQUALS)) {
      admindir_list.push_back(admindir);
    }

  } else {
    admindir_list.push_back(kAdminDir);
  }

  // Drop to 'nobody' to ensure that the libdpkg library
  // can't change the package database. Privileges will be
  // restored automatically when the `dropper` object goes
  // out of scope.
  //
  // Note that this is *NOT* a security feature
  auto dropper = DropPrivileges::get();
  dropper->dropTo("nobody");

  QueryData results;

  for (const auto& admindir : admindir_list) {
    auto dpkg_query_exp = IDpkgQuery::create(admindir);
    if (dpkg_query_exp.isError()) {
      logError(logger,
               "Failed to open the dpkg database",
               dpkg_query_exp.takeError(),
               admindir);

      continue;
    }

    auto dpkg_query = dpkg_query_exp.take();

    auto package_list_exp = dpkg_query->getPackageList();
    if (package_list_exp.isError()) {
      logError(logger,
               "Failed to list the packages",
               package_list_exp.takeError(),
               admindir);

      continue;
    }

    auto package_list = package_list_exp.take();

    for (const auto& package : package_list) {
      Row r;
      r["name"] = package.name;
      r["version"] = package.version;
      r["arch"] = package.arch;
      r["status"] = package.status;
      r["revision"] = package.revision;
      r["priority"] = package.priority;
      r["section"] = package.section;
      r["source"] = package.source;
      r["size"] = package.size;
      r["maintainer"] = package.maintainer;
      r["admindir"] = admindir;
      r["pid_with_namespace"] = "0";

      results.push_back(std::move(r));
    }
  }

  return results;
}

QueryData genDebPackages(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "deb_packages", genDebPackagesImpl);
  } else {
    GLOGLogger logger;
    return genDebPackagesImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
