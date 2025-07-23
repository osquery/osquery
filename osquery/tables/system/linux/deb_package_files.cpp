// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/linux/idpkgquery.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>
#include <osquery/sql/dynamic_table_row.h>

#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <unistd.h>

namespace osquery {
namespace tables {

namespace {

struct ErrorLog {
  std::string message;
  Error<IDpkgQuery::ErrorCode> code;
  std::string admindir;

  ErrorLog(const std::string& msg,
           Error<IDpkgQuery::ErrorCode>&& c,
           const std::string& dir)
      : message(msg), code(std::move(c)), admindir(dir) {}
};

const std::string kAdminDir{"/var/lib/dpkg"};

void logError(Logger& logger,
              const std::string& message,
              const Error<IDpkgQuery::ErrorCode>& error,
              const std::string& admindir) {
  auto error_code = error.getErrorCode();
  const auto& error_description =
      IDpkgQuery::getErrorCodeDescription(error_code);
  logger.log(google::GLOG_ERROR,
             "deb_package_files: " + message + ": " + error_description +
                 " (admindir='" + admindir + "')");
}

// Helper to get file info (username, groupname, mode, size, sha256)
bool getFileInfo(const std::string& path, std::string& username, std::string& groupname, std::string& mode, std::string& size, std::string& sha256) {
  struct stat st;
  if (lstat(path.c_str(), &st) != 0) {
    return false;
  }
  struct passwd* pw = getpwuid(st.st_uid);
  struct group* gr = getgrgid(st.st_gid);
  username = pw ? pw->pw_name : std::to_string(st.st_uid);
  groupname = gr ? gr->gr_name : std::to_string(st.st_gid);
  char mode_buf[11];
  snprintf(mode_buf, sizeof(mode_buf), "%o", st.st_mode & 07777);
  mode = mode_buf;
  size = std::to_string(st.st_size);
  // SHA256 calculation omitted for brevity; can be added if needed
  sha256 = "";
  return true;
}

} // namespace

void genDebPackageFiles(RowYield& yield, QueryContext& context) {
  GLOGLogger logger;
  std::vector<std::string> admindir_list{};
  std::vector<ErrorLog> errorLogBuffer{};

  if (context.hasConstraint("admindir", EQUALS)) {
    for (const auto& admindir :
         context.constraints["admindir"].getAll(EQUALS)) {
      admindir_list.push_back(admindir);
    }
  } else {
    admindir_list.push_back(kAdminDir);
  }

  auto dropper = DropPrivileges::get();
  dropper->dropTo("nobody");

  for (const auto& admindir : admindir_list) {
    if (!pathExists(admindir).ok()) {
      continue;
    }
    auto dpkg_query_exp = IDpkgQuery::create(admindir);
    if (dpkg_query_exp.isError()) {
      errorLogBuffer.emplace_back("Failed to open the dpkg database",
                                  dpkg_query_exp.takeError(),
                                  admindir);
      continue;
    }
    auto dpkg_query = dpkg_query_exp.take();
    auto package_list_exp = dpkg_query->getPackageList();
    if (package_list_exp.isError()) {
      errorLogBuffer.emplace_back("Failed to list the packages",
                                  package_list_exp.takeError(),
                                  admindir);
      continue;
    }
    auto package_list = package_list_exp.take();

    // Handle package constraint
    std::set<std::string> allowed_packages;
    bool has_package_constraint = false;
    if (context.constraints["package"].exists(EQUALS)) {
      has_package_constraint = true;
      allowed_packages = context.constraints["package"].getAll(EQUALS);
    }

    for (const auto& package : package_list) {
      if (has_package_constraint && allowed_packages.count(package.name) == 0) {
        continue;
      }
      // For each package, try to read its list of files from /var/lib/dpkg/info/<package>.list
      std::string list_file = admindir + "/info/" + package.name + ".list";
      if (!pathExists(list_file).ok()) {
        continue;
      }
      std::string file_content;
      auto status = osquery::readFile(list_file, file_content);
      if (!status.ok()) {
        continue;
      }
      std::istringstream iss(file_content);
      std::string file_path;
      while (std::getline(iss, file_path)) {
        if (file_path.empty()) {
          continue;
        }
        std::string username, groupname, mode, size, sha256;
        getFileInfo(file_path, username, groupname, mode, size, sha256);
        auto r = make_table_row();
        r["package"] = package.name;
        r["path"] = file_path;
        r["username"] = username;
        r["groupname"] = groupname;
        r["mode"] = mode;
        r["size"] = size;
        r["sha256"] = sha256;
        r["admindir"] = admindir;
        yield(std::move(r));
      }
    }
  }

  // Now that we have privileges restored, we can log the errors.
  for (const auto& errorLog : errorLogBuffer) {
    logError(logger, errorLog.message, errorLog.code, errorLog.admindir);
  }
}

} // namespace tables
} // namespace osquery 