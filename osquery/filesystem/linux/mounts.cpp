/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <mntent.h>
#include <sys/vfs.h>

#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include <osquery/filesystem/linux/mounts.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/system/filepath.h>

namespace osquery {
namespace {
const std::string kMountsPseudoFile{"/proc/mounts"};

// Liveness deadline, not a latency target: generous enough that a
// slow-but-alive mount still returns full data, short enough to bound how long
// a hung mount can park the worker. Mounts slower than this are
// indistinguishable from hung.
constexpr std::chrono::seconds kStatFsTimeout{5};

boost::optional<MountInformation::StatFsInfo> readStatFsInfo(
    const std::string& path) {
  struct statfs stats = {};
  if (statfs(path.c_str(), &stats) != 0) {
    LOG(ERROR) << "statfs failed with errno " << std::to_string(errno)
               << " on path " << path;
    return boost::none;
  }

  MountInformation::StatFsInfo statfs_info = {};
  statfs_info.block_size = static_cast<std::uint64_t>(stats.f_bsize);
  statfs_info.block_count = static_cast<std::uint64_t>(stats.f_blocks);
  statfs_info.free_block_count = static_cast<std::uint64_t>(stats.f_bfree);
  statfs_info.unprivileged_free_block_count =
      static_cast<std::uint64_t>(stats.f_bavail);
  statfs_info.inode_count = static_cast<std::uint64_t>(stats.f_files);
  statfs_info.free_inode_count = static_cast<std::uint64_t>(stats.f_ffree);
  return statfs_info;
}

struct MountDataDeleter final {
  void operator()(FILE* ptr) {
    if (ptr == nullptr) {
      return;
    }

    endmntent(ptr);
  }
};

using MountData = std::unique_ptr<FILE, MountDataDeleter>;

Status getMountData(MountData& obj) {
  obj = {};

  auto mount_data = setmntent(kMountsPseudoFile.c_str(), "r");
  if (mount_data == nullptr) {
    return Status::failure("Failed to open the '" + kMountsPseudoFile +
                           "' pseudo file");
  }

  obj.reset(mount_data);
  return Status::success();
}

// Mount paths with an outstanding statfs probe (detached thread still blocked).
// Skipping in-flight paths caps the leak at one thread per hung mount.
class InFlightStatFsProbes final {
 public:
  bool tryBegin(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    return in_flight_.insert(path).second;
  }

  void end(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    in_flight_.erase(path);
  }

 private:
  std::mutex mutex_;
  std::unordered_set<std::string> in_flight_;
};

InFlightStatFsProbes& inFlightStatFsProbes() {
  // Leaked on purpose: a detached probe thread can outlive main() and call
  // end() during shutdown, so this must never be destroyed under it.
  static auto* probes = new InFlightStatFsProbes;
  return *probes;
}
} // namespace

std::vector<boost::optional<MountInformation::StatFsInfo>>
getStatFsInfoWithTimeout(const std::vector<std::string>& paths,
                         std::chrono::milliseconds timeout,
                         const StatFsInfoProducer& producer) {
  using OptionalStatFsInfo = boost::optional<MountInformation::StatFsInfo>;

  // statfs(path) depends only on the path, so probe each distinct path once and
  // fan the result to every occurrence -- otherwise a shadowed mount (listed
  // twice in /proc/mounts) would be skipped by the in-flight tracker.
  std::vector<std::size_t> unique_paths;
  std::unordered_map<std::string, std::size_t> path_to_unique;
  std::vector<std::size_t> occurrence_of_unique(paths.size());
  for (std::size_t i = 0; i < paths.size(); ++i) {
    auto it = path_to_unique.find(paths[i]);
    if (it == path_to_unique.end()) {
      path_to_unique.emplace(paths[i], unique_paths.size());
      occurrence_of_unique[i] = unique_paths.size();
      unique_paths.push_back(i);
    } else {
      occurrence_of_unique[i] = it->second;
    }
  }

  std::vector<OptionalStatFsInfo> unique_results(unique_paths.size());
  std::vector<std::future<OptionalStatFsInfo>> futures(unique_paths.size());

  auto& probes = inFlightStatFsProbes();
  for (std::size_t u = 0; u < unique_paths.size(); ++u) {
    const auto& path = paths[unique_paths[u]];
    if (!probes.tryBegin(path)) {
      // Verbose, not ERROR: recurs every scheduled query for a known-hung
      // mount.
      VLOG(1) << "statfs already in flight (mount likely hung) on path " << path
              << "; skipping filesystem statistics for this mount";
      continue;
    }

    auto promise = std::make_shared<std::promise<OptionalStatFsInfo>>();
    futures[u] = promise->get_future();

    // Detached: a thread blocked in statfs() can't be cancelled, so we abandon
    // it. The shared_ptr keeps the promise alive for it to write into after we
    // return. The inner try/catch is required -- an exception escaping the
    // thread would call std::terminate.
    try {
      std::thread([promise, producer, path, &probes]() {
        OptionalStatFsInfo value;
        try {
          value = producer(path);
        } catch (const std::exception& e) {
          LOG(ERROR) << "statfs producer threw on path " << path << ": "
                     << e.what();
        } catch (...) {
          LOG(ERROR) << "statfs producer threw on path " << path;
        }
        probes.end(path);
        promise->set_value(value);
      }).detach();
    } catch (const std::system_error& e) {
      LOG(ERROR) << "Failed to create statfs thread on path " << path << ": "
                 << e.what();
      probes.end(path);
      futures[u] = {};
    }
  }

  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (std::size_t u = 0; u < futures.size(); ++u) {
    if (!futures[u].valid()) {
      continue;
    }

    if (futures[u].wait_until(deadline) != std::future_status::ready) {
      LOG(ERROR) << "statfs timed out after " << std::to_string(timeout.count())
                 << "ms on path " << paths[unique_paths[u]]
                 << "; skipping filesystem statistics for this mount";
      continue;
    }

    unique_results[u] = futures[u].get();
  }

  std::vector<OptionalStatFsInfo> results(paths.size());
  for (std::size_t i = 0; i < paths.size(); ++i) {
    results[i] = unique_results[occurrence_of_unique[i]];
  }

  return results;
}

Status getMountedFilesystems(MountedFilesystems& mounted_fs_info) {
  mounted_fs_info = {};

  MountData mount_data;
  auto status = getMountData(mount_data);
  if (!status.ok()) {
    return status;
  }

  std::vector<char> string_buffer(4096);

  std::vector<std::string> statfs_paths;
  std::vector<std::size_t> statfs_targets;

  for (;;) {
    mntent ent = {};
    errno = 0;
    if (getmntent_r(mount_data.get(),
                    &ent,
                    string_buffer.data(),
                    string_buffer.size()) == nullptr) {
      if (errno != 0) {
        LOG(ERROR) << "getmntent_r failed with errno " << std::to_string(errno);
      }
      break;
    }

    MountInformation mount_info = {};
    mount_info.type = ent.mnt_type;
    mount_info.device = ent.mnt_fsname;
    mount_info.device_alias = canonicalize_file_name(ent.mnt_fsname);
    mount_info.path = ent.mnt_dir;
    mount_info.flags = ent.mnt_opts;

    if (mount_info.type == "autofs") {
      VLOG(1) << "Skipping statfs information for autofs mount: "
              << mount_info.path;

    } else {
      // statfs() can hang indefinitely on a malicious or unresponsive mount
      // (e.g. a FUSE filesystem whose handler never returns), so defer it and
      // run every mount's probe under a shared timeout below.
      statfs_paths.push_back(mount_info.path);
      statfs_targets.push_back(mounted_fs_info.size());
    }

    mounted_fs_info.emplace_back(std::move(mount_info));
  }

  auto statfs_info =
      getStatFsInfoWithTimeout(statfs_paths, kStatFsTimeout, readStatFsInfo);
  for (std::size_t i = 0; i < statfs_targets.size(); ++i) {
    mounted_fs_info[statfs_targets[i]].optional_statfs_info =
        std::move(statfs_info[i]);
  }

  return Status::success();
}
} // namespace osquery
