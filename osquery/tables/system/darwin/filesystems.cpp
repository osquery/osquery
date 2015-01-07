#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>

#include <glog/logging.h>

#include <osquery/tables.h>

namespace osquery {
namespace tables {

  QueryData genFilesystems(QueryContext& context) {
    Row r;
    QueryData results;

    // First get count of filesystems
    int fs_count = getfsstat(NULL, 0, 0);
    if (fs_count == -1) {
      LOG(ERROR) << "Error retrieving filesystems count from getfsstat";
      return {};
    }

    size_t fs_infos_size = fs_count * sizeof(struct statfs);
    std::unique_ptr<struct statfs[]> fs_infos(new struct statfs[fs_infos_size]);
    if (fs_infos == NULL) {
      LOG(ERROR) << "Error allocating fs_info structs";
      return {};
    }

    // Now fill fs_infos with the full info for each fs
    fs_count = getfsstat(fs_infos.get(), fs_infos_size, 0);
    if (fs_count == -1) {
      LOG(ERROR) << "Error retrieving getfsstat info";
      return {};
    }

    for (int i = 0; i < fs_count; ++i) {
      const struct statfs& fs_info = fs_infos[i];
      r["name"] = fs_info.f_mntfromname;
      r["path"] = fs_info.f_mntonname;
      r["type"] = fs_info.f_fstypename;
      results.push_back(r);
    }

    return results;
  }
}
}
