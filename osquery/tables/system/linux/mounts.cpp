#include <boost/lexical_cast.hpp>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

#include <stdio.h>
#include <mntent.h>
#include <sys/vfs.h>

namespace osquery {
namespace tables {
QueryData genMounts() {
  QueryData results;
  FILE *mounts;
  struct mntent *ent;
  char real_path[PATH_MAX];
  struct statfs st;

  if (mounts = setmntent("/proc/mounts", "r")) {
    while (ent = getmntent(mounts)) {
      Row r;

      r["fsname"] = std::string(ent->mnt_fsname);
      r["fsname_real"] = std::string(
          realpath(ent->mnt_fsname, real_path) ? real_path : ent->mnt_fsname);
      r["dir"] = std::string(ent->mnt_dir);
      r["type"] = std::string(ent->mnt_type);
      r["opts"] = std::string(ent->mnt_opts);
      r["freq"] = boost::lexical_cast<std::string>(ent->mnt_freq);
      r["passno"] = boost::lexical_cast<std::string>(ent->mnt_passno);
      if (!statfs(ent->mnt_dir, &st)) {
        r["block_size"] = boost::lexical_cast<std::string>(st.f_bsize);
        r["blocks"] = boost::lexical_cast<std::string>(st.f_blocks);
        r["blocks_free"] = boost::lexical_cast<std::string>(st.f_bfree);
        r["blocks_avail"] = boost::lexical_cast<std::string>(st.f_bavail);
        r["inodes"] = boost::lexical_cast<std::string>(st.f_files);
        r["inodes_free"] = boost::lexical_cast<std::string>(st.f_ffree);
      }

      results.push_back(r);
    }
    endmntent(mounts);
  }

  return results;
}
}
}
