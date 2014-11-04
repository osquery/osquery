#include <stdio.h>
#include <stdlib.h>

#include <iostream>
#include <string>
#include <boost/regex.hpp>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <boost/algorithm/string.hpp>

#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"


namespace osquery {
namespace tables {

void crawl_proc(QueryData &results) {
  boost::filesystem::path dir_path = "/proc";
  for (boost::filesystem::directory_iterator itr(dir_path), end_itr; itr != end_itr; ++itr) {

    if (boost::filesystem::is_directory(itr->status())) {
      std::string d_path = itr->path().string();

      // make sure /proc/*/fd is there
      d_path.append("/fd");
      struct stat s;
      int err = stat(d_path.c_str(), &s);
      if (err == -1) {
        continue;
      }

      for (boost::filesystem::directory_iterator i(d_path), e_i; i != e_i; ++i) {
        char* linkname = (char *)malloc(32);
        std::string path = i->path().string();
        auto r = readlink(path.c_str(), linkname, 32);
        std::string link_str(linkname, linkname + 32);
        free(linkname);

        // matches socket:[13415]
        if (link_str.find("socket") != std::string::npos) {
          boost::regex e("[0-9]+");
          boost::smatch inode;
          boost::regex_search(link_str, inode, e);
          if (inode[0].str().length() > 0) {
            std::vector<std::string> pid;
            boost::split(pid, path, boost::is_any_of("/"));
            Row r;
            r["pid"] = boost::lexical_cast<std::string>(pid[2].c_str());
            r["inode"] = boost::lexical_cast<std::string>(inode[0].str());
            results.push_back(r);
            continue;
          }
        }
      }
    }
  }
  return;
}

QueryData genSocketInode() {
  QueryData results;
  crawl_proc(results);
  return results;
}
}
}
