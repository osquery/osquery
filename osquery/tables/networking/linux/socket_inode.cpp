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

using namespace boost::filesystem;
using namespace boost;

namespace osquery {
    namespace tables {

        void crawl_proc(QueryData &results) {
            path dir_path = "/proc";
            directory_iterator end_itr;
            directory_iterator itr(dir_path);
            for ( itr; itr != end_itr; ++itr ) {

                if (itr->path().string().find("self") != std::string::npos) {
                    continue;
                }

                if ( is_directory(itr->status()) ) {
                    std::string d_path = itr->path().string();

                    // make sure /proc/*/fd is there
                    d_path.append("/fd");
                    struct stat s;
                    int err = stat(d_path.c_str(), &s);
                    if(-1 == err) {
                        continue;
                    }

                    directory_iterator e_i;
                    directory_iterator i( d_path);
                    for ( i; i != e_i; ++i ) {
                        char *linkname;
                        ssize_t r;
                        linkname = (char*)malloc(32);
                        std::string path = i->path().string();

                        r = readlink(path.c_str(), linkname, 32);
                        std::string link_str(linkname, linkname + 32);

                        // matches socket:[13415]
                        if (link_str.find("socket") != std::string::npos) {
                            boost::regex e("[0-9]+");
                            boost::smatch inode;
                            boost::regex_search(link_str, inode, e);
                            if(inode[0].str().length() > 0) {
                                std::vector<std::string> pid;
                                boost::split(pid, path, boost::is_any_of("/"));
                                Row r;
                                r["pid"] = boost::lexical_cast<std::string>( pid[2].c_str() );
                                r["inode"] = boost::lexical_cast<std::string>( inode[0].str() );
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
