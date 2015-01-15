// Copyright 2004-present Facebook. All Rights Reserved.

#include <vector>
#include <string>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <glog/logging.h>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

namespace osquery {
	namespace tables {

		QueryData parseNfsSharesContent(const std::string& content) {
			QueryData results;

			for (const auto& i : split(content, "\n")) {
				auto line = split(i);
				if (line.size() == 0 || boost::starts_with(line[0], "#")) {
					continue;
				}
				std::vector<std::string> lineExports;
				unsigned int readonly = 0;
				int indexOfOptions = -1;

				for (std::vector<std::string>::iterator iter = line.begin();
					 iter != line.end();
					 ++iter){
					indexOfOptions++;
					if((*iter)[0] == '/'){
						lineExports.push_back(*iter);
						
					}else{
						break;
					}
				}
				for(std::vector<std::string>::iterator iter = line.begin()+indexOfOptions;
					 iter != line.end();
					 ++iter){
					if(iter->compare("-ro") == 0|| iter->compare("-o") == 0){
						readonly = 1;
					}
				}
				for (std::vector<std::string>::iterator iter = lineExports.begin(); iter != lineExports.end(); ++iter)
				{
					Row r;
					r["share"] = *iter;
					if(readonly){
						r["readonly"]  = "yes";
					}else{
						r["readonly"] = "no";
					}
					std::ostringstream oss;
					std::copy(line.begin()+indexOfOptions, line.end(), std::ostream_iterator<std::string>(oss, " "));
					r["options"] = oss.str();
					results.push_back(r);
				}
				//r["hosts"] = boost::algorithm::join(line, " ");
				//results.push_back(r);
			}

			return results;
		}

		QueryData genNfsShares(QueryContext& context) {
			std::string content;
				auto s = osquery::readFile("/etc/exports", content);
			if (s.ok()) {
				return parseNfsSharesContent(content);
			} else {
				LOG(ERROR) << "Error reading /etc/exports: " << s.toString();
				return {};
			}
		}
	}
}