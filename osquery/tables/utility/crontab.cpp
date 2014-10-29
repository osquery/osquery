// Copyright 2004-present Facebook. All Rights Reserved.

#include <ctime>
#include <string>
#include <iostream>
#include <boost/lexical_cast.hpp>
#include "osquery/database.h"
#include <boost/algorithm/string.hpp>

using namespace std;
using namespace boost;

using std::string;
using boost::lexical_cast;

namespace osquery {
namespace tables {

const char* COL_COMMAND = "command";
const char* COL_DAY_OF_WEEK = "day_of_week";
const char* COL_MONTH = "month";
const char* COL_DAY_OF_MONTH = "day_of_month";
const char* COL_HOUR = "hour";
const char* COL_MINUTE = "minute";

std::vector<std::string> getCmdOutput(const std::string& mStr) {
  std::vector<std::string> lines;
  std::string result, line, chunk;
  FILE* pipe{popen(mStr.c_str(), "r")};
  if (pipe == nullptr) {
    return lines;
  }

  // currently works only for lines shorter than 1024 characters
  char buffer[1024];
  while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
    chunk = buffer;
    lines.push_back(chunk.substr(0, chunk.size() - 1));
  }

  pclose(pipe);
  return lines;
}

QueryData genCronTab() {
  QueryData results;

  std::vector<std::string> lines = getCmdOutput("crontab -l");

  for (std::vector<std::string>::iterator itL = lines.begin();
       itL < lines.end();
       ++itL) {

    Row r;

    std::vector<std::string> columns;
    boost::split(columns, *itL, boost::is_any_of(" \t"));

    r[COL_MINUTE] = "";
    r[COL_HOUR] = "";
    r[COL_DAY_OF_MONTH] = "";
    r[COL_MONTH] = "";
    r[COL_DAY_OF_WEEK] = "";
    r[COL_COMMAND] = "";

    int index = 0;
    for (std::vector<std::string>::iterator itC = columns.begin();
         itC < columns.end();
         ++itC) {
      switch (index) {
      case 0:
        r[COL_MINUTE] = *itC;
        break;
      case 1:
        r[COL_HOUR] = *itC;
        break;
      case 2:
        r[COL_DAY_OF_MONTH] = *itC;
        break;
      case 3:
        r[COL_MONTH] = *itC;
        break;
      case 4:
        r[COL_DAY_OF_WEEK] = *itC;
        break;
      case 5:
        r[COL_COMMAND] = *itC;
        break;
      default:
        r[COL_COMMAND] += (' ' + *itC);
      }
      index++;
    }

    results.push_back(r);
  }

  return results;
}
}
}
