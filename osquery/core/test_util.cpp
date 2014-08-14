// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core/test_util.h"

#include <deque>
#include <sstream>

#include <boost/property_tree/json_parser.hpp>

#include <glog/logging.h>

#include "osquery/core/sqlite_util.h"
#include "osquery/filesystem.h"

using namespace osquery::db;
namespace pt = boost::property_tree;

namespace osquery {
namespace core {

const std::string kTestQuery = "SELECT * FROM test_table";

sqlite3* createTestDB() {
  sqlite3* db = createDB();
  char* err = nullptr;
  std::vector<std::string> queries = {
      "CREATE TABLE test_table ("
      "username varchar(30) primary key, "
      "age int"
      ")",
      "INSERT INTO test_table VALUES (\"mike\", 23)",
      "INSERT INTO test_table VALUES (\"matt\", 24)"};
  for (auto q : queries) {
    sqlite3_exec(db, q.c_str(), nullptr, nullptr, &err);
    if (err != nullptr) {
      LOG(ERROR) << "Error creating test database: " << err;
      return nullptr;
    }
  }

  return db;
}

QueryData getTestDBExpectedResults() {
  QueryData d;
  Row row1;
  row1["username"] = "mike";
  row1["age"] = "23";
  d.push_back(row1);
  Row row2;
  row2["username"] = "matt";
  row2["age"] = "24";
  d.push_back(row2);
  return d;
}

std::vector<std::pair<std::string, QueryData>> getTestDBResultStream() {
  std::vector<std::pair<std::string, QueryData>> results;

  std::string q2 =
      "INSERT INTO test_table (username, age) VALUES (\"joe\", 25)";
  QueryData d2;
  Row row2_1;
  row2_1["username"] = "mike";
  row2_1["age"] = "23";
  d2.push_back(row2_1);
  Row row2_2;
  row2_2["username"] = "matt";
  row2_2["age"] = "24";
  d2.push_back(row2_2);
  Row row2_3;
  row2_3["username"] = "joe";
  row2_3["age"] = "25";
  d2.push_back(row2_3);
  results.push_back(std::make_pair(q2, d2));

  std::string q3 = "UPDATE test_table SET age = 27 WHERE username = \"matt\"";
  QueryData d3;
  Row row3_1;
  row3_1["username"] = "mike";
  row3_1["age"] = "23";
  d3.push_back(row3_1);
  Row row3_2;
  row3_2["username"] = "matt";
  row3_2["age"] = "27";
  d3.push_back(row3_2);
  Row row3_3;
  row3_3["username"] = "joe";
  row3_3["age"] = "25";
  d3.push_back(row3_3);
  results.push_back(std::make_pair(q3, d3));

  std::string q4 =
      "DELETE FROM test_table WHERE username = \"matt\" AND age = 27";
  QueryData d4;
  Row row4_1;
  row4_1["username"] = "mike";
  row4_1["age"] = "23";
  d4.push_back(row4_1);
  Row row4_2;
  row4_2["username"] = "joe";
  row4_2["age"] = "25";
  d4.push_back(row4_2);
  results.push_back(std::make_pair(q4, d4));

  return results;
}

osquery::config::OsqueryScheduledQuery getOsqueryScheduledQuery() {
  osquery::config::OsqueryScheduledQuery q;
  q.name = "foobartest";
  q.query = "SELECT filename FROM fs WHERE path = '/bin' ORDER BY filename";
  q.interval = 5;
  return q;
}

std::pair<boost::property_tree::ptree, Row> getSerializedRow() {
  Row r;
  r["foo"] = "bar";
  r["meaning_of_life"] = "42";
  pt::ptree arr;
  arr.put<std::string>("foo", "bar");
  arr.put<std::string>("meaning_of_life", "42");
  return std::make_pair(arr, r);
}

std::pair<boost::property_tree::ptree, QueryData> getSerializedQueryData() {
  auto r = getSerializedRow();
  QueryData q = {r.second, r.second};
  pt::ptree arr;
  arr.push_back(std::make_pair("", r.first));
  arr.push_back(std::make_pair("", r.first));
  return std::make_pair(arr, q);
}

std::pair<boost::property_tree::ptree, DiffResults> getSerializedDiffResults() {
  auto qd = getSerializedQueryData();
  DiffResults diff_results;
  diff_results.added = qd.second;
  diff_results.removed = qd.second;

  pt::ptree root;
  root.add_child("added", qd.first);
  root.add_child("removed", qd.first);

  return std::make_pair(root, diff_results);
}

std::pair<std::string, osquery::db::DiffResults>
getSerializedDiffResultsJSON() {
  auto results = getSerializedDiffResults();

  std::ostringstream ss;
  pt::write_json(ss, results.first, false);

  return std::make_pair(ss.str(), results.second);
}

std::pair<pt::ptree, osquery::db::HistoricalQueryResults>
getSerializedHistoricalQueryResults() {
  auto qd = getSerializedQueryData();
  auto dr = getSerializedDiffResults();
  HistoricalQueryResults r;
  r.executions = std::deque<int>{2, 1};
  r.mostRecentResults.first = 2;
  r.mostRecentResults.second = qd.second;
  r.pastResults[1] = dr.second;

  pt::ptree root;

  pt::ptree executions;
  pt::ptree item1;
  item1.put("", 2);
  executions.push_back(std::make_pair("", item1));
  pt::ptree item2;
  item2.put("", 1);
  executions.push_back(std::make_pair("", item2));
  root.add_child("executions", executions);

  pt::ptree mostRecentResults;
  mostRecentResults.add_child("2", qd.first);
  root.add_child("mostRecentResults", mostRecentResults);

  pt::ptree pastResults;
  pastResults.add_child("1", dr.first);
  root.add_child("pastResults", pastResults);

  return std::make_pair(root, r);
}

std::pair<std::string, osquery::db::HistoricalQueryResults>
getSerializedHistoricalQueryResultsJSON() {
  auto results = getSerializedHistoricalQueryResults();

  std::ostringstream ss;
  pt::write_json(ss, results.first, false);

  return std::make_pair(ss.str(), results.second);
}

std::pair<boost::property_tree::ptree, osquery::db::ScheduledQueryLogItem>
getSerializedScheduledQueryLogItem() {
  ScheduledQueryLogItem i;
  pt::ptree root;
  auto dr = getSerializedDiffResults();
  i.diffResults = dr.second;
  i.name = "foobar";
  root.add_child("diffResults", dr.first);
  root.put<std::string>("name", "foobar");
  return std::make_pair(root, i);
}

std::pair<std::string, osquery::db::ScheduledQueryLogItem>
getSerializedScheduledQueryLogItemJSON() {
  auto results = getSerializedScheduledQueryLogItem();

  std::ostringstream ss;
  pt::write_json(ss, results.first, false);

  return std::make_pair(ss.str(), results.second);
}

std::string getEtcHostsContent() {
  std::string content = R"(
    ##
    # Host Database
    #
    # localhost is used to configure the loopback interface
    # when the system is booting.  Do not change this entry.
    ##
    127.0.0.1       localhost
    255.255.255.255 broadcasthost
    ::1             localhost
    fe80::1%lo0     localhost
    )";
  return content;
}

std::string getPlistContent() {
  std::string content = R"(
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Disabled</key>
  <true/>
  <key>Label</key>
  <string>com.apple.FileSyncAgent.sshd</string>
  <key>ProgramArguments</key>
  <array>
    <string>/System/Library/CoreServices/FileSyncAgent.app/Contents/Resources/FileSyncAgent_sshd-keygen-wrapper</string>
    <string>-i</string>
    <string>-f</string>
    <string>/System/Library/CoreServices/FileSyncAgent.app/Contents/Resources/FileSyncAgent_sshd_config</string>
  </array>
  <key>SessionCreate</key>
  <true/>
  <key>Sockets</key>
  <dict>
    <key>Listeners</key>
    <dict>
      <key>SockServiceName</key>
      <string>appleugcontrol</string>
      <key>Bonjour</key>
      <true/>
    </dict>
  </dict>
  <key>StandardErrorPath</key>
  <string>/dev/null</string>
  <key>inetdCompatibility</key>
  <dict>
    <key>Wait</key>
    <false/>
  </dict>
</dict>
</plist>
)";
  return content;
}

osquery::db::QueryData getEtcHostsExpectedResults() {
  Row row1;
  Row row2;
  Row row3;
  Row row4;

  row1["address"] = "127.0.0.1";
  row1["hostnames"] = "localhost";
  row2["address"] = "255.255.255.255";
  row2["hostnames"] = "broadcasthost";
  row3["address"] = "::1";
  row3["hostnames"] = "localhost";
  row4["address"] = "fe80::1%lo0";
  row4["hostnames"] = "localhost";
  return {row1, row2, row3, row4};
}

std::vector<SplitStringTestData> generateSplitStringTestData() {
  SplitStringTestData s1;
  s1.test_string = "a b\tc";
  s1.test_vector = {"a", "b", "c"};

  SplitStringTestData s2;
  s2.test_string = " a b   c";
  s2.test_vector = {"a", "b", "c"};

  SplitStringTestData s3;
  s3.test_string = "  a     b   c";
  s3.test_vector = {"a", "b", "c"};

  return {s1, s2, s3};
}

std::string getALFContent() {
  std::string content = R"(
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>allowsignedenabled</key>
  <integer>1</integer>
  <key>applications</key>
  <array/>
  <key>exceptions</key>
  <array>
    <dict>
      <key>path</key>
      <string>/usr/libexec/configd</string>
      <key>state</key>
      <integer>3</integer>
    </dict>
    <dict>
      <key>path</key>
      <string>/usr/sbin/mDNSResponder</string>
      <key>state</key>
      <integer>3</integer>
    </dict>
    <dict>
      <key>path</key>
      <string>/usr/sbin/racoon</string>
      <key>state</key>
      <integer>3</integer>
    </dict>
    <dict>
      <key>path</key>
      <string>/usr/bin/nmblookup</string>
      <key>state</key>
      <integer>3</integer>
    </dict>
    <dict>
      <key>path</key>
      <string>/System/Library/PrivateFrameworks/Admin.framework/Versions/A/Resources/readconfig</string>
      <key>state</key>
      <integer>3</integer>
    </dict>
  </array>
  <key>explicitauths</key>
  <array>
    <dict>
      <key>id</key>
      <string>org.python.python.app</string>
    </dict>
    <dict>
      <key>id</key>
      <string>com.apple.ruby</string>
    </dict>
    <dict>
      <key>id</key>
      <string>com.apple.a2p</string>
    </dict>
    <dict>
      <key>id</key>
      <string>com.apple.javajdk16.cmd</string>
    </dict>
    <dict>
      <key>id</key>
      <string>com.apple.php</string>
    </dict>
    <dict>
      <key>id</key>
      <string>com.apple.nc</string>
    </dict>
    <dict>
      <key>id</key>
      <string>com.apple.ksh</string>
    </dict>
  </array>
  <key>firewall</key>
  <dict>
    <key>Apple Remote Desktop</key>
    <dict>
      <key>proc</key>
      <string>AppleVNCServer</string>
      <key>state</key>
      <integer>0</integer>
    </dict>
    <key>FTP Access</key>
    <dict>
      <key>proc</key>
      <string>ftpd</string>
      <key>state</key>
      <integer>0</integer>
    </dict>
    <key>ODSAgent</key>
    <dict>
      <key>proc</key>
      <string>ODSAgent</string>
      <key>servicebundleid</key>
      <string>com.apple.ODSAgent</string>
      <key>state</key>
      <integer>0</integer>
    </dict>
    <key>Personal File Sharing</key>
    <dict>
      <key>proc</key>
      <string>AppleFileServer</string>
      <key>state</key>
      <integer>0</integer>
    </dict>
    <key>Personal Web Sharing</key>
    <dict>
      <key>proc</key>
      <string>httpd</string>
      <key>state</key>
      <integer>0</integer>
    </dict>
    <key>Printer Sharing</key>
    <dict>
      <key>proc</key>
      <string>cupsd</string>
      <key>state</key>
      <integer>0</integer>
    </dict>
    <key>Remote Apple Events</key>
    <dict>
      <key>proc</key>
      <string>AEServer</string>
      <key>state</key>
      <integer>0</integer>
    </dict>
    <key>Remote Login - SSH</key>
    <dict>
      <key>proc</key>
      <string>sshd-keygen-wrapper</string>
      <key>state</key>
      <integer>0</integer>
    </dict>
    <key>Samba Sharing</key>
    <dict>
      <key>proc</key>
      <string>smbd</string>
      <key>state</key>
      <integer>0</integer>
    </dict>
  </dict>
  <key>firewallunload</key>
  <integer>0</integer>
  <key>globalstate</key>
  <integer>0</integer>
  <key>loggingenabled</key>
  <integer>0</integer>
  <key>loggingoption</key>
  <integer>0</integer>
  <key>stealthenabled</key>
  <integer>0</integer>
  <key>version</key>
  <string>1.0a25</string>
</dict>
</plist>
)";
  return content;
}

pt::ptree getALFTree() {
  auto content = getALFContent();
  pt::ptree tree;
  fs::parsePlistContent(content, tree);
  return tree;
}

std::string getInfoPlistContent() {
  std::string content = R"(
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>BuildMachineOSBuild</key>
  <string>13C23</string>
  <key>CFBundleDevelopmentRegion</key>
  <string>English</string>
  <key>CFBundleDocumentTypes</key>
  <array>
    <dict>
      <key>CFBundleTypeExtensions</key>
      <array>
        <string>Photo Booth</string>
      </array>
      <key>CFBundleTypeIconFile</key>
      <string>PBLibraryIcon</string>
      <key>CFBundleTypeName</key>
      <string>Photo Booth Library</string>
      <key>CFBundleTypeOSTypes</key>
      <array>
        <string>PBLb</string>
      </array>
      <key>CFBundleTypeRole</key>
      <string>Viewer</string>
      <key>LSTypeIsPackage</key>
      <true/>
      <key>NSDocumentClass</key>
      <string>ArchiveDocument</string>
    </dict>
  </array>
  <key>CFBundleExecutable</key>
  <string>Photo Booth</string>
  <key>CFBundleHelpBookFolder</key>
  <string>PhotoBooth.help</string>
  <key>CFBundleHelpBookName</key>
  <string>com.apple.PhotoBooth.help</string>
  <key>CFBundleIconFile</key>
  <string>PhotoBooth.icns</string>
  <key>CFBundleIdentifier</key>
  <string>com.apple.PhotoBooth</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>6.0</string>
  <key>CFBundleSignature</key>
  <string>PhBo</string>
  <key>CFBundleVersion</key>
  <string>517</string>
  <key>DTCompiler</key>
  <string>com.apple.compilers.llvm.clang.1_0</string>
  <key>DTPlatformBuild</key>
  <string>5A2053</string>
  <key>DTPlatformVersion</key>
  <string>GM</string>
  <key>DTSDKBuild</key>
  <string>13C23</string>
  <key>DTSDKName</key>
  <string></string>
  <key>DTXcode</key>
  <string>0501</string>
  <key>DTXcodeBuild</key>
  <string>5A2053</string>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.entertainment</string>
  <key>LSMinimumSystemVersion</key>
  <string>10.7.0</string>
  <key>NSMainNibFile</key>
  <string>MainMenu</string>
  <key>NSPrincipalClass</key>
  <string>PBApplication</string>
  <key>NSSupportsAutomaticGraphicsSwitching</key>
  <true/>
  <key>NSSupportsSuddenTermination</key>
  <string>YES</string>
</dict>
</plist>
)";
  return content;
}

pt::ptree getInfoPlistTree() {
  auto content = getInfoPlistContent();
  pt::ptree tree;
  fs::parsePlistContent(content, tree);
  return tree;
}
}
}
