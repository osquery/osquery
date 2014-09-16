// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core/darwin/test_util.h"

#include <boost/property_tree/json_parser.hpp>

using namespace osquery::db;
namespace pt = boost::property_tree;

namespace osquery {
namespace core {

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
  parsePlistContent(content, tree);
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

std::string getLaunchdContent() {
  std::string content = R"(
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.apple.mDNSResponder</string>
  <key>OnDemand</key>
  <false/>
  <key>InitGroups</key>
  <false/>
  <key>UserName</key>
  <string>_mdnsresponder</string>
  <key>GroupName</key>
  <string>_mdnsresponder</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/sbin/mDNSResponder</string>
  </array>
  <key>MachServices</key>
  <dict>
    <key>com.apple.mDNSResponder</key>
    <true/>
               <key>com.apple.mDNSResponder.dnsproxy</key>
               <true/>
  </dict>
  <key>Sockets</key>
  <dict>
    <key>Listeners</key>
    <dict>
      <key>SockFamily</key>
      <string>Unix</string>
      <key>SockPathName</key>
      <string>/var/run/mDNSResponder</string>
      <key>SockPathMode</key>
      <integer>438</integer>
    </dict>
  </dict>
  <key>EnableTransactions</key>
  <true/>
  <key>BeginTransactionAtShutdown</key>
  <true/>
  <key>POSIXSpawnType</key>
  <string>Interactive</string>
</dict>
</plist>
)";
  return content;
}

pt::ptree getInfoPlistTree() {
  auto content = getInfoPlistContent();
  pt::ptree tree;
  parsePlistContent(content, tree);
  return tree;
}

pt::ptree getLaunchdTree() {
  auto content = getLaunchdContent();
  pt::ptree tree;
  parsePlistContent(content, tree);
  return tree;
}
}
}
