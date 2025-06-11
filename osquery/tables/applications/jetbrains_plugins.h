/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

namespace osquery {
namespace tables {
enum class JetBrainsProductType {
  CLion,
  DataGrip,
  GoLand,
  IntelliJIdea,
  IntelliJIdeaCommunityEdition,
  PhpStorm,
  PyCharm,
  PyCharmCommunityEdition,
  ReSharper,
  Rider,
  RubyMine,
  RustRover,
  WebStorm
};

using ProductPathMap =
    std::vector<std::tuple<JetBrainsProductType, std::string>>;

const ProductPathMap kWindowsPathList = {
    {JetBrainsProductType::CLion,
     "AppData\\Roaming\\JetBrains\\CLion%\\plugins"},
    {JetBrainsProductType::DataGrip,
     "AppData\\Roaming\\JetBrains\\DataGrip%\\plugins"},
    {JetBrainsProductType::GoLand,
     "AppData\\Roaming\\JetBrains\\GoLand%\\plugins"},
    {JetBrainsProductType::IntelliJIdea,
     "AppData\\Roaming\\JetBrains\\IntelliJIdea%\\plugins"},
    {JetBrainsProductType::IntelliJIdeaCommunityEdition,
     "AppData\\Roaming\\JetBrains\\IdeaIC%\\plugins"},
    {JetBrainsProductType::PhpStorm,
     "AppData\\Roaming\\JetBrains\\PhpStorm%\\plugins"},
    {JetBrainsProductType::PyCharm,
     "AppData\\Roaming\\JetBrains\\PyCharm%\\plugins"},
    {JetBrainsProductType::PyCharmCommunityEdition,
     "AppData\\Roaming\\JetBrains\\PyCharmCE%\\plugins"},
    {JetBrainsProductType::ReSharper,
     "AppData\\Roaming\\JetBrains\\ReSharper%\\plugins"},
    {JetBrainsProductType::Rider,
     "AppData\\Roaming\\JetBrains\\Rider%\\plugins"},
    {JetBrainsProductType::RubyMine,
     "AppData\\Roaming\\JetBrains\\RubyMine%\\plugins"},
    {JetBrainsProductType::RustRover,
     "AppData\\Roaming\\JetBrains\\RustRover%\\plugins"},
    {JetBrainsProductType::WebStorm,
     "AppData\\Roaming\\JetBrains\\WebStorm%\\plugins"}};

const ProductPathMap kMacOsPathList = {
    {JetBrainsProductType::CLion,
     "Library/Application Support/JetBrains/CLion%/plugins"},
    {JetBrainsProductType::DataGrip,
     "Library/Application Support/JetBrains/DataGrip%/plugins"},
    {JetBrainsProductType::GoLand,
     "Library/Application Support/JetBrains/GoLand%/plugins"},
    {JetBrainsProductType::IntelliJIdea,
     "Library/Application Support/JetBrains/IntelliJIdea%/plugins"},
    {JetBrainsProductType::IntelliJIdeaCommunityEdition,
     "Library/Application Support/JetBrains/IdeaIC%/plugins"},
    {JetBrainsProductType::PhpStorm,
     "Library/Application Support/JetBrains/PhpStorm%/plugins"},
    {JetBrainsProductType::PyCharm,
     "Library/Application Support/JetBrains/PyCharm%/plugins"},
    {JetBrainsProductType::PyCharmCommunityEdition,
     "Library/Application Support/JetBrains/PyCharmCE%/plugins"},
    {JetBrainsProductType::ReSharper,
     "Library/Application Support/JetBrains/ReSharper%/plugins"},
    {JetBrainsProductType::Rider,
     "Library/Application Support/JetBrains/Rider%/plugins"},
    {JetBrainsProductType::RubyMine,
     "Library/Application Support/JetBrains/RubyMine%/plugins"},
    {JetBrainsProductType::RustRover,
     "Library/Application Support/JetBrains/RustRover%/plugins"},
    {JetBrainsProductType::WebStorm,
     "Library/Application Support/JetBrains/WebStorm%/plugins"}};

const ProductPathMap kLinuxPathList = {
    {JetBrainsProductType::CLion, ".local/share/JetBrains/CLion%"},
    {JetBrainsProductType::DataGrip, ".local/share/JetBrains/DataGrip%"},
    {JetBrainsProductType::GoLand, ".local/share/JetBrains/GoLand%"},
    {JetBrainsProductType::IntelliJIdea,
     ".local/share/JetBrains/IntelliJIdea%"},
    {JetBrainsProductType::IntelliJIdeaCommunityEdition,
     ".local/share/JetBrains/IdeaIC%"},
    {JetBrainsProductType::PhpStorm, ".local/share/JetBrains/PhpStorm%"},
    {JetBrainsProductType::PyCharm, ".local/share/JetBrains/PyCharm%"},
    {JetBrainsProductType::PyCharmCommunityEdition,
     ".local/share/JetBrains/PyCharmCE%"},
    {JetBrainsProductType::ReSharper, ".local/share/JetBrains/ReSharper%"},
    {JetBrainsProductType::Rider, ".local/share/JetBrains/Rider%"},
    {JetBrainsProductType::RubyMine, ".local/share/JetBrains/RubyMine%"},
    {JetBrainsProductType::RustRover, ".local/share/JetBrains/RustRover%"},
    {JetBrainsProductType::WebStorm, ".local/share/JetBrains/WebStorm%"}};

const std::unordered_map<JetBrainsProductType, std::string>
    kProductTypeToString = {
        {JetBrainsProductType::CLion, "clion"},
        {JetBrainsProductType::DataGrip, "datagrip"},
        {JetBrainsProductType::GoLand, "goland"},
        {JetBrainsProductType::IntelliJIdea, "intellij_idea"},
        {JetBrainsProductType::IntelliJIdeaCommunityEdition,
         "intellij_idea_community_edition"},
        {JetBrainsProductType::PhpStorm, "phpstorm"},
        {JetBrainsProductType::PyCharm, "pycharm"},
        {JetBrainsProductType::PyCharmCommunityEdition,
         "pycharm_community_edition"},
        {JetBrainsProductType::ReSharper, "resharper"},
        {JetBrainsProductType::Rider, "rider"},
        {JetBrainsProductType::RubyMine, "rubymine"},
        {JetBrainsProductType::RustRover, "rust_rov"},
        {JetBrainsProductType::WebStorm, "webstorm"}};

const std::string getProductName(const JetBrainsProductType type);
void putMoreLikelyPluginJarsFirst(
    const std::string& plugin_dir_name,
    std::vector<std::string>& files_in_lib_under_plugin_dir);
bool fileNameIsLikeVersionedLibraryName(const std::string& name);
} // namespace tables
} // namespace osquery
