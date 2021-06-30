/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <boost/optional.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/expected/expected.h>

#include <unordered_map>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

namespace tables {

/// One of the possible Chrome-based browser names
enum class ChromeBrowserType {
  GoogleChrome,
  Brave,
  Chromium,
  Yandex,
  Opera,
  Edge,
  EdgeBeta
};

/// Converts the browser type to a printable string
const std::string& getChromeBrowserName(const ChromeBrowserType& type);

/// A snapshot of all the important files inside a chrome profile
struct ChromeProfileSnapshot final {
  /// A single extension found inside the profile
  struct Extension final {
    /// The absolute path to the extension folder
    std::string path;

    /// The contents of the manifest file
    std::string manifest;
  };

  /// A map of extensions where the key identifies the (relative) path
  using ExtensionMap = std::unordered_map<std::string, Extension>;

  /// Profile type
  ChromeBrowserType type{ChromeBrowserType::GoogleChrome};

  /// Absolute path to this profile
  std::string path;

  /// The contents of the 'Preferences' file
  std::string preferences;

  /// The contents of the 'Secure Preferences' file
  std::string secure_preferences;

  /// The user id
  std::int64_t uid{};

  /// A map of all the extensions discovered in the preferences
  ExtensionMap referenced_extensions;

  /// A map of all the extensions that are not present in the preferences
  ExtensionMap unreferenced_extensions;
};

/// A list of chrome profile snapshots
using ChromeProfileSnapshotList = std::vector<ChromeProfileSnapshot>;

/// A js -> match pair from the content_scripts manifest entry
struct ContentScriptsEntry final {
  /// The target script
  std::string script;

  /// The match entry
  std::string match;
};

/// A list of content_scripts entries
using ContentScriptsEntryList = std::vector<ContentScriptsEntry>;

/// A Chrome profile
struct ChromeProfile final {
  /// A single Chrome extension
  struct Extension final {
    /// A key/value list of properties
    using Properties = std::unordered_map<std::string, std::string>;

    /// Absolute path to the extension folder
    std::string path;

    /// True if this extension is referenced by the profile
    bool referenced{false};

    /// Additional settings, only present if this extension
    /// is referenced by the Preferences file
    Properties profile_settings;

    /// Extension properties, taken from the manifest file
    Properties properties;

    /// The full JSON manifest, on a single line
    std::string manifest_json;

    /// The SHA256 hash of the manifest file
    std::string manifest_hash;

    /// The 'matches' entries inside 'content_scripts'
    ContentScriptsEntryList content_scripts_matches;

    /// The extension id, computed from the 'key' property
    boost::optional<std::string> opt_computed_identifier;
  };

  /// A list of extensions
  using ExtensionList = std::vector<Extension>;

  /// Profile type
  ChromeBrowserType type{ChromeBrowserType::GoogleChrome};

  /// Absolute path to this profile
  std::string path;

  /// The profile name
  std::string name;

  /// The user id
  std::int64_t uid{};

  /// A list of extensions associated with this profile
  ExtensionList extension_list;
};

/// A list of Chrome profiles
using ChromeProfileList = std::vector<ChromeProfile>;

/// Returns the list of 'matches' entries inside the 'content_scripts' array
ContentScriptsEntryList getExtensionContentScriptsMatches(
    const pt::iptree& parsed_manifest);

/// Returns a list of Chrome profiles from the given snapshot
ChromeProfileList getChromeProfilesFromSnapshotList(
    const ChromeProfileSnapshotList& snapshot_list);

/// Returns the profile name from the given parsed preferences
Status getProfileNameFromPreferences(std::string& name,
                                     const pt::iptree& parsed_preferences);

/// Captures the extension properties from the given parsed manifest
Status getExtensionProperties(ChromeProfile::Extension::Properties& properties,
                              const pt::iptree& parsed_manifest);

/// Returns a list of all profiles for Chrome-based browsers
ChromeProfileList getChromeProfiles(const QueryContext& context);

/// Returns the extension's profile settings
Status getExtensionProfileSettings(
    ChromeProfile::Extension::Properties& profile_settings,
    const pt::iptree& parsed_preferences,
    const std::string& extension_path,
    const std::string& profile_path);

/// Parses the given snapshot to create an extension object
Status getExtensionFromSnapshot(
    ChromeProfile::Extension& extension,
    const ChromeProfileSnapshot::Extension& snapshot);

/// Retrieves the localized version of the given string
Status getStringLocalization(std::string& localized_string,
                             const pt::iptree& parsed_localization,
                             const std::string string);

/// Returns the specified extension property
std::string getExtensionProperty(
    const ChromeProfile::Extension& extension,
    const std::string& property_name,
    bool optional,
    const std::string& default_value = std::string());

/// Returns the specified extension profile setting
std::string getExtensionProfileSettingsValue(
    const ChromeProfile::Extension& extension,
    const std::string& property_name);

using ExpectedUnixTimestamp = Expected<std::int64_t, ConversionError>;

/// Converts a timestamp from Webkit to Unix format
ExpectedUnixTimestamp webkitTimeToUnixTimestamp(const std::string& timestamp);

enum class ExtensionKeyError {
  MissingProperty,
  InvalidValue,
  HashingError,
  TransformationError,
};

using ExpectedExtensionKey = Expected<std::string, ExtensionKeyError>;

/// Computes the extension id based on the given key
ExpectedExtensionKey computeExtensionIdentifier(
    const ChromeProfile::Extension& extension);

} // namespace tables

} // namespace osquery
