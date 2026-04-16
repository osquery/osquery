/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#include <windows.h>

#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/core/windows/ntapi.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/windows/token_privileges.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/windows/strings.h>

// Link against ntdll.lib directly to access NT Native API functions
// (NtQueryObject, NtQuerySystemInformation, NtDuplicateObject, etc.)
// that are not exposed through standard Win32 headers
#pragma comment(lib, "ntdll.lib")

namespace osquery {

HIDDEN_FLAG(bool,
            allow_handle_threads,
            true,
            "Disable using blockable threads in process_open_handles"
            " when the system handle information query fails");

namespace tables {

namespace handles {

constexpr size_t INITIAL_ENUMERATION_BUFFER_SIZE = 1024 * 1024 * 4; // 4 MBs
constexpr size_t MAXIMUM_ENUMERATION_BUFFER_SIZE = 1024 * 1024 * 1024; // 1GB

#ifndef MemoryMappedFilenameInformation
#define MemoryMappedFilenameInformation 2
#endif

#ifndef THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002
#endif

// Alignment helpers for walking the serialized buffer returned by
// NtQueryObject(ObjectAllTypesInformation).  Each OBJECT_TYPE_INFORMATION
// entry is followed by its TypeName string data, and the next entry starts
// at the next pointer-aligned boundary after that string.
constexpr size_t AlignUp(size_t value, size_t align) {
  return (value + (align - 1)) & ~(align - 1);
}

constexpr size_t AlignUpPtr(size_t value) {
  return AlignUp(value, sizeof(void*));
}

// NT Native API structures for handle enumeration and object type queries.
// These are not part of the public Windows SDK
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
  PVOID Object;
  ULONG_PTR UniqueProcessId;
  ULONG_PTR HandleValue;
  ULONG GrantedAccess;
  USHORT CreatorBackTraceIndex;
  USHORT ObjectTypeIndex;
  ULONG HandleAttributes;
  ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
  ULONG_PTR NumberOfHandles;
  ULONG_PTR Reserved;
  SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _OBJECT_BASIC_INFORMATION {
  ULONG Attributes;
  ACCESS_MASK GrantedAccess;
  ULONG HandleCount;
  ULONG PointerCount;
  ULONG PagedPoolCharge;
  ULONG NonPagedPoolCharge;
  ULONG Reserved[3];
  ULONG NameInfoSize;
  ULONG TypeInfoSize;
  ULONG SecurityDescriptorSize;
  LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
  UNICODE_STRING TypeName;
  ULONG TotalNumberOfObjects;
  ULONG TotalNumberOfHandles;
  ULONG TotalPagedPoolUsage;
  ULONG TotalNonPagedPoolUsage;
  ULONG TotalNamePoolUsage;
  ULONG TotalHandleTableUsage;
  ULONG HighWaterNumberOfObjects;
  ULONG HighWaterNumberOfHandles;
  ULONG HighWaterPagedPoolUsage;
  ULONG HighWaterNonPagedPoolUsage;
  ULONG HighWaterNamePoolUsage;
  ULONG HighWaterHandleTableUsage;
  ULONG InvalidAttributes;
  GENERIC_MAPPING GenericMapping;
  ULONG ValidAccessMask;
  BOOLEAN SecurityRequired;
  BOOLEAN MaintainHandleCount;
  UCHAR TypeIndex; // Available > Win8, Empty otherwise
  CHAR ReservedByte;
  ULONG PoolType;
  ULONG DefaultPagedPoolCharge;
  ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_TYPES_INFORMATION {
  ULONG NumberOfTypes;
  OBJECT_TYPE_INFORMATION Types[1];
} OBJECT_ALL_TYPES_INFORMATION, *POBJECT_ALL_TYPES_INFORMATION;

// Avoid dynamic allocation for name buffer by using a buffer that
// can contain the largest possible UNICODE_STRING.
typedef struct _OBJECT_TYPE_INFORMATION_WITH_STORAGE {
  OBJECT_TYPE_INFORMATION TypeInfo;
  BYTE Storage[USHRT_MAX];
} OBJECT_TYPE_INFORMATION_WITH_STORAGE, *POBJECT_TYPE_INFORMATION_WITH_STORAGE;

// Avoid dynamic allocation for name buffer by using a buffer that
// can contain the largest possible UNICODE_STRING.
typedef struct _OBJECT_NAME_BUFFER_WITH_STORAGE {
  UNICODE_STRING usName;
  BYTE Storage[USHRT_MAX];
} OBJECT_NAME_BUFFER_WITH_STORAGE, *POBJECT_NAME_BUFFER_WITH_STORAGE;

typedef struct _QUERY_OBJECT_NAME_PARAMS {
  HANDLE hObject;
  OBJECT_NAME_BUFFER_WITH_STORAGE nameBuffer;
  NTSTATUS ntStatus;
} QUERY_OBJECT_NAME_PARAMS, *PQUERY_OBJECT_NAME_PARAMS;

// NT Native API function declarations.  These are exported by ntdll.dll but
// are not declared in standard Windows SDK headers.  We declare them with
// extern "C" linkage and link against ntdll.lib (see #pragma above).
extern "C" NTSTATUS NTAPI NtDuplicateObject(HANDLE SourceProcessHandle,
                                            HANDLE SourceHandle,
                                            HANDLE TargetProcessHandle,
                                            PHANDLE TargetHandle,
                                            ACCESS_MASK DesiredAccess,
                                            ULONG HandleAttributes,
                                            ULONG Options);

extern "C" LONG NTAPI RtlCompareUnicodeString(PCUNICODE_STRING String1,
                                              PCUNICODE_STRING String2,
                                              BOOLEAN CaseInSensitive);

extern "C" NTSTATUS NTAPI
RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);

extern "C" NTSTATUS NTAPI NtCreateThreadEx(PHANDLE ThreadHandle,
                                           ACCESS_MASK DesiredAccess,
                                           PVOID ObjectAttributes,
                                           HANDLE ProcessHandle,
                                           PVOID StartRoutine,
                                           PVOID Argument,
                                           ULONG CreateFlags,
                                           SIZE_T ZeroBits,
                                           SIZE_T StackSize,
                                           SIZE_T MaximumStackSize,
                                           PVOID AttributeList);

extern "C" NTSTATUS NTAPI NtCreateSection(PHANDLE SectionHandle,
                                          ACCESS_MASK DesiredAccess,
                                          PVOID ObjectAttributes,
                                          PLARGE_INTEGER MaximumSize,
                                          ULONG SectionPageProtection,
                                          ULONG AllocationAttributes,
                                          HANDLE FileHandle);

extern "C" NTSTATUS NTAPI NtMapViewOfSection(HANDLE SectionHandle,
                                             HANDLE ProcessHandle,
                                             PVOID* BaseAddress,
                                             ULONG_PTR ZeroBits,
                                             SIZE_T CommitSize,
                                             PLARGE_INTEGER SectionOffset,
                                             PSIZE_T ViewSize,
                                             ULONG InheritDisposition,
                                             ULONG AllocationType,
                                             ULONG Win32Protect);

extern "C" NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE ProcessHandle,
                                               PVOID BaseAddress);

extern "C" NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE ProcessHandle,
                                               PVOID BaseAddress,
                                               ULONG MemoryInformationClass,
                                               PVOID MemoryInformation,
                                               SIZE_T MemoryInformationLength,
                                               PSIZE_T ReturnLength);

enum class ErrorStage {
  None = 0,
  ProcessOpening = 1,
  HandleDuplication = 2,
  ObjectBasicInfoQuerying = 3,
  ObjectTypeInfoQuerying = 4,
  ObjectNameQuerying = 5,
  ObjectNameMapping = 6
};

enum class MappingTechniqueResult { Success, FailedInvalidHandle, FailedOther };

std::string_view ErrorStageString(ErrorStage stage) {
  switch (stage) {
  case ErrorStage::None:
    return "";
  case ErrorStage::ProcessOpening:
    return "ProcessOpening";
  case ErrorStage::HandleDuplication:
    return "HandleDuplication";
  case ErrorStage::ObjectBasicInfoQuerying:
    return "ObjectBasicInfoQuerying";
  case ErrorStage::ObjectTypeInfoQuerying:
    return "ObjectTypeInfoQuerying";
  case ErrorStage::ObjectNameQuerying:
    return "ObjectNameQuerying";
  case ErrorStage::ObjectNameMapping:
    return "ObjectNameMapping";
  default:
    return "Unknown";
  }
}

namespace mappings {
struct MappedValue {
  unsigned long mask;
  std::string_view name;
};

constexpr MappedValue Generic[] = {{GENERIC_READ, "GENERIC_READ"},
                                   {GENERIC_WRITE, "GENERIC_WRITE"},
                                   {GENERIC_EXECUTE, "GENERIC_EXECUTE"},
                                   {GENERIC_ALL, "GENERIC_ALL"}};

constexpr MappedValue Standard[] = {{DELETE, "DELETE"},
                                    {READ_CONTROL, "READ_CONTROL"},
                                    {WRITE_DAC, "WRITE_DAC"},
                                    {WRITE_OWNER, "WRITE_OWNER"},
                                    {SYNCHRONIZE, "SYNCHRONIZE"}};

constexpr MappedValue File[] = {{FILE_READ_DATA, "READ_DATA"},
                                {FILE_WRITE_DATA, "WRITE_DATA"},
                                {FILE_APPEND_DATA, "APPEND_DATA"},
                                {FILE_READ_EA, "READ_EA"},
                                {FILE_WRITE_EA, "WRITE_EA"},
                                {FILE_EXECUTE, "EXECUTE"},
                                {FILE_READ_ATTRIBUTES, "READ_ATTRIBUTES"},
                                {FILE_WRITE_ATTRIBUTES, "WRITE_ATTRIBUTES"}};

constexpr MappedValue Directory[] = {
    {FILE_READ_DATA, "LIST_DIRECTORY"},
    {FILE_WRITE_DATA, "ADD_FILE"},
    {FILE_APPEND_DATA, "ADD_SUBDIRECTORY"},
    {FILE_READ_EA, "READ_EA"},
    {FILE_WRITE_EA, "WRITE_EA"},
    {FILE_EXECUTE, "TRAVERSE"},
    {FILE_READ_ATTRIBUTES, "READ_ATTRIBUTES"},
    {FILE_WRITE_ATTRIBUTES, "WRITE_ATTRIBUTES"}};

constexpr MappedValue Key[] = {{KEY_QUERY_VALUE, "QUERY_VALUE"},
                               {KEY_SET_VALUE, "SET_VALUE"},
                               {KEY_CREATE_SUB_KEY, "CREATE_SUB_KEY"},
                               {KEY_ENUMERATE_SUB_KEYS, "ENUMERATE_SUB_KEYS"},
                               {KEY_NOTIFY, "NOTIFY"},
                               {KEY_CREATE_LINK, "CREATE_LINK"}};

constexpr MappedValue Attributes[] = {
    {OBJ_INHERIT, "INHERIT"},
    {OBJ_PERMANENT, "PERMANENT"},
    {OBJ_EXCLUSIVE, "EXCLUSIVE"},
    {OBJ_CASE_INSENSITIVE, "CASE_INSENSITIVE"},
    {OBJ_OPENIF, "OPENIF"},
    {OBJ_OPENLINK, "OPENLINK"},
    {OBJ_KERNEL_HANDLE, "KERNEL_HANDLE"},
    {OBJ_FORCE_ACCESS_CHECK, "FORCE_ACCESS_CHECK"},
    {OBJ_IGNORE_IMPERSONATED_DEVICEMAP, "IGNORE_IMPERSONATED_DEVICEMAP"},
    {OBJ_DONT_REPARSE, "DONT_REPARSE"}};
} // namespace mappings

struct KeyHash {
  size_t operator()(const std::pair<ULONG, std::string>& key) const {
    return std::hash<ULONG>()(key.first) ^ std::hash<std::string>()(key.second);
  }
};
using GrantedAccessCache =
    std::unordered_map<std::pair<ULONG, std::string>, std::string, KeyHash>;
using HandleAttributesCache = std::unordered_map<ULONG, std::string>;
using ObjectNameCache = std::unordered_map<std::wstring, std::string>;
using HandleTypeMap = std::unordered_map<ULONG, std::string>;

// Cache for handle enumeration that allows us to avoid expensive operations
// like string conversions and access mask decoding when possible.  During
// enumeration we could possibly encounter larger numbers of handles, and would
// have serious performance issues if we did did not have this cache in place.
//
class HandleRecordCache {
 private:
  GrantedAccessCache m_grantedAccessCache;
  HandleAttributesCache m_handleAttributesCache;
  ObjectNameCache m_objectNameCache;
  HandleTypeMap m_handleTypeMap;

  std::wstring FromPUnicodeString(PUNICODE_STRING us) {
    if (!us || !us->Buffer || us->Length == 0) {
      return L"";
    }
    if (us->Length > us->MaximumLength) {
      return L"";
    }
    return std::wstring(us->Buffer, us->Length / sizeof(WCHAR));
  }

 public:
  HandleRecordCache() = default;

  // ObjectName comes in as a unicode string, but we will cache
  // it as an std::string for use in our final output.  The function
  // is overloaded to allow callers to pass in either a PUNICODE_STRING
  // (default) or a std::wstring in cases where we are storing special sentinel
  // values like "Unknown" for objects we failed to query the name of.
  //
  const std::string* GetObjectName(PUNICODE_STRING us) {
    return GetObjectName(FromPUnicodeString(us));
  }

  const std::string* GetObjectName(const std::wstring& lookup) {
    if (lookup.empty()) {
      return nullptr;
    }

    auto it = m_objectNameCache.find(lookup);
    if (it != m_objectNameCache.end()) {
      // Found!
      return &(it->second);
    }

    std::string converted = wstringToString(lookup.c_str());
    auto [insertIt, _] =
        m_objectNameCache.try_emplace(std::move(lookup), std::move(converted));
    return &(insertIt->second);
  }

  // During Enumeration we collect granted access as a raw mask, but we want to
  // convert it to a string for our final output.  This function is used to
  // cache the results of that conversion.  We are returning the result as an
  // std::string instead of a pointer because this function is only called at
  // row generation time, and will be copied regardless
  //
  const std::string& GetGrantedAccessString(ULONG grantedAccess,
                                            const std::string& type) {
    auto it = m_grantedAccessCache.find({grantedAccess, type});
    if (it != m_grantedAccessCache.end()) {
      return it->second;
    }

    std::vector<std::string> rights;
    auto check_mask = [&](const mappings::MappedValue& mapping) {
      if (grantedAccess & mapping.mask)
        rights.emplace_back(mapping.name.data(), mapping.name.size());
    };

    // Handle Generic Rights
    for (const auto& mapping : mappings::Generic) {
      check_mask(mapping);
    }

    // Handle Standard Rights (Common to most objects)
    for (const auto& mapping : mappings::Standard) {
      check_mask(mapping);
    }

    // Handle Type-Specific Rights
    if (type == "File") {
      for (const auto& mapping : mappings::File) {
        check_mask(mapping);
      }
    } else if (type == "Directory") {
      for (const auto& mapping : mappings::Directory) {
        check_mask(mapping);
      }
    } else if (type == "Key") {
      for (const auto& mapping : mappings::Key) {
        check_mask(mapping);
      }
    }

    // Combine results
    if (rights.empty()) {
      std::string noAccess = "NO_ACCESS";
      auto emplace_result = m_grantedAccessCache.try_emplace(
          {grantedAccess, type}, std::move(noAccess));
      return emplace_result.first->second;
    }

    std::string accessRights = osquery::join(rights, "|");

    auto emplace_result = m_grantedAccessCache.try_emplace(
        {grantedAccess, type}, std::move(accessRights));
    return emplace_result.first->second;
  }

  // Similar to GetGrantedAccessString, we want to cache the results of
  // decoding handle attributes for use in our final output.
  //
  std::string& GetHandleAttributesString(ULONG handleAttributes) {
    auto it = m_handleAttributesCache.find(handleAttributes);
    if (it != m_handleAttributesCache.end()) {
      return it->second;
    }
    std::vector<std::string> attributes;
    auto check_mask = [&](const mappings::MappedValue& mapping) {
      if (handleAttributes & mapping.mask)
        attributes.emplace_back(mapping.name.data(), mapping.name.size());
    };
    for (const auto& mapping : mappings::Attributes) {
      check_mask(mapping);
    }

    if (attributes.empty()) {
      std::string emptyString = "";
      auto emplace_result = m_handleAttributesCache.try_emplace(
          handleAttributes, std::move(emptyString));
      return emplace_result.first->second;
    }

    std::string attributesStr = osquery::join(attributes, ",");
    auto emplace_result = m_handleAttributesCache.try_emplace(
        handleAttributes, std::move(attributesStr));
    return emplace_result.first->second;
  }

  void CacheHandleType(ULONG typeIndex, const std::wstring& typeName) {
    auto it = m_handleTypeMap.find(typeIndex);
    if (it != m_handleTypeMap.end()) {
      return;
    }
    m_handleTypeMap[typeIndex] = wstringToString(typeName.c_str());
  }

  void CacheHandleType(ULONG typeIndex, PUNICODE_STRING typeName) {
    auto it = m_handleTypeMap.find(typeIndex);
    if (it != m_handleTypeMap.end()) {
      return;
    }
    CacheHandleType(typeIndex, FromPUnicodeString(typeName));
  }

  std::string* GetCachedHandleType(ULONG typeIndex) {
    auto it = m_handleTypeMap.find(typeIndex);
    if (it != m_handleTypeMap.end()) {
      return &it->second;
    }
    return nullptr;
  }
};

// Represents a single handle record for enumeration and eventual conversion to
// a Row for output. This class also contains an error state that allows us to
// capture and log errors that occur during enumeration while still returning
// partial results for handles that we were able to query successfully.
//
class HandleRecord {
 private:
  // the stage at which an error occurred for this handle, if any
  ErrorStage m_errorStage{ErrorStage::None};
  // the error code resulting from the error, if any
  DWORD m_errorStatus{0};
  // the granted access mask for the handle
  ULONG m_GrantedAccess = 0;
  // the handle attributes
  ULONG m_HandleAttributes = 0;
  // the raw pointer count
  ULONG m_RawPointerCount = 0;
  // the handle count
  ULONG m_HandleCount = 0;
  // the name of the object, if available
  const std::string* m_ObjectName{nullptr};
  // the process ID associated with the handle
  DWORD m_ProcessId = 0;
  // reference to the handle record cache
  HandleRecordCache& m_cache;
  // the handle value
  HANDLE m_HandleValue = 0;
  // the object type index
  USHORT m_ObjectTypeIndex = 0;

 public:
  HandleRecord(PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry,
               HandleRecordCache& cache)
      : m_cache(cache) {
    m_ProcessId = static_cast<DWORD>(entry->UniqueProcessId);
    m_HandleValue = reinterpret_cast<HANDLE>(entry->HandleValue);
    m_GrantedAccess = entry->GrantedAccess;
    m_ObjectTypeIndex = entry->ObjectTypeIndex;
    m_HandleAttributes = entry->HandleAttributes;
  }

  // Setters and Getters optimized to use the cache where possible for
  // string conversions and lookups

  HANDLE Handle() const {
    return m_HandleValue;
  }

  USHORT TypeIndex() const {
    return m_ObjectTypeIndex;
  }

  DWORD Pid() const {
    return m_ProcessId;
  }

  void SetObjectName(PUNICODE_STRING objectName) {
    m_ObjectName = m_cache.GetObjectName(objectName);
  }
  void SetObjectName(const std::wstring& objectName) {
    m_ObjectName = m_cache.GetObjectName(objectName);
  }

  void SetObjectTypeName(PUNICODE_STRING objectTypeName) {
    m_cache.CacheHandleType(m_ObjectTypeIndex, objectTypeName);
  }

  void SetGrantedAccess(ULONG grantedAccess) {
    m_GrantedAccess = grantedAccess;
  }

  void SetHandleAttributes(ULONG handleAttributes) {
    m_HandleAttributes = handleAttributes;
  }

  void SetRawPointerCount(ULONG rawPointerCount) {
    m_RawPointerCount = rawPointerCount;
  }

  void SetHandleCount(ULONG handleCount) {
    m_HandleCount = handleCount;
  }

  const std::string& Type() {
    // If we don't have a valid type, attempt to look it up in the cache using
    // the ObjectTypeIndex. If we find a match, cache it and return it
    std::string* typeName = m_cache.GetCachedHandleType(m_ObjectTypeIndex);
    if (typeName) {
      return *typeName;
    }
    static std::string unknown = "Unknown";
    return unknown;
  }

  const std::string& Access() {
    return m_cache.GetGrantedAccessString(m_GrantedAccess, Type());
  }

  const std::string& Attributes() {
    return m_cache.GetHandleAttributesString(m_HandleAttributes);
  }

  const std::string& Name() {
    static std::string emptyString = "";
    return m_ObjectName ? *m_ObjectName : emptyString;
  }

  ULONG RawPointerCount() const {
    return m_RawPointerCount;
  }

  ULONG HandleCount() const {
    return m_HandleCount;
  }

  void SetError(ErrorStage errorStage,
                DWORD errorStatus,
                bool logError = false) {
    m_errorStage = errorStage;
    m_errorStatus = errorStatus;

    if (!logError) {
      return;
    }
    VLOG(1) << "Error during handle enumeration. "
            << ErrorStageString(errorStage) << " Pid: " << m_ProcessId
            << " Error Code: " << m_errorStatus << " Handle 0x" << std::hex
            << m_HandleValue << std::dec;
  }

  ErrorStage GetErrorStage() const {
    return m_errorStage;
  }

  DWORD GetErrorCode() const {
    return m_errorStatus;
  }

  Row ToRow() {
    Row row;
    row["pid"] = INTEGER(Pid());
    row["value"] = INTEGER(reinterpret_cast<uintptr_t>(Handle()));
    row["type"] = Type();
    row["access"] = Access();
    row["name"] = Name();
    row["attributes"] = Attributes();
    row["count"] = INTEGER(HandleCount());
    row["raw_pointer_count"] = INTEGER(RawPointerCount());
    row["error_stage"] = ErrorStageString(GetErrorStage());
    row["error_code"] = INTEGER(GetErrorCode());
    return row;
  }
};
using HandleRecordPtr = std::unique_ptr<HandleRecord>;

// Helper struct to query the os version, as certain operations we
// perform during handle enumeration are only supported on certain
// versions of Windows.
struct OSVersionInfo {
  bool isWin80OrGreater = false;

  OSVersionInfo() {
    RTL_OSVERSIONINFOW osvi = {sizeof(osvi)};

    // Win 8.0/2012 is 6.2, Win 8.1/2012R2 is 6.3
    if (RtlGetVersion(&osvi) == 0) {
      if (osvi.dwMajorVersion > 6) {
        isWin80OrGreater = true;
      } else if (osvi.dwMajorVersion == 6) {
        if (osvi.dwMinorVersion >= 2) {
          isWin80OrGreater = true;
        }
      }
    }
  }
};
static const OSVersionInfo gOSVersionInfo;

struct HandleCloser {
  void operator()(void* h) const {
    if (h && h != INVALID_HANDLE_VALUE)
      CloseHandle(h);
  }
};
using ScopedHandle = std::unique_ptr<void, HandleCloser>;

// Thread function for querying an object's name via NtQueryObject.
// This thread may be terminated via TerminateThread if NtQueryObject blocks
// on a synchronous file handle (named pipe, console, etc.).  Because
// TerminateThread does not run destructors or release synchronization
// objects, this function must not allocate heap memory, hold locks, or
// use any RAII constructs.
DWORD
WINAPI
QueryObjectNameThreadFunc(LPVOID lpParam) {
  auto params = static_cast<PQUERY_OBJECT_NAME_PARAMS>(lpParam);

  if (!params) {
    return ERROR_INVALID_PARAMETER;
  }
  ULONG retLen = 0;
  params->ntStatus = NtQueryObject(params->hObject,
                                   ObjectNameInformation,
                                   &params->nameBuffer,
                                   sizeof(params->nameBuffer),
                                   &retLen);

  // the real result of the query is in params->ntStatus
  return ERROR_SUCCESS;
}

// Construct and cache a list of all known types by calling
// ObjectAllTypesInformation
NTSTATUS
GetObjectTypeEnumeration(HandleRecordCache& cache) {
  NTSTATUS ntStatus = STATUS_SUCCESS;
  POBJECT_ALL_TYPES_INFORMATION pTypes = nullptr;
  ULONG retLen = 0;
  std::vector<uint8_t> localBuffer(INITIAL_ENUMERATION_BUFFER_SIZE);

  if (!gOSVersionInfo.isWin80OrGreater) {
    VLOG(1) << "Object type enumeration is only supported on Windows 8.0+";
    return STATUS_NOT_SUPPORTED;
  }

  ntStatus = NtQueryObject(nullptr,
                           ObjectAllTypesInformation,
                           localBuffer.data(),
                           static_cast<ULONG>(localBuffer.size()),
                           &retLen);

  if (STATUS_INFO_LENGTH_MISMATCH == ntStatus) {
    // We assume that even if an active system is creating/destroying object
    // types, it will not change so fast that the required buffer size doubles
    // between our calls. It's atypical for it to dynamically change at all
    // on most systems.
    size_t newSize = static_cast<size_t>(retLen) * 2;
    if ((newSize > MAXIMUM_ENUMERATION_BUFFER_SIZE) || (newSize > ULONG_MAX)) {
      return STATUS_BUFFER_TOO_SMALL;
    }
    localBuffer.resize(newSize);
    ntStatus = NtQueryObject(nullptr,
                             ObjectAllTypesInformation,
                             localBuffer.data(),
                             static_cast<ULONG>(newSize),
                             &retLen);
  }

  if (!NT_SUCCESS(ntStatus)) {
    VLOG(1) << "Failed to query object all types information: 0x" << std::hex
            << ntStatus << std::dec;
    return ntStatus;
  }

  pTypes = reinterpret_cast<POBJECT_ALL_TYPES_INFORMATION>(localBuffer.data());
  if (pTypes->NumberOfTypes > USHRT_MAX) {
    VLOG(1) << "Too many object types (" << pTypes->NumberOfTypes
            << ") exceeds a uint16_t which is used for handle type indices";
    return STATUS_INTEGER_OVERFLOW;
  }

  // Walk the serialized array of OBJECT_TYPE_INFORMATION entries.  Entries are
  // variable-length: each struct is followed by its TypeName string data, and
  // the next entry starts at the next pointer-aligned address.
  POBJECT_TYPE_INFORMATION typeIter = &pTypes->Types[0];
  for (ULONG i = 0; i < pTypes->NumberOfTypes; i++) {
    cache.CacheHandleType(typeIter->TypeIndex, &typeIter->TypeName);

    // advance our iterator, accounting for the trailing serialized string
    // buffer and alignment
    typeIter = reinterpret_cast<POBJECT_TYPE_INFORMATION>(
        reinterpret_cast<PBYTE>(typeIter) +
        AlignUpPtr(sizeof(OBJECT_TYPE_INFORMATION) +
                   typeIter->TypeName.MaximumLength));
  }

  return STATUS_SUCCESS;
}

// Attempt to resolve a File object's name by creating a section, mapping a
// view, and querying the mapped filename.  On success the result is written
// directly into params.nameBuffer / params.ntStatus so the caller's existing
// result-handling logic works unchanged.
MappingTechniqueResult GetFileObjectNameViaMappingTechnique(
    HANDLE hFile, QUERY_OBJECT_NAME_PARAMS& params) {
  HANDLE hSection = NULL;
  PVOID pBaseAddress = NULL;
  SIZE_T viewSize = 1;
  NTSTATUS ntStatus;

  ntStatus = NtCreateSection(&hSection,
                             SECTION_MAP_READ | SECTION_QUERY,
                             NULL,
                             NULL,
                             PAGE_READONLY,
                             SEC_COMMIT,
                             hFile);
  if (!NT_SUCCESS(ntStatus)) {
    if (STATUS_INVALID_HANDLE == ntStatus) {
      return MappingTechniqueResult::FailedInvalidHandle;
    }
    return MappingTechniqueResult::FailedOther;
  }

  ntStatus = NtMapViewOfSection(hSection,
                                GetCurrentProcess(),
                                &pBaseAddress,
                                0,
                                0,
                                NULL,
                                &viewSize,
                                2 /* ViewUnmap */,
                                0,
                                PAGE_READONLY);
  CloseHandle(hSection);
  if (!NT_SUCCESS(ntStatus)) {
    return MappingTechniqueResult::FailedOther;
  }

  SIZE_T retLen = 0;
  params.ntStatus = NtQueryVirtualMemory(GetCurrentProcess(),
                                         pBaseAddress,
                                         MemoryMappedFilenameInformation,
                                         &params.nameBuffer,
                                         sizeof(params.nameBuffer),
                                         &retLen);

  // Regardless of whether the Query succeeded or not, we need to unmap the view
  // of the section.
  NtUnmapViewOfSection(GetCurrentProcess(), pBaseAddress);

  if (!NT_SUCCESS(params.ntStatus)) {
    return MappingTechniqueResult::FailedOther;
  }

  return MappingTechniqueResult::Success;
}

/// Retrieves a process handle for duplication, using caches to avoid
/// redundant OpenProcess calls.  Returns the process HANDLE on success.
/// On failure, sets the error on the HandleRecord and returns
/// INVALID_HANDLE_VALUE.
HANDLE AcquireProcessHandle(
    HandleRecord& record,
    std::unordered_map<ULONG_PTR, DWORD>& failedPIDErrors,
    std::unordered_map<ULONG_PTR, ScopedHandle>& processHandleCache) {
  HANDLE processHandle = INVALID_HANDLE_VALUE;

  // Check the failedPiDErrors cache to see if we've already attempted and
  // failed to open a handle to this PID. If so, we can skip the attempt and
  // directly set the error on the record. This is important to avoid repeated
  // failed attempts on the same PID which can happen with many handles from the
  // same process
  auto failedPidIt = failedPIDErrors.find(record.Pid());
  if (failedPidIt != failedPIDErrors.end()) {
    record.SetError(ErrorStage::ProcessOpening, failedPidIt->second);
    return INVALID_HANDLE_VALUE;
  }

  // Check the processHandleCache to see if we already have a handle (successful
  // or failed) for this PID.  If so, use it.
  auto cachedHandleIt = processHandleCache.find(record.Pid());
  if (cachedHandleIt != processHandleCache.end()) {
    return cachedHandleIt->second.get();
  }

  // Attempt to open a handle to the process for duplication.
  // We need PROCESS_DUP_HANDLE access right to be able to duplicate handles
  // from it.
  processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, record.Pid());

  // If we failed to open a handle to the process, cache this failure in
  // failedPIDErrors and set the error on the record.
  if (NULL == processHandle || INVALID_HANDLE_VALUE == processHandle) {
    DWORD openProcessError = GetLastError();
    record.SetError(ErrorStage::ProcessOpening, openProcessError);
    failedPIDErrors.insert({record.Pid(), openProcessError});
    return INVALID_HANDLE_VALUE;
  }

  // cache the handle to avoid repeated attempts on the same PID
  // which can happen with many handles from the same process
  processHandleCache.try_emplace(record.Pid(), processHandle);

  return processHandle;
}

/// Resolve the name of the object referenced by duplicatedObjectHandle.
/// For File objects, uses the mapping technique first, then optionally
/// falls back to a thread with a timeout.  For non-File objects, queries
/// NtQueryObject directly (which is safe — only File objects can block).
void ResolveObjectName(HandleRecord& record,
                       HANDLE duplicatedObjectHandle,
                       const UNICODE_STRING& objectTypeName,
                       const UNICODE_STRING& fileTypeName,
                       QUERY_OBJECT_NAME_PARAMS& params) {
  ULONG retLen = 0;
  bool bThreadWaitSatisfied = false;

  // Prepare params for querying the name
  // STATUS_UNSUCCESSFUL allows us to detect failure in the thread if it
  // doesn't get to the point of setting it.
  params = {0};
  params.hObject = duplicatedObjectHandle;
  params.ntStatus = STATUS_UNSUCCESSFUL;

  // Consolidates the name-result recording logic used by all exit paths below.
  auto updateRecordWithNameResult = [&record, &params]() -> void {
    if (NT_SUCCESS(params.ntStatus) && (params.nameBuffer.usName.Length > 0)) {
      record.SetObjectName(&params.nameBuffer.usName);
    } else {
      record.SetObjectName(L"");
    }

    if (!NT_SUCCESS(params.ntStatus) &&
        record.GetErrorStage() == ErrorStage::None) {
      record.SetError(ErrorStage::ObjectNameQuerying,
                      RtlNtStatusToDosError(params.ntStatus),
                      true);
    }
  };

  // For File object types the NtQueryObject call could block
  // indefinitely (sync consoles, pipes, etc.)  We first attempt the
  // non-blocking mapping technique (section + mapped filename query).
  // If the mapping technique fails and the caller opted in via
  // FLAGS_allow_handle_threads, we fall back to a thread with a timeout.
  if (0 != RtlCompareUnicodeString(&objectTypeName, &fileTypeName, FALSE)) {
    params.ntStatus = NtQueryObject(params.hObject,
                                    ObjectNameInformation,
                                    &params.nameBuffer,
                                    sizeof(params.nameBuffer),
                                    &retLen);
    updateRecordWithNameResult();
    return;
  }

  MappingTechniqueResult mappingResult =
      GetFileObjectNameViaMappingTechnique(duplicatedObjectHandle, params);

  if (MappingTechniqueResult::Success == mappingResult) {
    updateRecordWithNameResult();
    return;
  }

  if (MappingTechniqueResult::FailedInvalidHandle == mappingResult) {
    params.ntStatus = STATUS_INVALID_HANDLE;
    updateRecordWithNameResult();
    return;
  }

  // Mapping technique failed, we will continue with the thread fallback only if
  // the user has explicitly accepted the risk of potential hangs by enabling
  // FLAGS_allow_handle_threads. Otherwise we will record the mapping error and
  // return.
  if (!FLAGS_allow_handle_threads) {
    // Mapping technique failed and thread fallback is disabled (the default).
    // NtQueryObject risks blocking indefinitely.  Record the mapping error
    // and leave the name unresolved.
    record.SetError(ErrorStage::ObjectNameMapping,
                    RtlNtStatusToDosError(params.ntStatus),
                    true);
    return;
  }

  // This thread technique is believed to be as safe as we can make it given
  // present Windows behaviors.  We use
  // NtCreateThreadEx(...,THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH, ...) to
  // attempt to ensure no per thread locking, ref counting, or allocations are
  // caused in user mode that might not get an opportunity to be cleaned if we
  // have to use NtTerminateThread().

  // Thread fallback poses a risk because we may need TerminateThread`
  // if `NtQueryObject` blocks on synchronous File handles.
  // We mitigate risk by:
  // 1) creating a minimal worker (`SKIP_THREAD_ATTACH`),
  // 2) bounding wait time (500ms),
  // 3) forcing thread exit only on timeout/failure.
  // 4) thread fallback is excplicitly opt-in via FLAGS_allow_handle_threads
  // (default is disabled)
  HANDLE hThread = NULL;
  NTSTATUS ntThreadStatus =
      NtCreateThreadEx(&hThread,
                       THREAD_ALL_ACCESS,
                       NULL,
                       GetCurrentProcess(),
                       static_cast<PVOID>(QueryObjectNameThreadFunc),
                       &params,
                       THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH,
                       0,
                       0,
                       0,
                       NULL);

  // If we failed to create the thread, we won't be able to query the name, so
  // log the error and return.
  if (!NT_SUCCESS(ntThreadStatus) || NULL == hThread) {
    record.SetError(ErrorStage::ObjectNameQuerying,
                    NT_SUCCESS(ntThreadStatus)
                        ? GetLastError()
                        : RtlNtStatusToDosError(ntThreadStatus));
    record.SetObjectName(L"<failed resolving>");
    return;
  }

  // Wait for the thread to complete with a timeout.  If the wait fails or times
  // out, we will proceed to hard-terminate the thread.
  ScopedHandle threadHandle(hThread);
  switch (WaitForSingleObject(hThread, 500)) {
  case WAIT_OBJECT_0:
    bThreadWaitSatisfied = true;
    break;
  case WAIT_TIMEOUT:
    record.SetError(ErrorStage::ObjectNameQuerying, ERROR_TIMEOUT, true);
    break;
  default:
    DWORD lastError = GetLastError();
    record.SetError(ErrorStage::ObjectNameQuerying, lastError, true);
    break;
  }

  if (!bThreadWaitSatisfied) {
    // Hard-terminate the thread.  TerminateThread is dangerous — it does not
    // run destructors, release locks, or notify DLLs.  We accept this risk
    // because the alternative (NtQueryObject blocking forever) is worse.
    // WaitForSingleObject ensures the thread has fully exited before we
    // return (and the params struct on our stack goes out of scope).
    // The user is aware of this risk when they enable the handle threads
    // fallback via FLAGS_allow_handle_threads.
    TerminateThread(hThread, ERROR_CANCELLED);
    WaitForSingleObject(hThread, INFINITE);
  }

  updateRecordWithNameResult();
}

/// Populate record with duplicated-handle metadata (basic info, type, name).
void EnrichHandleRecord(
    HandleRecord& record,
    HANDLE processHandle,
    const UNICODE_STRING& fileTypeName,
    OBJECT_BASIC_INFORMATION& objBasicInfo, // reusable buffer
    OBJECT_TYPE_INFORMATION_WITH_STORAGE& objTypeInfo, // reusable buffer
    QUERY_OBJECT_NAME_PARAMS& params) {
  NTSTATUS ntStatus = STATUS_SUCCESS;
  HANDLE duplicatedObjectHandle = INVALID_HANDLE_VALUE;

  // Try duplicating with GENERIC_READ first because the mapping technique
  // (NtCreateSection) requires read access to the file handle.
  ntStatus = NtDuplicateObject(processHandle,
                               record.Handle(),
                               GetCurrentProcess(),
                               &duplicatedObjectHandle,
                               GENERIC_READ,
                               0,
                               0);

  // If the source process's handle doesn't grant read, we fall back to a
  // zero-access duplicate which is sufficient for NtQueryObject but cannot
  // use the mapping technique.
  if (STATUS_ACCESS_DENIED == ntStatus) {
    ntStatus = NtDuplicateObject(processHandle,
                                 record.Handle(),
                                 GetCurrentProcess(),
                                 &duplicatedObjectHandle,
                                 0,
                                 0,
                                 0);
  }

  // If duplication still fails, we won't be able to query anything about this
  // handle, so log the error and return
  if (!NT_SUCCESS(ntStatus)) {
    record.SetError(
        ErrorStage::HandleDuplication, RtlNtStatusToDosError(ntStatus), true);
    return;
  }

  // query ObjectBasicInformation to get the raw PointerCount and handle
  // potential handle reuse between our enumeration and duplication.
  ULONG retLen = 0;
  auto scopedDupHandle = ScopedHandle(duplicatedObjectHandle);
  objBasicInfo = {0};
  ntStatus = NtQueryObject(duplicatedObjectHandle,
                           ObjectBasicInformation,
                           &objBasicInfo,
                           sizeof(objBasicInfo),
                           &retLen);

  // If basic info querying fails, there is no new information we can get about
  // this handle, so log the error and return.
  if (!NT_SUCCESS(ntStatus)) {
    record.SetError(ErrorStage::ObjectBasicInfoQuerying,
                    RtlNtStatusToDosError(ntStatus),
                    true);
    return;
  }

  // The pointer count is new information we wanted.
  record.SetRawPointerCount(objBasicInfo.PointerCount);

  // Other information came in the initial enumeration, but we have to
  // allow for the possibility that the handle value got reused between
  // that enumeration and now, so if we're able to get to the
  // ObjectBasicInformation query on the duplicated handle, we should
  // replace it.
  record.SetGrantedAccess(objBasicInfo.GrantedAccess);
  record.SetHandleAttributes(objBasicInfo.Attributes);
  record.SetHandleCount(objBasicInfo.HandleCount);

  // We query the ObjectTypeInformation to accommodate the potential
  // handle reuse case, but also on pre-Win8 systems we would not have had
  // access to type information in the initial enumeration.
  objTypeInfo = {0};
  ntStatus = NtQueryObject(duplicatedObjectHandle,
                           ObjectTypeInformation,
                           &objTypeInfo,
                           sizeof(objTypeInfo),
                           &retLen);

  if (!NT_SUCCESS(ntStatus)) {
    // If unsuccessful, log the error and move on, we will
    // have a chance to recover at row generation by checking the type index
    // mapping against the cache
    record.SetError(ErrorStage::ObjectTypeInfoQuerying,
                    RtlNtStatusToDosError(ntStatus));
    return;
  }
  record.SetObjectTypeName(&objTypeInfo.TypeInfo.TypeName);

  // Attempt to resolve the object name
  ResolveObjectName(record,
                    duplicatedObjectHandle,
                    objTypeInfo.TypeInfo.TypeName,
                    fileTypeName,
                    params);
}

// Parent class that holds the state of handle enumeration,
// including the cache, the list of PIDs to filter on, and the resulting handle
// records that will be converted to rows for output.
class HandleEnumeration {
 public:
  HandleRecordCache m_cache;
  std::set<int> m_pidlist;
  std::vector<HandleRecordPtr> handleRecords;
  int32_t failedHandleThreadCount = 0;

  HandleEnumeration(const std::set<int>& pidlist) : m_pidlist(pidlist) {}

  bool IsPidFiltered(DWORD pid) const {
    return !m_pidlist.empty() &&
           m_pidlist.find(static_cast<int>(pid)) == m_pidlist.end();
  }

  HandleRecordCache& Cache() {
    return m_cache;
  }

  QueryData ToRows() {
    QueryData rows;
    for (const auto& handle : handleRecords) {
      rows.push_back(handle->ToRow());
    }
    return rows;
  }

  // Get handle enumeration and a minimal type mapping.
  NTSTATUS
  GetHandleAndTypeEnumeration() {
    NTSTATUS ntStatus = STATUS_SUCCESS;
    PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = nullptr;
    ULONG retLen = 0;

    std::vector<uint8_t> localBuffer(INITIAL_ENUMERATION_BUFFER_SIZE);

    // 1. Acquire the type enumeration if supported.
    ntStatus = GetObjectTypeEnumeration(m_cache);
    if (STATUS_SUCCESS != ntStatus && STATUS_NOT_SUPPORTED != ntStatus) {
      return ntStatus;
    }

    // 2. Query handles
    ntStatus = NtQuerySystemInformation(SystemExtendedHandleInformation,
                                        localBuffer.data(),
                                        static_cast<ULONG>(localBuffer.size()),
                                        &retLen);

    if (STATUS_INFO_LENGTH_MISMATCH == ntStatus) {
      // We assume that the quantity of handles won't more than double between
      // our calls, on typical system we'll be expecting on the order of 10s of
      // thousands of handles
      size_t newSize = static_cast<size_t>(retLen) * 2;
      if ((newSize > MAXIMUM_ENUMERATION_BUFFER_SIZE) ||
          (newSize > ULONG_MAX)) {
        return STATUS_BUFFER_TOO_SMALL;
      }
      localBuffer.resize(newSize);
      ntStatus = NtQuerySystemInformation(SystemExtendedHandleInformation,
                                          localBuffer.data(),
                                          static_cast<ULONG>(newSize),
                                          &retLen);
    }

    if (STATUS_SUCCESS != ntStatus) {
      return ntStatus;
    }

    // 3. Filter and process the basic enumeration into our record structure
    pHandleInfo =
        reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(localBuffer.data());
    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++) {
      PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = &pHandleInfo->Handles[i];
      if (IsPidFiltered(static_cast<DWORD>(entry->UniqueProcessId))) {
        continue;
      }
      handleRecords.emplace_back(
          std::make_unique<HandleRecord>(entry, m_cache));
    }

    return STATUS_SUCCESS;
  }

  // Enumerate and enrich all handle records not excluded by our PID filter
  // including error handling and mitigations for potential blocking calls
  // when querying object names.
  DWORD
  EnumerateAllHandles() {
    NTSTATUS ntStatus = STATUS_SUCCESS;
    UNICODE_STRING fileTypeName = {0};
    std::unordered_map<ULONG_PTR, DWORD> failedPIDErrors;
    std::unordered_map<ULONG_PTR, ScopedHandle> processHandleCache;

    // Acquire the enumerations.
    ntStatus = GetHandleAndTypeEnumeration();
    if (STATUS_SUCCESS != ntStatus) {
      DWORD dwStatus = RtlNtStatusToDosError(ntStatus);
      return dwStatus;
    }

    // We need the File type name as a special case for the mapping technique in
    // object name resolution.  We initialize it here to avoid unnecessary stack
    // allocation in the inner loop of name resolution
    RtlInitUnicodeString(&fileTypeName, L"File");

    // Each loop iteration needs these structures, but we want to avoid
    // per-iteration stack allocation The enrichment function will zero and
    // repopulate them on each call
    OBJECT_TYPE_INFORMATION_WITH_STORAGE objTypeInfo = {0};
    QUERY_OBJECT_NAME_PARAMS params = {0};
    OBJECT_BASIC_INFORMATION objBasicInfo = {0};

    // Enrich Handle records
    for (auto& handleIter : handleRecords) {
      // Aquire the Process Handle for this record, using caches to avoid
      // redundant OpenProcess calls on the same PID
      HANDLE processHandle = AcquireProcessHandle(
          *handleIter, failedPIDErrors, processHandleCache);
      if (INVALID_HANDLE_VALUE == processHandle) {
        continue;
      }

      // Enrich the record with the duplicated handle's information,
      // including querying the name with potential blocking mitigations
      // for File objects
      EnrichHandleRecord(*handleIter,
                         processHandle,
                         fileTypeName,
                         objBasicInfo,
                         objTypeInfo,
                         params);

      // The combination of ErrorStage::ObjectNameQuerying and ERROR_TIMEOUT is
      // an indication that we had to fall back to the thread technique for
      // querying the object name and that it timed out, which likely means we
      // were dealing with a synchronous File handle (console, pipe, etc.) that
      // NtQueryObject blocked on.
      if (handleIter->GetErrorStage() == ErrorStage::ObjectNameQuerying) {
        if (handleIter->GetErrorCode() == ERROR_TIMEOUT) {
          failedHandleThreadCount++;
        }
      }
    }
    return ERROR_SUCCESS;
  }
};

} // namespace handles

// osquery table entry point for the "handles" table.
// If no pid constraint is provided, defaults to the current (osquery)
// process.  Requires SeDebugPrivilege for cross-process enumeration.
QueryData genProcessOpenHandles(QueryContext& context) {
  // Determine pid constraints, pid is a required column
  std::set<int> pidlist = context.constraints.at("pid").getAll<int>(EQUALS);

  if (pidlist.empty()) {
    // If no pid constraints are provided, default to the current process
    VLOG(1) << "No pid constraint provided for handles table";
    return QueryData();
  }

  // Acquire the debug token privilege guard
  SeDebugPrivilegeGuard debugPrivilegeGuard;

  // Perform the enumeration and enrichment of handle records
  handles::HandleEnumeration handleEnumeration(pidlist);
  if (ERROR_SUCCESS != handleEnumeration.EnumerateAllHandles()) {
    VLOG(1) << "Failed to enumerate all handles.";
    return QueryData();
  }

  if (handleEnumeration.failedHandleThreadCount > 0) {
    VLOG(1) << handleEnumeration.failedHandleThreadCount
            << " handle enumeration thread(s) timed out."
            << " Occasional occurrences are considered normal due to the "
               "nature of the technique,"
            << " however a large number of timeouts could indicate an issue."
            << RLOG(8818);
  }

  // Convert the resulting handle records to rows for output
  return handleEnumeration.ToRows();
}

} // namespace tables
} // namespace osquery