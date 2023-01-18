/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

#include <comdef.h>
#include <taskschd.h>
#include <winbase.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>

#include <osquery/process/process.h>

namespace osquery {
namespace tables {

const std::string kTimeFormat{"%H:%M:%S %b-%d-%Y"};
const std::map<TASK_STATE, std::string> kStateMap = {
    {TASK_STATE_UNKNOWN, "unknown"},
    {TASK_STATE_DISABLED, "disabled"},
    {TASK_STATE_QUEUED, "queued"},
    {TASK_STATE_READY, "ready"},
    {TASK_STATE_RUNNING, "running"},
};

void enumerateTasksForFolder(std::string path, QueryData& results) {
  void* vpService = nullptr;
  auto ret = CoCreateInstance(CLSID_TaskScheduler,
                              nullptr,
                              CLSCTX_INPROC_SERVER,
                              IID_ITaskService,
                              &vpService);
  if (FAILED(ret)) {
    VLOG(1) << "Failed to create COM instance " << ret;
    return;
  }

  auto pService = static_cast<ITaskService*>(vpService);
  ret =
      pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
  if (FAILED(ret)) {
    VLOG(1) << "Failed to connect to TaskService " << ret;
    pService->Release();
    return;
  }

  ITaskFolder* pRootFolder = nullptr;
  auto widePath = stringToWstring(path);
  ret = pService->GetFolder(BSTR(widePath.c_str()), &pRootFolder);
  pService->Release();
  if (FAILED(ret)) {
    VLOG(1) << "Failed to get root task folder " << ret;
    return;
  }

  IRegisteredTaskCollection* pTaskCollection = nullptr;
  ret = pRootFolder->GetTasks(TASK_ENUM_HIDDEN, &pTaskCollection);
  pRootFolder->Release();
  if (FAILED(ret)) {
    VLOG(1) << "Failed to get task collection for root folder " << ret;
    return;
  }

  long numTasks = 0;
  pTaskCollection->get_Count(&numTasks);
  for (size_t i = 0; i < numTasks; i++) {
    IRegisteredTask* pRegisteredTask = nullptr;
    // Collections are 1-based lists
    ret = pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask);
    if (FAILED(ret)) {
      VLOG(1) << "Failed to process task";
      continue;
    }

    Row r;
    BSTR taskName;
    ret = pRegisteredTask->get_Name(&taskName);
    std::wstring wTaskName(taskName, SysStringLen(taskName));
    ::SysFreeString(taskName);
    r["name"] = ret == S_OK ? SQL_TEXT(wstringToString(wTaskName.c_str())) : "";

    VARIANT_BOOL enabled = false;
    pRegisteredTask->get_Enabled(&enabled);
    r["enabled"] = enabled ? INTEGER(1) : INTEGER(0);

    TASK_STATE taskState;
    pRegisteredTask->get_State(&taskState);
    r["state"] = kStateMap.count(taskState) > 0
                     ? kStateMap.at(taskState)
                     : kStateMap.at(TASK_STATE_UNKNOWN);

    BSTR taskPath;
    ret = pRegisteredTask->get_Path(&taskPath);
    std::wstring wTaskPath(taskPath, SysStringLen(taskPath));
    r["path"] = ret == S_OK ? wstringToString(wTaskPath.c_str()) : "";
    ::SysFreeString(taskPath);

    VARIANT_BOOL hidden = false;
    pRegisteredTask->get_Enabled(&hidden);
    r["hidden"] = hidden ? INTEGER(1) : INTEGER(0);

    HRESULT lastTaskRun = E_FAIL;
    pRegisteredTask->get_LastTaskResult(&lastTaskRun);
    _com_error err(lastTaskRun);
    r["last_run_message"] = wstringToString(err.ErrorMessage());
    r["last_run_code"] = INTEGER(lastTaskRun);

    // We conver the COM Date type to a unix epoch timestamp
    DATE dRunTime;
    SYSTEMTIME st;
    FILETIME ft;
    FILETIME locFt;

    pRegisteredTask->get_LastRunTime(&dRunTime);
    VariantTimeToSystemTime(dRunTime, &st);
    SystemTimeToFileTime(&st, &ft);
    LocalFileTimeToFileTime(&ft, &locFt);
    r["last_run_time"] = BIGINT(filetimeToUnixtime(locFt));

    pRegisteredTask->get_NextRunTime(&dRunTime);
    VariantTimeToSystemTime(dRunTime, &st);
    SystemTimeToFileTime(&st, &ft);
    LocalFileTimeToFileTime(&ft, &locFt);
    r["next_run_time"] = BIGINT(filetimeToUnixtime(locFt));

    ITaskDefinition* taskDef = nullptr;
    IActionCollection* tActionCollection = nullptr;
    pRegisteredTask->get_Definition(&taskDef);
    if (taskDef != nullptr) {
      taskDef->get_Actions(&tActionCollection);
      taskDef->Release();
    }
    pRegisteredTask->Release();

    long actionCount = 0;
    if (tActionCollection != nullptr) {
      tActionCollection->get_Count(&actionCount);
    }
    std::vector<std::string> actions;

    // Task collections are 1-indexed
    for (auto j = 1; j <= actionCount; j++) {
      IAction* act = nullptr;
      IExecAction* execAction = nullptr;
      tActionCollection->get_Item(j, &act);
      if (act == nullptr) {
        continue;
      }
      act->QueryInterface(IID_IExecAction,
                          reinterpret_cast<void**>(&execAction));
      act->Release();
      if (execAction == nullptr) {
        continue;
      }

      BSTR taskExecPath;
      execAction->get_Path(&taskExecPath);
      std::wstring wTaskExecPath(taskExecPath, SysStringLen(taskExecPath));
      ::SysFreeString(taskExecPath);

      BSTR taskExecArgs;
      execAction->get_Arguments(&taskExecArgs);
      std::wstring wTaskExecArgs(taskExecArgs, SysStringLen(taskExecArgs));
      ::SysFreeString(taskExecArgs);

      BSTR taskExecRoot;
      execAction->get_WorkingDirectory(&taskExecRoot);
      std::wstring wTaskExecRoot(taskExecRoot, SysStringLen(taskExecRoot));
      ::SysFreeString(taskExecRoot);

      execAction->Release();

      auto full = wTaskExecRoot + L" " + wTaskExecPath + L" " + wTaskExecArgs;
      actions.push_back(wstringToString(full.c_str()));
    }
    if (tActionCollection != nullptr) {
      tActionCollection->Release();
    }
    r["action"] = !actions.empty() ? osquery::join(actions, ",") : "";

    results.push_back(r);
  }
  pTaskCollection->Release();
}

QueryData genScheduledTasks(QueryContext& context) {
  QueryData results;

  // First process all tasks in the root folder
  enumerateTasksForFolder("\\", results);

  // We attempt to derive the location of the tasks folder
  auto sysRoot = getEnvVar("SystemRoot");
  if (!sysRoot.is_initialized()) {
    return results;
  }
  auto sysTaskPath = *sysRoot + "\\System32\\Tasks";

  // Then process all tasks in subsequent folders
  std::vector<std::string> taskPaths;
  listDirectoriesInDirectory(sysTaskPath, taskPaths, true);
  for (const auto& path : taskPaths) {
    if (sysTaskPath.size() >= path.size()) {
      VLOG(1) << "Invalid task path " << path;
      continue;
    }
    auto taskPath =
        "\\" + join(split(path.substr(sysTaskPath.size(),
                                      (path.size() - sysTaskPath.size())),
                          "\\"),
                    "\\");
    enumerateTasksForFolder(taskPath, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
