/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for scheduled_tasks
// Spec file: specs/windows/scheduled_tasks.table

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/utils/scope_guard.h>

#include <comdef.h>
#include <taskschd.h>
#include <windows.h>

#include <string>

namespace osquery {
namespace table_tests {

class scheduledTasks : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();

    task_name_ =
        "osquery_test_hidden_disabled_" + std::to_string(GetCurrentProcessId());

    void* task_service = nullptr;
    auto ret = CoCreateInstance(CLSID_TaskScheduler,
                                nullptr,
                                CLSCTX_INPROC_SERVER,
                                IID_ITaskService,
                                &task_service);

    ASSERT_TRUE(SUCCEEDED(ret));

    task_service_ = static_cast<ITaskService*>(task_service);

    ret = task_service_->Connect(
        _variant_t(), _variant_t(), _variant_t(), _variant_t());

    ASSERT_TRUE(SUCCEEDED(ret));

    ret = task_service_->GetFolder(_bstr_t(L"\\"), &root_folder_);

    ASSERT_TRUE(SUCCEEDED(ret));

    root_folder_->DeleteTask(_bstr_t(task_name_.c_str()), 0);

    ret = createHiddenDisabledTask();

    ASSERT_TRUE(SUCCEEDED(ret));
  }

  void TearDown() override {
    if (root_folder_ != nullptr) {
      root_folder_->DeleteTask(_bstr_t(task_name_.c_str()), 0);
      root_folder_->Release();
      root_folder_ = nullptr;
    }

    if (task_service_ != nullptr) {
      task_service_->Release();
      task_service_ = nullptr;
    }
  }

  HRESULT createHiddenDisabledTask() {
    ITaskDefinition* task_definition = nullptr;

    auto ret = task_service_->NewTask(0, &task_definition);
    if (FAILED(ret)) {
      return ret;
    }

    auto const task_definition_guard = scope_guard::create(
        [task_definition]() { task_definition->Release(); });

    ITaskSettings* task_settings = nullptr;

    ret = task_definition->get_Settings(&task_settings);
    if (FAILED(ret)) {
      return ret;
    }

    auto const task_settings_guard =
        scope_guard::create([task_settings]() { task_settings->Release(); });

    ret = task_settings->put_Hidden(VARIANT_TRUE);
    if (FAILED(ret)) {
      return ret;
    }

    IActionCollection* action_collection = nullptr;

    ret = task_definition->get_Actions(&action_collection);
    if (FAILED(ret)) {
      return ret;
    }

    auto const action_collection_guard = scope_guard::create(
        [action_collection]() { action_collection->Release(); });

    IAction* action = nullptr;

    ret = action_collection->Create(TASK_ACTION_EXEC, &action);
    if (FAILED(ret)) {
      return ret;
    }

    auto const action_guard =
        scope_guard::create([action]() { action->Release(); });

    IExecAction* exec_action = nullptr;

    ret = action->QueryInterface(IID_IExecAction,
                                 reinterpret_cast<void**>(&exec_action));

    if (FAILED(ret)) {
      return ret;
    }

    auto const exec_action_guard =
        scope_guard::create([exec_action]() { exec_action->Release(); });

    ret = exec_action->put_Path(_bstr_t(L"cmd.exe"));
    if (FAILED(ret)) {
      return ret;
    }

    IRegisteredTask* registered_task = nullptr;

    ret = root_folder_->RegisterTaskDefinition(_bstr_t(task_name_.c_str()),
                                               task_definition,
                                               TASK_CREATE,
                                               _variant_t(),
                                               _variant_t(),
                                               TASK_LOGON_INTERACTIVE_TOKEN,
                                               _variant_t(),
                                               &registered_task);

    if (FAILED(ret)) {
      return ret;
    }

    auto const registered_task_guard = scope_guard::create(
        [registered_task]() { registered_task->Release(); });

    return registered_task->put_Enabled(VARIANT_FALSE);
  }

 private:
  ITaskService* task_service_{nullptr};
  ITaskFolder* root_folder_{nullptr};
  std::string task_name_;
};

TEST_F(scheduledTasks, test_hidden_state) {
  auto const data = execute_query(
      "select name, enabled, hidden from scheduled_tasks where name = '" +
      task_name_ + "'");

  ASSERT_EQ(data.size(), 1ul);

  EXPECT_EQ(data[0].at("enabled"), "0");
  EXPECT_EQ(data[0].at("hidden"), "1");
}

} // namespace table_tests
} // namespace osquery
