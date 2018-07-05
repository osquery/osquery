#include <osquery/killswitch/killswitch_plugin.h>
#include <osquery/expected.h>

namespace osquery {
/**
 * @brief Interface class for killswitch plugins.
 */
class KillswitchRefreshablePlugin : public KillswitchPlugin {
 public:
  enum class RefreshError {NoContent = 1};

 public:
  Status setUp() override;

  /// Main entrypoint for killswitch plugin requests
  virtual Status call(const PluginRequest& request,
                      PluginResponse& response) override;

 protected:
  virtual ExpectedSuccess<RefreshError> refresh() = 0;
};
} // namespace osquery
