#include <osquery/expected.h>
#include <osquery/killswitch/killswitch_plugin.h>

namespace osquery {
/**
 * @brief Interface class for killswitch plugins.
 */
class KillswitchRefreshablePlugin : public KillswitchPlugin {
 public:
  Status setUp() override;

  /// Main entrypoint for killswitch plugin requests
  virtual Status call(const PluginRequest& request,
                      PluginResponse& response) override;

 protected:
  enum class RefreshError {
    NoContent = 1,
    ParsingError = 2,
    IncorrectKeyType = 3,
    IncorrectValueType = 4
  };
  virtual ExpectedSuccess<RefreshError> refresh() = 0;
};
} // namespace osquery
