#pragma once

#include <array>
#include <atomic>
#include <functional>
#include <string>
#include <string_view>
#include <thread>

struct sd_bus;
struct sd_bus_slot;
struct sd_bus_message;
struct sd_bus_error;

namespace auth {

enum class FingerprintError { NotMatch, NotFound, System };

class Fingerprint;

struct FingerprintHandlers {
  std::function<void(Fingerprint *)> on_init{};
  std::function<void(Fingerprint *)> on_start{};
  std::function<void(Fingerprint *)> on_loop{};
  std::function<void(Fingerprint *)> on_finish{};
  std::function<void(Fingerprint *, FingerprintError, std::string_view)>
      on_error{};
  std::function<void(Fingerprint *)> on_end{};
  std::function<void(Fingerprint *)> on_stop{};
  std::function<void(Fingerprint *)> on_delete{};
};

class Fingerprint {
public:
  explicit Fingerprint(std::string username, void *user_data = nullptr);
  ~Fingerprint() noexcept;

  void set_handlers(const FingerprintHandlers &handlers);
  bool start() noexcept;
  void stop() noexcept;
  [[nodiscard]] bool is_running() const noexcept;
  [[nodiscard]] void *get_user_data() const noexcept;
  void set_user_data(void *data) noexcept;
  [[nodiscard]] const std::string &get_username() const noexcept;

private:
  void run_worker();
  static int fprint_signal_cb(sd_bus_message *m, void *userdata,
                              sd_bus_error *ret_error);

  std::string username_;
  void *user_data_{nullptr};
  FingerprintHandlers handlers_{};

  std::jthread worker_thread_{};
  bool init_called_{false};

  std::atomic<bool> is_running_{false};
  std::atomic<bool> check_in_progress_{false};
  std::array<int, 2> cancel_pipe_{-1, -1};

  sd_bus *bus_{nullptr};
  std::string device_path_{};
  sd_bus_slot *signal_slot_{nullptr};
};

} // namespace auth
