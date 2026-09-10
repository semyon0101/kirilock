#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <thread>

namespace auth {

enum class PasswordError { AuthFailed, System };

class Password;

struct PasswordHandlers {
  std::function<void(Password *)> on_init{};
  std::function<void(Password *)> on_begin{};
  std::function<void(Password *)> on_finish{};
  std::function<void(Password *, PasswordError, std::string_view)> on_error{};
  std::function<void(Password *)> on_end{};
  std::function<void(Password *)> on_stop{};
  std::function<void(Password *)> on_delete{};
};

class Password {
public:
  explicit Password(std::string username, void *user_data = nullptr);
  ~Password() noexcept;

  void set_handlers(const PasswordHandlers &handlers);
  bool verify(std::string_view password) noexcept;
  void stop() noexcept;
  [[nodiscard]] bool is_running() const noexcept;
  [[nodiscard]] void *get_user_data() const noexcept;
  void set_user_data(void *data) noexcept;
  [[nodiscard]] const std::string &get_username() const noexcept;

private:
  void run_worker();
  void cleanup() noexcept;
  void clear_candidate() noexcept;

  std::string username_;
  void *user_data_{nullptr};
  PasswordHandlers handlers_{};

  std::jthread worker_thread_{};
  bool init_called_{false};

  std::atomic<bool> is_running_{false};
  std::atomic<pid_t> active_pam_pid_{0};
  std::string candidate_{};
};

} // namespace auth
