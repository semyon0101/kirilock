#include "auth/password.hpp"

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <security/pam_appl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef NDEBUG
#ifdef __GLIBC__
extern "C" void __libc_freeres(void);
#endif
#endif

namespace auth {

namespace {

void secure_clear(void *v, size_t n) {
  volatile unsigned char *p = static_cast<volatile unsigned char *>(v);
  while (n--)
    *p++ = 0;
}

int internal_pam_conv(int num_msg, const struct pam_message **msg,
                      struct pam_response **resp, void *appdata_ptr) {
  if (num_msg <= 0 || !resp || !appdata_ptr)
    return PAM_CONV_ERR;
  auto *reply = static_cast<struct pam_response *>(
      std::calloc(static_cast<size_t>(num_msg), sizeof(struct pam_response)));
  if (!reply)
    return PAM_BUF_ERR;

  for (int i = 0; i < num_msg; ++i) {
    if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
        msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
      reply[i].resp = strdup(static_cast<const char *>(appdata_ptr));
      if (!reply[i].resp) {
        while (i > 0) {
          std::free(reply[--i].resp);
        }
        std::free(reply);
        return PAM_BUF_ERR;
      }
      reply[i].resp_retcode = 0;
    }
  }
  *resp = reply;
  return PAM_SUCCESS;
}

} // anonymous namespace

Password::Password(std::string username, void *user_data)
    : username_(std::move(username)), user_data_(user_data) {}

Password::~Password() {
  stop();

  if (worker_thread_.joinable()) {
    worker_thread_.join();
  }

  clear_candidate();

  if (handlers_.on_delete) {
    handlers_.on_delete(this);
  }
}

void Password::clear_candidate() noexcept {
  if (!candidate_.empty()) {
    secure_clear(candidate_.data(), candidate_.size());
    candidate_.clear();
  }
}

void Password::set_handlers(const PasswordHandlers &handlers) {
  handlers_ = handlers;
  if (!init_called_ && handlers_.on_init) {
    handlers_.on_init(this);
    init_called_ = true;
  }
}

bool Password::verify(std::string_view pass) noexcept {
  try {
    bool expected = false;
    if (!is_running_.compare_exchange_strong(expected, true))
      return false;

    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }

    candidate_ = pass;

    worker_thread_ = std::jthread([this]() { run_worker(); });
    return true;
  } catch (...) {
    is_running_.store(false);
    clear_candidate();
    return false;
  }
}

void Password::stop() noexcept {
  bool expected = true;
  if (!is_running_.compare_exchange_strong(expected, false))
    return;

  pid_t pam_pid = active_pam_pid_.exchange(0);
  if (pam_pid > 0) {
    kill(pam_pid, SIGKILL);
  }
}

void Password::run_worker() {
  if (handlers_.on_begin)
    handlers_.on_begin(this);

  pid_t pid = fork();
  if (pid < 0) {
    if (handlers_.on_error)
      handlers_.on_error(this, PasswordError::System, "fork() failed");
    cleanup();
    return;
  }

  if (pid == 0) {
    // Child process for PAM isolation
    pam_handle_t *pamh = nullptr;
    struct pam_conv conv = {internal_pam_conv, candidate_.data()};
    int ret = pam_start("system-auth", username_.c_str(), &conv, &pamh);
    if (ret == PAM_SUCCESS) {
      ret = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
      if (ret == PAM_SUCCESS)
        ret = pam_acct_mgmt(pamh, 0);
    }
    pam_end(pamh, ret);

    secure_clear(candidate_.data(), candidate_.size());
#ifndef NDEBUG
#ifdef __GLIBC__
    __libc_freeres();
#endif
#endif
    _exit(ret == PAM_SUCCESS ? 0 : 1);
  }

  active_pam_pid_.store(pid);

  if (!is_running_.load()) {
    pid_t to_kill = active_pam_pid_.exchange(0);
    if (to_kill > 0) {
      kill(to_kill, SIGKILL);
    }
  }

  int status = 0;
  waitpid(pid, &status, 0);
  active_pam_pid_.store(0);

  if (is_running_.load()) {
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
      if (handlers_.on_finish)
        handlers_.on_finish(this);
    } else {
      if (handlers_.on_error)
        handlers_.on_error(this, PasswordError::AuthFailed,
                           "Invalid password or access denied");
    }
  }

  cleanup();
}

void Password::cleanup() noexcept {
  if (handlers_.on_end)
    handlers_.on_end(this);

  if (!is_running_.load()) {
    if (handlers_.on_stop)
      handlers_.on_stop(this);
  }

  clear_candidate();
  is_running_.store(false);
}

bool Password::is_running() const noexcept { return is_running_.load(); }

void *Password::get_user_data() const noexcept { return user_data_; }

void Password::set_user_data(void *data) noexcept { user_data_ = data; }

const std::string &Password::get_username() const noexcept { return username_; }

} // namespace auth
