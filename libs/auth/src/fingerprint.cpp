#include "auth/fingerprint.hpp"

#include <chrono>
#include <cstring>
#include <sys/select.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

namespace auth {

Fingerprint::Fingerprint(std::string username, void *user_data)
    : username_(std::move(username)), user_data_(user_data) {
  if (pipe(cancel_pipe_.data()) != 0) {
    cancel_pipe_[0] = -1;
    cancel_pipe_[1] = -1;
  }

  if (sd_bus_open_system(&bus_) >= 0) {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = nullptr;
    int r = sd_bus_call_method(bus_, "net.reactivated.Fprint",
                               "/net/reactivated/Fprint/Manager",
                               "net.reactivated.Fprint.Manager",
                               "GetDefaultDevice", &error, &reply, "");
    if (r >= 0) {
      const char *path = nullptr;
      if (sd_bus_message_read(reply, "o", &path) >= 0 && path) {
        device_path_ = path;
      }
      sd_bus_message_unref(reply);

      if (!device_path_.empty()) {
        sd_bus_call_method(bus_, "net.reactivated.Fprint", device_path_.c_str(),
                           "net.reactivated.Fprint.Device", "Claim", nullptr,
                           nullptr, "s", username_.c_str());

        sd_bus_match_signal(bus_, &signal_slot_, "net.reactivated.Fprint",
                            device_path_.c_str(),
                            "net.reactivated.Fprint.Device", "VerifyStatus",
                            fprint_signal_cb, this);
      }
    }
    sd_bus_error_free(&error);
  }
}

Fingerprint::~Fingerprint() {
  stop();

  if (worker_thread_.joinable()) {
    worker_thread_.join();
  }

  if (bus_ && !device_path_.empty()) {
    sd_bus_call_method(bus_, "net.reactivated.Fprint", device_path_.c_str(),
                       "net.reactivated.Fprint.Device", "Release", nullptr,
                       nullptr, "");
  }
  if (signal_slot_) {
    sd_bus_slot_unref(signal_slot_);
    signal_slot_ = nullptr;
  }
  if (bus_) {
    sd_bus_flush_close_unref(bus_);
    bus_ = nullptr;
  }

  if (cancel_pipe_[0] >= 0) {
    close(cancel_pipe_[0]);
    cancel_pipe_[0] = -1;
  }
  if (cancel_pipe_[1] >= 0) {
    close(cancel_pipe_[1]);
    cancel_pipe_[1] = -1;
  }

  if (handlers_.on_delete) {
    handlers_.on_delete(this);
  }
}

void Fingerprint::set_handlers(const FingerprintHandlers &handlers) {
  handlers_ = handlers;
  if (!init_called_ && handlers_.on_init) {
    handlers_.on_init(this);
    init_called_ = true;
  }
}

bool Fingerprint::start() noexcept {
  try {
    if (worker_thread_.joinable()) {
      if (is_running_.load()) {
        return false;
      }
      worker_thread_.join();
    }

    // Drain cancel pipe
    if (cancel_pipe_[0] >= 0) {
      char dump[64];
      struct timeval tv = {0, 0};
      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(cancel_pipe_[0], &rfds);
      while (select(cancel_pipe_[0] + 1, &rfds, nullptr, nullptr, &tv) > 0) {
        if (read(cancel_pipe_[0], dump, sizeof(dump)) <= 0)
          break;
      }
    }

    is_running_.store(true);
    check_in_progress_.store(false);

    if (handlers_.on_start) {
      handlers_.on_start(this);
    }

    worker_thread_ = std::jthread([this]() { run_worker(); });
    return true;
  } catch (...) {
    is_running_.store(false);
    return false;
  }
}

void Fingerprint::stop() noexcept {
  bool expected = true;
  if (is_running_.compare_exchange_strong(expected, false)) {
    if (cancel_pipe_[1] >= 0) {
      char dummy = 'x';
      (void)write(cancel_pipe_[1], &dummy, 1);
    }
  }

  expected = true;
  if (check_in_progress_.compare_exchange_strong(expected, false)) {
    if (handlers_.on_end) {
      handlers_.on_end(this);
    }
    if (handlers_.on_stop) {
      handlers_.on_stop(this);
    }
  }
}

bool Fingerprint::is_running() const noexcept { return is_running_.load(); }

void *Fingerprint::get_user_data() const noexcept { return user_data_; }

void Fingerprint::set_user_data(void *data) noexcept { user_data_ = data; }

const std::string &Fingerprint::get_username() const noexcept {
  return username_;
}

int Fingerprint::fprint_signal_cb(sd_bus_message *m, void *userdata,
                                  sd_bus_error * /*ret_error*/) {
  auto *self = static_cast<Fingerprint *>(userdata);
  if (!self)
    return 0;

  const char *result = nullptr;
  int done = 0;
  if (sd_bus_message_read(m, "sb", &result, &done) >= 0 && result) {
    if (std::strcmp(result, "verify-match") == 0) {
      if (self->handlers_.on_finish)
        self->handlers_.on_finish(self);
    } else if (std::strcmp(result, "verify-no-match") == 0) {
      if (self->handlers_.on_error)
        self->handlers_.on_error(self, FingerprintError::NotMatch,
                                 "Fingerprint did not match");
    } else {
      if (self->handlers_.on_error)
        self->handlers_.on_error(self, FingerprintError::System,
                                 "Internal sensor error");
    }

    if (done) {
      bool expected = true;
      if (self->check_in_progress_.compare_exchange_strong(expected, false)) {
        if (self->handlers_.on_end)
          self->handlers_.on_end(self);
      }
    }
  }
  return 0;
}

void Fingerprint::run_worker() {
  sd_bus_error error = SD_BUS_ERROR_NULL;
  sd_bus_message *reply = nullptr;

  while (is_running_.load()) {
    if (!bus_ || device_path_.empty()) {
      if (handlers_.on_error) {
        handlers_.on_error(this, FingerprintError::NotFound,
                           "D-Bus or device not found");
      }
      break;
    }

    int r =
        sd_bus_call_method(bus_, "net.reactivated.Fprint", device_path_.c_str(),
                           "net.reactivated.Fprint.Device", "VerifyStart",
                           &error, &reply, "s", "any");
    if (r < 0) {
      if (handlers_.on_error) {
        handlers_.on_error(this, FingerprintError::System,
                           error.message ? error.message
                                         : "Failed to start scanning");
      }
      sd_bus_error_free(&error);
      break;
    }
    sd_bus_error_free(&error);
    if (reply) {
      sd_bus_message_unref(reply);
      reply = nullptr;
    }

    check_in_progress_.store(true);
    if (handlers_.on_loop) {
      handlers_.on_loop(this);
    }

    while (is_running_.load() && check_in_progress_.load()) {
      r = sd_bus_process(bus_, nullptr);
      if (r < 0)
        break;
      if (r > 0)
        continue;

      if (cancel_pipe_[0] >= 0) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(cancel_pipe_[0], &rfds);
        struct timeval tv = {0, 50000};
        select(cancel_pipe_[0] + 1, &rfds, nullptr, nullptr, &tv);
      } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
    }

    sd_bus_call_method(bus_, "net.reactivated.Fprint", device_path_.c_str(),
                       "net.reactivated.Fprint.Device", "VerifyStop", nullptr,
                       nullptr, "");

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

} // namespace auth
