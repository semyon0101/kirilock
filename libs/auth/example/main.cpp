#include "auth/fingerprint.hpp"
#include "auth/password.hpp"

#include <atomic>
#include <csignal>
#include <cstring>
#include <iostream>
#include <print>
#include <pwd.h>
#include <string>
#include <string_view>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#include <vector>

#ifndef NDEBUG
#ifdef __GLIBC__
extern "C" void __libc_freeres(void);
#endif
#endif

namespace {

constexpr size_t MAX_PASS_LEN = 512;
volatile sig_atomic_t g_interrupted = 0;
struct termios g_orig_termios;
bool g_termios_saved = false;

void global_sig_handler(int) {
    g_interrupted = 1;
}

void restore_tty() {
    if (g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_orig_termios);
    }
}

void console_input_start() {
    tcgetattr(STDIN_FILENO, &g_orig_termios);
    g_termios_saved = true;
    std::atexit(restore_tty);

    struct termios raw = g_orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
}

std::string get_current_username() {
    uid_t uid = getuid();
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1)
        bufsize = 16384;

    std::vector<char> pw_buf(static_cast<size_t>(bufsize));
    struct passwd pw_struct{};
    struct passwd* pw = nullptr;
    getpwuid_r(uid, &pw_struct, pw_buf.data(), pw_buf.size(), &pw);

    std::string username = (pw && pw->pw_name) ? pw->pw_name : "unknown";
    explicit_bzero(pw_buf.data(), pw_buf.size());
    endpwent();
    return username;
}

struct AuthCoordinator {
    auth::Fingerprint* fp{nullptr};
    auth::Password* pw{nullptr};
    std::atomic<bool> authenticated{false};
};

} // anonymous namespace

int main() {
    struct sigaction sa{};
    sa.sa_handler = global_sig_handler;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    std::string username = get_current_username();

    AuthCoordinator coord;

    auth::Fingerprint fp(username, &coord);
    auth::Password pw(username, &coord);

    coord.fp = &fp;
    coord.pw = &pw;

    auth::FingerprintHandlers fp_handlers{
        .on_init = [](auth::Fingerprint*) {
            std::println("[FP] on_init: Scanner hardware subsystem created.");
        },
        .on_start = [](auth::Fingerprint*) {
            std::println("[FP] on_start: Start looping fingerprint verification.");
        },
        .on_loop = [](auth::Fingerprint*) {
            std::println("[FP] on_loop: Place your finger on the scanner...");
        },
        .on_finish = [](auth::Fingerprint* ctx) {
            auto* coord = static_cast<AuthCoordinator*>(ctx->get_user_data());
            bool expected = false;
            if (coord->authenticated.compare_exchange_strong(expected, true)) {
                std::println("\n[FP] on_finish: Fingerprint match verified!");
                coord->pw->stop();
                ctx->stop();
            }
        },
        .on_error = [](auth::Fingerprint* ctx, auth::FingerprintError err, std::string_view msg) {
            std::println("\n[FP] on_error (code {}): {}", static_cast<int>(err), msg);
            if (err == auth::FingerprintError::NotFound) {
                std::println("[FP] Sensor unavailable. Disabling scanner module...");
                ctx->stop();
            }
        },
        .on_end = [](auth::Fingerprint*) {
            std::println("[FP] on_end: Scanning session terminated.");
        },
        .on_stop = [](auth::Fingerprint*) {
            std::println("[FP] on_stop: Stop fingerprint verification.");
        },
        .on_delete = [](auth::Fingerprint*) {
            std::println("[FP] on_delete: Structures destroyed.");
        }
    };
    fp.set_handlers(fp_handlers);

    auth::PasswordHandlers pw_handlers{
        .on_init = [](auth::Password*) {
            std::println("[PW] on_init: PAM password subsystem created.");
        },
        .on_begin = [](auth::Password*) {
            std::print("[PW] on_begin: Asynchronous hash verification via PAM...\n");
            std::fflush(stdout);
        },
        .on_finish = [](auth::Password* ctx) {
            auto* coord = static_cast<AuthCoordinator*>(ctx->get_user_data());
            bool expected = false;
            if (coord->authenticated.compare_exchange_strong(expected, true)) {
                std::println("\n[PW] on_finish: Password verified!");
                coord->fp->stop();
                ctx->stop();
            }
        },
        .on_error = [](auth::Password*, auth::PasswordError err, std::string_view msg) {
            std::println("\n[PW] on_error (code {}): {}", static_cast<int>(err), msg);
            std::print("\n[MAIN] Enter password (hidden):\n");
            std::fflush(stdout);
        },
        .on_end = [](auth::Password*) {
            std::println("[PW] on_end: Password verification thread finished.");
        },
        .on_stop = [](auth::Password*) {
            std::println("[PW] on_stop: Stop password verification.");
        },
        .on_delete = [](auth::Password*) {
            std::println("[PW] on_delete: Structures destroyed.");
        }
    };
    pw.set_handlers(pw_handlers);

    console_input_start();
    if (!fp.start()) {
        std::println("[MAIN] Fingerprint module failed to start.");
    }

    std::println("\n[MAIN] Waiting for hardware fingerprint scan OR enter your PAM password:");
    std::print("\n[MAIN] Enter password (hidden):\n");
    std::fflush(stdout);

    std::string pass_buf;
    pass_buf.reserve(MAX_PASS_LEN);

    while (!coord.authenticated.load() && !g_interrupted) {
        if (!fp.is_running() && !pw.is_running()) {
            break;
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);

        struct timeval tv = {0, 50000};
        int res = select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv);

        if (res > 0 && FD_ISSET(STDIN_FILENO, &fds)) {
            char c = 0;
            if (read(STDIN_FILENO, &c, 1) > 0) {
                if (c == '\n' || c == '\r') {
                    if (!pass_buf.empty()) {
                        pw.verify(pass_buf);
                        explicit_bzero(pass_buf.data(), pass_buf.size());
                        pass_buf.clear();
                    }
                } else if (c == 127 || c == '\b') {
                    if (!pass_buf.empty()) {
                        pass_buf.pop_back();
                    }
                } else if (c >= 32 && c <= 126) {
                    if (pass_buf.size() < MAX_PASS_LEN - 1) {
                        pass_buf.push_back(c);
                    }
                }
            }
        }
    }

    if (!pass_buf.empty()) {
        explicit_bzero(pass_buf.data(), pass_buf.size());
        pass_buf.clear();
    }

    fp.stop();
    pw.stop();

#ifndef NDEBUG
#ifdef __GLIBC__
    __libc_freeres();
#endif
#endif

    std::println("\n[MAIN] Coordinator cleanly exited hardware monitoring scope.");

    bool is_auth = coord.authenticated.load();
    if (is_auth) {
        std::println("\n>>> ACCESS GRANTED <<<");
    } else {
        std::println("\n>>> ACCESS DENIED <<<");
    }

    return is_auth ? 0 : 1;
}
