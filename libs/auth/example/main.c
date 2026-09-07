#define _GNU_SOURCE
#include "auth/fingerprint.h"
#include "auth/password.h"
#include <pwd.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

#define MAX_PASS_LEN 512

#ifndef NDEBUG
#ifdef __GLIBC__
extern void __libc_freeres(void);
#endif
#endif

static volatile sig_atomic_t g_interrupted = 0;
static struct termios g_orig_termios;
static bool g_termios_saved = false;

static void global_sig_handler(int sig) {
  (void)sig;
  g_interrupted = 1;
}

static void restore_tty(void) {
  if (g_termios_saved) {
    tcsetattr(STDIN_FILENO, TCSANOW, &g_orig_termios);
  }
}

typedef struct {
  kl_fingerprint_ctx_t *fp;
  kl_password_ctx_t *pw;
  atomic_bool authenticated;
} auth_coordinator_t;

/* --- Fingerprint Callbacks --- */
void fp_on_init(kl_fingerprint_ctx_t *ctx) {
  (void)ctx;
  printf("[FP] on_init: Scanner hardware subsystem created.\n");
}
void fp_on_start(kl_fingerprint_ctx_t *ctx){
  (void)ctx;
  printf("[FP] on_start: Start looping fingerprint verification.\n");
}
void fp_on_loop(kl_fingerprint_ctx_t *ctx) {
  (void)ctx;
  printf("[FP] on_loop: Place your finger on the scanner...\n");
}
void fp_on_finish(kl_fingerprint_ctx_t *ctx) {
  auth_coordinator_t *coord = kl_fingerprint_get_user_data(ctx);
  bool expected = false;
  if (atomic_compare_exchange_strong(&coord->authenticated, &expected, true)) {
    printf("\n[FP] on_finish: Fingerprint match verified!\n");
    kl_password_stop(coord->pw);
    kl_fingerprint_stop(ctx);
  }
}
void fp_on_error(kl_fingerprint_ctx_t *ctx, kl_fingerprint_error_t err, const char *msg) {
  (void)ctx;
  printf("\n[FP] on_error (code %d): %s\n", err, msg);

  if ( err == FP_ERR_NOT_FOUND) {
    printf("[FP] Sensor unavailable. Disabling scanner module...\n");
    kl_fingerprint_stop(ctx);
  }
}
void fp_on_end(kl_fingerprint_ctx_t *ctx) {
  (void)ctx;
  printf("[FP] on_end: Scanning session terminated.\n");
}
void fp_on_stop(kl_fingerprint_ctx_t *ctx) {
  (void)ctx;
  printf("[FP] on_stop: Stop fingerprint verification.\n");
}
void fp_on_delete(kl_fingerprint_ctx_t *ctx) {
  (void)ctx;
  printf("[FP] on_delete: Structures destroyed.\n");
}

/* --- Password Callbacks --- */
void pw_on_init(kl_password_ctx_t *ctx) {
  (void)ctx;
  printf("[PW] on_init: PAM password subsystem created.\n");
}
void pw_on_begin(kl_password_ctx_t *ctx) {
  (void)ctx;
  printf("[PW] on_begin: Asynchronous hash verification via PAM...\n");
  fflush(stdout);
}
void pw_on_finish(kl_password_ctx_t *ctx) {
  auth_coordinator_t *coord = kl_password_get_user_data(ctx);
  bool expected = false;
  if (atomic_compare_exchange_strong(&coord->authenticated, &expected, true)) {
    printf("\n[PW] on_finish: Password verified!\n");
    kl_fingerprint_stop(coord->fp);
    kl_password_stop(ctx);
  }
}
void pw_on_error(kl_password_ctx_t *ctx, kl_password_error_t err, const char *msg) {
  (void)ctx;
  printf("\n[PW] on_error (code %d): %s\n", err, msg);
  printf("\n[MAIN] Enter password (hidden):\n");
  fflush(stdout);
}
void pw_on_end(kl_password_ctx_t *ctx) {
  (void)ctx;
  printf("[PW] on_end: Password verification thread finished.\n");
}
void pw_on_stop(kl_password_ctx_t *ctx) {
  (void)ctx;
  printf(("[PW] on_stop: Stop password verification.\n"));
}
void pw_on_delete(kl_password_ctx_t *ctx) {
  (void)ctx;
  printf("[PW] on_delete: Structures destroyed.\n");
}

/* --- Terminal configuration --- */
void console_input_start(void) {
  tcgetattr(STDIN_FILENO, &g_orig_termios);
  g_termios_saved = true;
  atexit(restore_tty);

  struct termios raw = g_orig_termios;
  raw.c_lflag &= ~(ECHO | ICANON);
  tcsetattr(STDIN_FILENO, TCSANOW, &raw);
}

int main(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = global_sig_handler;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  uid_t uid = getuid();
  long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (bufsize == -1)
    bufsize = 16384;
  char *pw_buf = malloc((size_t)bufsize);
  if (!pw_buf)
    return 1;

  struct passwd pw_struct, *pw = NULL;
  getpwuid_r(uid, &pw_struct, pw_buf, (size_t)bufsize, &pw);
  char *username = pw ? strdup(pw->pw_name) : strdup("unknown");
  explicit_bzero(pw_buf, (size_t)bufsize);
  free(pw_buf);
  endpwent();

  if (!username)
    return 1;

  auth_coordinator_t coord;
  atomic_init(&coord.authenticated, false);

  coord.fp = kl_fingerprint_init(&coord, username);
  coord.pw = kl_password_init(&coord, username);
  free(username);

  if (!coord.fp || !coord.pw) {
    kl_fingerprint_delete(coord.fp);
    kl_password_delete(coord.pw);
    return 1;
  }

  kl_fingerprint_handlers_t fp_handlers = {fp_on_init, fp_on_start,  fp_on_loop, fp_on_finish,
                                        fp_on_error, fp_on_end, fp_on_stop,  fp_on_delete};
  kl_fingerprint_set_handlers(coord.fp, &fp_handlers);

  kl_password_handlers_t pw_handlers = {pw_on_init,  pw_on_begin, pw_on_finish,
                                     pw_on_error, pw_on_end, pw_on_stop,  pw_on_delete};
  kl_password_set_handlers(coord.pw, &pw_handlers);

  console_input_start();
  kl_fingerprint_start(coord.fp);

  printf("\n[MAIN] Waiting for hardware fingerprint scan OR enter your PAM "
         "password:\n");
  printf("\n[MAIN] Enter password (hidden):\n");
  fflush(stdout);

  char pass_buf[MAX_PASS_LEN];
  size_t pass_len = 0;

  while (!atomic_load(&coord.authenticated) && !g_interrupted) {

    if (!kl_fingerprint_is_running(coord.fp) && !kl_password_is_running(coord.pw)) {
      break;
    }

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);

    struct timeval tv = {0, 50000};
    int res = select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);

    if (res > 0 && FD_ISSET(STDIN_FILENO, &fds)) {
      char c;
      if (read(STDIN_FILENO, &c, 1) > 0) {
        if (c == '\n' || c == '\r') {
          pass_buf[pass_len] = '\0';
          if (pass_len > 0) {
            kl_password_verify(coord.pw, pass_buf);
            explicit_bzero(pass_buf, pass_len);
            pass_len = 0;
          }
        } else if (c == 127 || c == '\b') {
          if (pass_len > 0) {
            pass_buf[--pass_len] = 0;
          }
        } else if (c >= 32 && c <= 126) {
          if (pass_len < MAX_PASS_LEN - 1)
            pass_buf[pass_len++] = c;
        }
      }
    }
  }

  explicit_bzero(pass_buf, sizeof(pass_buf));

  /* Safe thread join sequence */
  kl_fingerprint_delete(coord.fp);
  kl_password_delete(coord.pw);

#ifndef NDEBUG
#ifdef __GLIBC__
  __libc_freeres();
#endif
#endif

  printf("\n[MAIN] Coordinator cleanly exited hardware monitoring scope.\n");

  bool is_auth = atomic_load(&coord.authenticated);
  if (is_auth) {
    printf("\n>>> ACCESS GRANTED <<<\n");
  } else {
    printf("\n>>> ACCESS DENIED <<<\n");
  }

  return is_auth ? 0 : 1;
}
