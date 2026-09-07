#define _GNU_SOURCE
#include "auth/password.h"
#include <pthread.h>
#include <security/pam_appl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef NDEBUG
#ifdef __GLIBC__
extern void __libc_freeres(void);
#endif
#endif

struct kl_password_ctx {
  kl_password_handlers_t handlers;
  void *user_data;
  char *username;

  pthread_t thread;
  bool has_thread;
  bool init_called;

  atomic_bool is_running;
  atomic_int active_pam_pid;

  char *candidate;
};

static void secure_clear(void *v, size_t n) {
  volatile unsigned char *p = (volatile unsigned char *)v;
  while (n--)
    *p++ = 0;
}

static int internal_pam_conv(int num_msg, const struct pam_message **msg,
                             struct pam_response **resp, void *appdata_ptr) {
  if (num_msg <= 0 || !resp || !appdata_ptr)
    return PAM_CONV_ERR;
  struct pam_response *reply =
      calloc((size_t)num_msg, sizeof(struct pam_response));
  if (!reply)
    return PAM_BUF_ERR;
  for (int i = 0; i < num_msg; ++i) {
    if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
        msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
      reply[i].resp = strdup((const char *)appdata_ptr);
      if (!reply[i].resp) {
        while (i > 0) {
          free(reply[--i].resp);
        }
        free(reply);
        return PAM_BUF_ERR;
      }
      reply[i].resp_retcode = 0;
    }
  }
  *resp = reply;
  return PAM_SUCCESS;
}

static void *pw_worker(void *arg) {
  kl_password_ctx_t *ctx = arg;

  if (ctx->handlers.on_begin)
    ctx->handlers.on_begin(ctx);

  pid_t pid = fork();
  if (pid < 0) {
    if (ctx->handlers.on_error)
      ctx->handlers.on_error(ctx, PW_ERR_SYSTEM, "fork() failed");
    goto cleanup;
  }

  if (pid == 0) {
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = {internal_pam_conv, ctx->candidate};
    int ret = pam_start("system-auth", ctx->username, &conv, &pamh);
    if (ret == PAM_SUCCESS) {
      ret = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
      if (ret == PAM_SUCCESS)
        ret = pam_acct_mgmt(pamh, 0);
    }
    pam_end(pamh, ret);

    secure_clear(ctx->candidate, strlen(ctx->candidate));
    free(ctx->candidate);
    free(ctx->username);
#ifndef NDEBUG
#ifdef __GLIBC__
    __libc_freeres();
#endif
#endif
    _exit(ret == PAM_SUCCESS ? 0 : 1);
  }

  atomic_store(&ctx->active_pam_pid, pid);

  if (!atomic_load(&ctx->is_running)) {
    pid_t to_kill = atomic_exchange(&ctx->active_pam_pid, 0);
    if (to_kill > 0) {
      kill(to_kill, SIGKILL);
    }
  }

  int status;
  waitpid(pid, &status, 0);
  atomic_store(&ctx->active_pam_pid, 0);

  if (atomic_load(&ctx->is_running)) {
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
      if (ctx->handlers.on_finish)
        ctx->handlers.on_finish(ctx);
    } else {
      if (ctx->handlers.on_error)
        ctx->handlers.on_error(ctx, PW_ERR_AUTH_FAILED,
                               "Invalid password or access denied");
    }
  }

cleanup:
  if (ctx->handlers.on_end)
    ctx->handlers.on_end(ctx);

  if (!atomic_load(&ctx->is_running)) {
    if (ctx->handlers.on_stop)
      ctx->handlers.on_stop(ctx);
  }

  if (ctx->candidate) {
    explicit_bzero(ctx->candidate, strlen(ctx->candidate));
    free(ctx->candidate);
    ctx->candidate = NULL;
  }

  atomic_store(&ctx->is_running, false);
  return NULL;
}

kl_password_ctx_t *kl_password_init(void *user_data, const char *username) {
  kl_password_ctx_t *ctx = calloc(1, sizeof(*ctx));
  if (!ctx)
    return NULL;

  ctx->user_data = user_data;
  ctx->username = username ? strdup(username) : NULL;
  if (username && !ctx->username) {
    free(ctx);
    return NULL;
  }

  atomic_init(&ctx->is_running, false);
  ctx->has_thread = false;
  return ctx;
}

void kl_password_set_handlers(kl_password_ctx_t *ctx,
                           const kl_password_handlers_t *handlers) {
  if (ctx && handlers) {
    ctx->handlers = *handlers;
    if (!ctx->init_called && ctx->handlers.on_init) {
      ctx->handlers.on_init(ctx);
      ctx->init_called = true;
    }
  }
}

int kl_password_verify(kl_password_ctx_t *ctx, const char *password) {
  if (!ctx || !password)
    return -1;

  bool expected = false;
  if (!atomic_compare_exchange_strong(&ctx->is_running, &expected, true))
    return -1;

  if (ctx->has_thread) {
    pthread_join(ctx->thread, NULL);
    ctx->has_thread = false;
  }

  ctx->candidate = strdup(password);
  if (!ctx->candidate) {
    atomic_store(&ctx->is_running, false);
    return -1;
  }

  ctx->has_thread = true;

  if (pthread_create(&ctx->thread, NULL, pw_worker, ctx) != 0) {
    ctx->has_thread = false;
    atomic_store(&ctx->is_running, false);
    explicit_bzero(ctx->candidate, strlen(ctx->candidate));
    free(ctx->candidate);
    ctx->candidate = NULL;
    return -1;
  }

  return 0;
}

void kl_password_stop(kl_password_ctx_t *ctx) {
  if (!ctx)
    return;
  bool expected = true;
  if (!atomic_compare_exchange_strong(&ctx->is_running, &expected, false))
    return;

  pid_t pam_pid = atomic_exchange(&ctx->active_pam_pid, 0);
  if (pam_pid > 0) {
    kill(pam_pid, SIGKILL);
  }

  /* Removed pthread_join / pthread_detach logic.
     The thread will exit its loop naturally and be reaped by kl_password_delete or
     kl_password_verify. */
}

void kl_password_delete(kl_password_ctx_t *ctx) {
  if (!ctx)
    return;
  kl_password_stop(ctx);

  if (ctx->has_thread) {
    pthread_join(ctx->thread, NULL);
    ctx->has_thread = false;
  }

  if (ctx->candidate) {
    explicit_bzero(ctx->candidate, strlen(ctx->candidate));
    free(ctx->candidate);
  }

  free(ctx->username);
  if (ctx->handlers.on_delete)
    ctx->handlers.on_delete(ctx);
  free(ctx);
}

bool kl_password_is_running(const kl_password_ctx_t *ctx) {
  return ctx ? atomic_load(&ctx->is_running) : false;
}

void *kl_password_get_user_data(const kl_password_ctx_t *ctx) {
  return ctx ? ctx->user_data : NULL;
}
