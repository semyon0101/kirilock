#define _GNU_SOURCE
#include "auth/fingerprint.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

struct kl_fingerprint_ctx {
  kl_fingerprint_handlers_t handlers;
  void *user_data;
  char *username;

  pthread_t thread;
  bool has_thread;
  bool init_called;

  atomic_bool is_running;
  atomic_bool check_in_progress;
  int cancel_pipe[2];

  sd_bus *bus;
  char *device_path;
  sd_bus_slot *signal_slot;
};

static int fprint_signal_cb(sd_bus_message *m, void *userdata,
                            sd_bus_error *ret_error) {
  (void)ret_error;
  kl_fingerprint_ctx_t *ctx = userdata;
  const char *result = NULL;
  int done = 0;

  if (sd_bus_message_read(m, "sb", &result, &done) >= 0) {
    if (strcmp(result, "verify-match") == 0) {
      if (ctx->handlers.on_finish)
        ctx->handlers.on_finish(ctx);
    } else if (strcmp(result, "verify-no-match") == 0) {
      if (ctx->handlers.on_error)
        ctx->handlers.on_error(ctx, FP_ERR_NOT_MATCH,
                               "Fingerprint did not match");
    } else {
      if (ctx->handlers.on_error)
        ctx->handlers.on_error(ctx, FP_ERR_SYSTEM, "Internal sensor error");
    }

    if (done) {
      bool expected = true;
      if (atomic_compare_exchange_strong(&ctx->check_in_progress, &expected,
                                         false)) {
        if (ctx->handlers.on_end)
          ctx->handlers.on_end(ctx);
      }
    }
  }
  return 0;
}

static void *fp_worker(void *arg) {
  kl_fingerprint_ctx_t *ctx = arg;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  sd_bus_message *reply = NULL;

  while (atomic_load(&ctx->is_running)) {
    if (!ctx->bus || !ctx->device_path) {
      if (ctx->handlers.on_error)
        ctx->handlers.on_error(ctx, FP_ERR_NOT_FOUND,
                               "D-Bus or device not found");
      break;
    }

    int r =
        sd_bus_call_method(ctx->bus, "net.reactivated.Fprint", ctx->device_path,
                           "net.reactivated.Fprint.Device", "VerifyStart",
                           &error, &reply, "s", "any");
    if (r < 0) {
      if (ctx->handlers.on_error)
        ctx->handlers.on_error(ctx, FP_ERR_SYSTEM,
                               error.message ? error.message
                                             : "Failed to start scanning");
      sd_bus_error_free(&error);
      break;
    }
    sd_bus_error_free(&error);
    if (reply)
      sd_bus_message_unref(reply);

    atomic_store(&ctx->check_in_progress, true);
    if (ctx->handlers.on_loop)
      ctx->handlers.on_loop(ctx);

    while (atomic_load(&ctx->is_running) &&
           atomic_load(&ctx->check_in_progress)) {
      r = sd_bus_process(ctx->bus, NULL);
      if (r < 0)
        break;
      if (r > 0)
        continue;

      /* Responsive cancellation using select on custom pipe */
      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(ctx->cancel_pipe[0], &rfds);
      struct timeval tv = {0, 50000};
      select(ctx->cancel_pipe[0] + 1, &rfds, NULL, NULL, &tv);
    }

    sd_bus_call_method(ctx->bus, "net.reactivated.Fprint", ctx->device_path,
                       "net.reactivated.Fprint.Device", "VerifyStop", NULL,
                       NULL, "");

    /* Hardware reset delay before next continuous scan attempt */
    usleep(100000);
  }
  return NULL;
}

kl_fingerprint_ctx_t *kl_fingerprint_init(void *user_data, const char *username) {
  kl_fingerprint_ctx_t *ctx = calloc(1, sizeof(*ctx));
  if (!ctx)
    return NULL;

  ctx->user_data = user_data;
  ctx->username = username ? strdup(username) : NULL;
  if (username && !ctx->username) {
    free(ctx);
    return NULL;
  }

  if (pipe(ctx->cancel_pipe) != 0) {
    free(ctx->username);
    free(ctx);
    return NULL;
  }

  atomic_init(&ctx->is_running, false);
  atomic_init(&ctx->check_in_progress, false);
  ctx->has_thread = false;

  if (sd_bus_open_system(&ctx->bus) >= 0) {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    int r = sd_bus_call_method(ctx->bus, "net.reactivated.Fprint",
                               "/net/reactivated/Fprint/Manager",
                               "net.reactivated.Fprint.Manager",
                               "GetDefaultDevice", &error, &reply, "");
    if (r >= 0) {
      const char *path = NULL;
      if (sd_bus_message_read(reply, "o", &path) >= 0) {
        ctx->device_path = strdup(path);
      }
      sd_bus_message_unref(reply);

      if (ctx->device_path) {
        sd_bus_call_method(ctx->bus, "net.reactivated.Fprint", ctx->device_path,
                           "net.reactivated.Fprint.Device", "Claim", NULL, NULL,
                           "s", ctx->username);

        sd_bus_match_signal(ctx->bus, &ctx->signal_slot,
                            "net.reactivated.Fprint", ctx->device_path,
                            "net.reactivated.Fprint.Device", "VerifyStatus",
                            fprint_signal_cb, ctx);
      }
    }
    sd_bus_error_free(&error);
  }
  return ctx;
}

void kl_fingerprint_set_handlers(kl_fingerprint_ctx_t *ctx,
                              const kl_fingerprint_handlers_t *handlers) {
  if (ctx && handlers) {
    ctx->handlers = *handlers;
    if (!ctx->init_called && ctx->handlers.on_init) {
      ctx->handlers.on_init(ctx);
      ctx->init_called = true;
    }
  }
}

int kl_fingerprint_start(kl_fingerprint_ctx_t *ctx) {
  if (!ctx || ctx->has_thread)
    return -1;

  /* Drain cancel pipe */
  char dump[64];
  struct timeval tv = {0, 0};
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(ctx->cancel_pipe[0], &rfds);
  while (select(ctx->cancel_pipe[0] + 1, &rfds, NULL, NULL, &tv) > 0) {
    if (read(ctx->cancel_pipe[0], dump, sizeof(dump)) <= 0)
      break;
  }

  atomic_store(&ctx->is_running, true);
  atomic_store(&ctx->check_in_progress, false);

  if (ctx->handlers.on_start)
    ctx->handlers.on_start(ctx);

  if (pthread_create(&ctx->thread, NULL, fp_worker, ctx) != 0) {
    atomic_store(&ctx->is_running, false);
    return -1;
  }

  ctx->has_thread = true;
  return 0;
}

void kl_fingerprint_stop(kl_fingerprint_ctx_t *ctx) {
  if (!ctx)
    return;
  bool expected = true;
  if (atomic_compare_exchange_strong(&ctx->is_running, &expected, false)) {
    if (write(ctx->cancel_pipe[1], "x", 1) < 0) { /* ignore */
    }
  }

  expected = true;
  if (atomic_compare_exchange_strong(&ctx->check_in_progress, &expected,
                                     false)) {
    if (ctx->handlers.on_end)
      ctx->handlers.on_end(ctx);
    if (ctx->handlers.on_stop)
      ctx->handlers.on_stop(ctx);
  }

  /* Removed pthread_join / pthread_detach logic.
     The thread will exit its loop naturally and be reaped by kl_fingerprint_delete
     or kl_fingerprint_start. */
}

void kl_fingerprint_delete(kl_fingerprint_ctx_t *ctx) {
  if (!ctx)
    return;
  kl_fingerprint_stop(ctx);

  if (ctx->has_thread) {
    pthread_join(ctx->thread, NULL);
    ctx->has_thread = false;
  }

  if (ctx->bus && ctx->device_path) {
    sd_bus_call_method(ctx->bus, "net.reactivated.Fprint", ctx->device_path,
                       "net.reactivated.Fprint.Device", "Release", NULL, NULL,
                       "");
  }
  if (ctx->signal_slot)
    sd_bus_slot_unref(ctx->signal_slot);
  if (ctx->bus)
    sd_bus_flush_close_unref(ctx->bus);

  free(ctx->device_path);
  free(ctx->username);

  close(ctx->cancel_pipe[0]);
  close(ctx->cancel_pipe[1]);

  if (ctx->handlers.on_delete)
    ctx->handlers.on_delete(ctx);
  free(ctx);
}

bool kl_fingerprint_is_running(const kl_fingerprint_ctx_t *ctx) {
  return ctx ? atomic_load(&ctx->is_running) : false;
}

void *kl_fingerprint_get_user_data(const kl_fingerprint_ctx_t *ctx) {
  return ctx ? ctx->user_data : NULL;
}
