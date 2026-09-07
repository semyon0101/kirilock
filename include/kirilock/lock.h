#ifndef KIRILOCK_LOCK_H
#define KIRILOCK_LOCK_H

#include <stdbool.h>
#include <stdint.h>
#include <wayland-client.h>

#include "session-lock-client-protocol.h"
#include "surface.h"

struct kl_context {
  struct wl_display *display;
  struct wl_registry *registry;
  struct wl_compositor *compositor;
  struct wl_shm *shm;
  struct ext_session_lock_manager_v1 *lock_manager;
  struct ext_session_lock_v1 *lock;

  struct wl_list surfaces;

  bool is_locked;
  bool is_finished;
  bool failed;
};

int kl_context_init(struct kl_context *ctx);
int kl_context_lock_session(struct kl_context *ctx);
int kl_context_unlock_session(struct kl_context *ctx);
void kl_context_destroy(struct kl_context *ctx);

#endif /* KIRILOCK_LOCK_H */
