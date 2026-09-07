#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include "lock.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static void kl_lock_handle_locked(void *data,
                                  struct ext_session_lock_v1 *lock) {
  (void)lock;
  if (!data) {
    return;
  }
  struct kl_context *ctx = (struct kl_context *)data;
  ctx->is_locked = true;
}

static void kl_lock_handle_finished(void *data,
                                    struct ext_session_lock_v1 *lock) {
  (void)lock;
  if (!data) {
    return;
  }
  struct kl_context *ctx = (struct kl_context *)data;
  ctx->is_finished = true;
  fprintf(stderr, "Session lock finished event received\n");
}

static const struct ext_session_lock_v1_listener kl_lock_listener = {
    .locked = kl_lock_handle_locked,
    .finished = kl_lock_handle_finished,
};

static void kl_registry_handle_global(void *data, struct wl_registry *registry,
                                      uint32_t name, const char *interface,
                                      uint32_t version) {
  (void)version;
  if (!data || !registry || !interface) {
    return;
  }

  struct kl_context *ctx = (struct kl_context *)data;

  if (strcmp(interface, wl_output_interface.name) == 0) {
    struct wl_output *output = (struct wl_output *)wl_registry_bind(
        registry, name, &wl_output_interface, 3);
    if (!output) {
      fprintf(stderr, "Failed to bind wl_output\n");
      ctx->failed = true;
      return;
    }

    struct kl_surface *surf = kl_surface_create(ctx, output, name);
    if (!surf) {
      if (wl_output_get_version(output) >= WL_OUTPUT_RELEASE_SINCE_VERSION) {
        wl_output_release(output);
      } else {
        wl_output_destroy(output);
      }
      ctx->failed = true;
      return;
    }
    wl_list_insert(&ctx->surfaces, &surf->link);

    // Hotplug attachment if session is already actively locked
    if (ctx->lock && !ctx->is_finished) {
      if (kl_surface_attach_lock(surf) < 0) {
        fprintf(stderr,
                "Failed to attach hotplugged output to active session lock\n");
      }
      wl_display_flush(ctx->display);
    }
  } else if (strcmp(interface, wl_compositor_interface.name) == 0) {
    ctx->compositor = (struct wl_compositor *)wl_registry_bind(
        registry, name, &wl_compositor_interface, 4);
    if (!ctx->compositor) {
      fprintf(stderr, "Failed to bind wl_compositor interface\n");
      ctx->failed = true;
    }
  } else if (strcmp(interface, wl_shm_interface.name) == 0) {
    ctx->shm =
        (struct wl_shm *)wl_registry_bind(registry, name, &wl_shm_interface, 1);
    if (!ctx->shm) {
      fprintf(stderr, "Failed to bind wl_shm interface\n");
      ctx->failed = true;
    }
  } else if (strcmp(interface, ext_session_lock_manager_v1_interface.name) ==
             0) {
    ctx->lock_manager = (struct ext_session_lock_manager_v1 *)wl_registry_bind(
        registry, name, &ext_session_lock_manager_v1_interface, 1);
    if (!ctx->lock_manager) {
      fprintf(stderr, "Failed to bind ext_session_lock_manager_v1 interface\n");
      ctx->failed = true;
    }
  }
}

static void kl_registry_handle_global_remove(void *data,
                                             struct wl_registry *registry,
                                             uint32_t name) {
  (void)registry;
  if (!data) {
    return;
  }

  struct kl_context *ctx = (struct kl_context *)data;
  struct kl_surface *surf = NULL;
  struct kl_surface *tmp = NULL;

  wl_list_for_each_safe(surf, tmp, &ctx->surfaces, link) {
    if (surf->global_name == name) {
      wl_list_remove(&surf->link);
      kl_surface_destroy(surf);
      break;
    }
  }
}

static const struct wl_registry_listener kl_registry_listener = {
    .global = kl_registry_handle_global,
    .global_remove = kl_registry_handle_global_remove,
};

int kl_context_init(struct kl_context *ctx) {
  if (!ctx) {
    return -1;
  }
  memset(ctx, 0, sizeof(*ctx));
  wl_list_init(&ctx->surfaces);

  ctx->display = wl_display_connect(NULL);
  if (!ctx->display) {
    fprintf(stderr, "Failed to connect to Wayland display: %s\n",
            strerror(errno));
    kl_context_destroy(ctx);
    return -1;
  }

  ctx->registry = wl_display_get_registry(ctx->display);
  if (!ctx->registry) {
    fprintf(stderr, "Failed to get Wayland registry\n");
    kl_context_destroy(ctx);
    return -1;
  }

  if (wl_registry_add_listener(ctx->registry, &kl_registry_listener, ctx) < 0) {
    fprintf(stderr, "Failed to add registry listener\n");
    kl_context_destroy(ctx);
    return -1;
  }

  if (wl_display_roundtrip(ctx->display) == -1 || ctx->failed) {
    fprintf(stderr, "Initial registry roundtrip failed\n");
    kl_context_destroy(ctx);
    return -1;
  }

  if (!ctx->compositor || !ctx->shm || !ctx->lock_manager) {
    fprintf(stderr, "Missing required Wayland interfaces\n");
    kl_context_destroy(ctx);
    return -1;
  }

  if (wl_list_empty(&ctx->surfaces)) {
    fprintf(stderr, "No outputs found to lock\n");
    kl_context_destroy(ctx);
    return -1;
  }

  return 0;
}

int kl_context_lock_session(struct kl_context *ctx) {
  if (!ctx || !ctx->lock_manager || !ctx->compositor) {
    return -1;
  }

  if (wl_list_empty(&ctx->surfaces)) {
    fprintf(stderr, "Cannot lock session: surface list is empty\n");
    return -1;
  }

  ctx->lock = ext_session_lock_manager_v1_lock(ctx->lock_manager);
  if (!ctx->lock) {
    fprintf(stderr, "Failed to acquire ext_session_lock_v1\n");
    return -1;
  }

  if (ext_session_lock_v1_add_listener(ctx->lock, &kl_lock_listener, ctx) < 0) {
    fprintf(stderr, "Failed to add session lock listener\n");
    return -1;
  }

  struct kl_surface *surf = NULL;
  wl_list_for_each(surf, &ctx->surfaces, link) {
    if (kl_surface_attach_lock(surf) < 0) {
      return -1;
    }
  }

  while (!ctx->is_locked && !ctx->is_finished) {
    if (wl_display_dispatch(ctx->display) == -1) {
      fprintf(stderr, "Fatal dispatch error during session lock acquisition\n");
      return -1;
    }
  }

  if (wl_display_flush(ctx->display) < 0 && errno != EAGAIN) {
    perror("wl_display_flush failed after locking session");
    return -1;
  }

  return ctx->is_locked ? 0 : -1;
}

int kl_context_unlock_session(struct kl_context *ctx) {
  if (!ctx) {
    return -1;
  }
  if (!ctx->lock || !ctx->is_locked || ctx->is_finished) {
    fprintf(stderr, "Cannot unlock: session is not actively locked\n");
    return -1;
  }

  struct kl_surface *surf = NULL;
  wl_list_for_each(surf, &ctx->surfaces, link) { kl_surface_detach_lock(surf); }

  ext_session_lock_v1_unlock_and_destroy(ctx->lock);
  ctx->lock = NULL;
  ctx->is_locked = false;
  ctx->is_finished = false;

  if (wl_display_roundtrip(ctx->display) == -1) {
    fprintf(stderr, "Roundtrip failed after unlocking session\n");
    return -1;
  }

  return 0;
}

void kl_context_destroy(struct kl_context *ctx) {
  if (!ctx) {
    return;
  }

  struct kl_surface *surf = NULL;
  struct kl_surface *tmp = NULL;
  wl_list_for_each_safe(surf, tmp, &ctx->surfaces, link) {
    wl_list_remove(&surf->link);
    kl_surface_destroy(surf);
  }

  if (ctx->lock) {
    if (ctx->is_locked && !ctx->is_finished) {
      ext_session_lock_v1_unlock_and_destroy(ctx->lock);
    } else {
      ext_session_lock_v1_destroy(ctx->lock);
    }
    ctx->lock = NULL;
  }

  if (ctx->lock_manager) {
    ext_session_lock_manager_v1_destroy(ctx->lock_manager);
    ctx->lock_manager = NULL;
  }

  if (ctx->shm) {
    wl_shm_destroy(ctx->shm);
    ctx->shm = NULL;
  }

  if (ctx->compositor) {
    wl_compositor_destroy(ctx->compositor);
    ctx->compositor = NULL;
  }

  if (ctx->registry) {
    wl_registry_destroy(ctx->registry);
    ctx->registry = NULL;
  }

  if (ctx->display) {
    wl_display_roundtrip(ctx->display);
    wl_display_disconnect(ctx->display);
    ctx->display = NULL;
  }

  ctx->is_locked = false;
  ctx->is_finished = false;
  ctx->failed = false;
}
