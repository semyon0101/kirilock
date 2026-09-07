#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include "surface.h"
#include "lock.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define KL_NS_PER_SEC 1000000000L

static uint64_t kl_get_time_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * KL_NS_PER_SEC + (uint64_t)ts.tv_nsec;
}

static void kl_surface_render_frame(struct kl_surface *surf);

static void kl_output_handle_geometry(void *data, struct wl_output *wl_output,
                                      int32_t x, int32_t y,
                                      int32_t physical_width,
                                      int32_t physical_height, int32_t subpixel,
                                      const char *make, const char *model,
                                      int32_t transform) {
  (void)data;
  (void)wl_output;
  (void)x;
  (void)y;
  (void)physical_width;
  (void)physical_height;
  (void)subpixel;
  (void)make;
  (void)model;
  (void)transform;
}

static void kl_output_handle_mode(void *data, struct wl_output *wl_output,
                                  uint32_t flags, int32_t width, int32_t height,
                                  int32_t refresh) {
  (void)data;
  (void)wl_output;
  (void)flags;
  (void)width;
  (void)height;
  (void)refresh;
}

static void kl_output_handle_done(void *data, struct wl_output *wl_output) {
  (void)data;
  (void)wl_output;
}

static void kl_output_handle_scale(void *data, struct wl_output *wl_output,
                                   int32_t factor) {
  (void)wl_output;
  struct kl_surface *surf = (struct kl_surface *)data;
  if (surf && factor > 0 && surf->scale != factor) {
    surf->scale = factor;
    surf->dirty = true;
    kl_surface_request_render(surf);
  }
}

static const struct wl_output_listener kl_output_listener = {
    .geometry = kl_output_handle_geometry,
    .mode = kl_output_handle_mode,
    .done = kl_output_handle_done,
    .scale = kl_output_handle_scale,
};

static void kl_surface_frame_handle_done(void *data,
                                         struct wl_callback *callback,
                                         uint32_t time) {
  (void)time;
  if (!data) {
    if (callback) {
      wl_callback_destroy(callback);
    }
    return;
  }

  struct kl_surface *surf = (struct kl_surface *)data;

  if (callback) {
    wl_callback_destroy(callback);
  }
  surf->frame_callback = NULL;
  surf->frame_pending = false;

  // VSync Animation Loop
  kl_surface_render_frame(surf);
}

static const struct wl_callback_listener kl_frame_listener = {
    .done = kl_surface_frame_handle_done,
};

static void kl_surface_on_buffer_release(struct kl_buffer *buf,
                                         void *user_data) {
  (void)buf;
  struct kl_surface *surf = (struct kl_surface *)user_data;
  if (surf && surf->dirty && !surf->frame_pending && surf->configured) {
    kl_surface_render_frame(surf);
  }
}

static struct kl_buffer *kl_surface_get_free_buffer(struct kl_surface *surf) {
  for (int i = 0; i < KL_SURFACE_BUFFER_COUNT; ++i) {
    int idx = (surf->current_buffer + 1 + i) % KL_SURFACE_BUFFER_COUNT;
    if (!surf->buffers[idx].busy) {
      surf->current_buffer = idx;
      return &surf->buffers[idx];
    }
  }
  return NULL;
}

struct kl_surface *kl_surface_create(struct kl_context *ctx,
                                     struct wl_output *output, uint32_t name) {
  if (!ctx || !output) {
    return NULL;
  }

  struct kl_surface *surf =
      (struct kl_surface *)calloc(1, sizeof(struct kl_surface));
  if (!surf) {
    perror("calloc kl_surface failed");
    return NULL;
  }

  surf->engine = kl_render_engine_create();
  if (!surf->engine) {
    free(surf);
    return NULL;
  }

  surf->global_name = name;
  surf->ctx = ctx;
  surf->scale = 1;
  surf->wl_output = output;
  surf->dirty = true;

  wl_output_add_listener(surf->wl_output, &kl_output_listener, surf);
  return surf;
}

static void kl_lock_surface_handle_configure(
    void *data, struct ext_session_lock_surface_v1 *ext_surface,
    uint32_t serial, uint32_t width, uint32_t height) {
  if (!data || !ext_surface) {
    return;
  }

  struct kl_surface *surf = (struct kl_surface *)data;
  surf->width = width;
  surf->height = height;

  ext_session_lock_surface_v1_ack_configure(ext_surface, serial);
  surf->configured = true;

  kl_surface_request_render(surf);
}

static const struct ext_session_lock_surface_v1_listener
    kl_lock_surface_listener = {
        .configure = kl_lock_surface_handle_configure,
};

int kl_surface_attach_lock(struct kl_surface *surf) {
  if (!surf || !surf->ctx || !surf->ctx->lock || !surf->ctx->compositor) {
    return -1;
  }

  if (surf->ext_lock_surface) {
    return 0;
  }

  surf->wl_surface = wl_compositor_create_surface(surf->ctx->compositor);
  if (!surf->wl_surface) {
    fprintf(stderr, "Failed to create surface for output %u\n",
            surf->global_name);
    return -1;
  }

  surf->ext_lock_surface = ext_session_lock_v1_get_lock_surface(
      surf->ctx->lock, surf->wl_surface, surf->wl_output);
  if (!surf->ext_lock_surface) {
    fprintf(stderr, "Failed to get lock surface for output %u\n",
            surf->global_name);
    wl_surface_destroy(surf->wl_surface);
    surf->wl_surface = NULL;
    return -1;
  }

  if (ext_session_lock_surface_v1_add_listener(
          surf->ext_lock_surface, &kl_lock_surface_listener, surf) < 0) {
    fprintf(stderr, "Failed to add lock surface listener for output %u\n",
            surf->global_name);
    return -1;
  }

  return 0;
}

void kl_surface_detach_lock(struct kl_surface *surf) {
  if (!surf) {
    return;
  }

  if (surf->frame_callback) {
    wl_callback_destroy(surf->frame_callback);
    surf->frame_callback = NULL;
  }

  for (int i = 0; i < KL_SURFACE_BUFFER_COUNT; ++i) {
    kl_buffer_destroy(&surf->buffers[i]);
  }

  if (surf->ext_lock_surface) {
    ext_session_lock_surface_v1_destroy(surf->ext_lock_surface);
    surf->ext_lock_surface = NULL;
  }

  if (surf->wl_surface) {
    wl_surface_destroy(surf->wl_surface);
    surf->wl_surface = NULL;
  }

  surf->configured = false;
  surf->frame_pending = false;
  surf->dirty = true;
  surf->width = 0;
  surf->height = 0;
  surf->current_buffer = 0;
  surf->start_time_ns = 0;
  surf->last_frame_time_ns = 0;
}

void kl_surface_request_render(struct kl_surface *surf) {
  if (!surf) {
    return;
  }
  surf->dirty = true;
  if (!surf->frame_pending && surf->configured) {
    kl_surface_render_frame(surf);
  }
}

static void kl_surface_render_frame(struct kl_surface *surf) {
  if (!surf || !surf->configured || !surf->ctx || surf->frame_pending) {
    return;
  }

  if (!surf->wl_surface || surf->width == 0 || surf->height == 0) {
    return;
  }

  struct kl_buffer *buf = kl_surface_get_free_buffer(surf);
  if (!buf) {
    surf->dirty = true;
    return;
  }

  if (buf->width != surf->width || buf->height != surf->height ||
      buf->scale != surf->scale || !buf->wl_buffer) {
    kl_buffer_destroy(buf);
    if (kl_buffer_create(surf->ctx->shm, buf, surf->width, surf->height,
                         surf->scale, kl_surface_on_buffer_release, surf) < 0) {
      fprintf(stderr, "Failed to allocate buffer for output %u\n",
              surf->global_name);
      return;
    }
  }

  uint64_t current_time_ns = kl_get_time_ns();
  if (surf->start_time_ns == 0) {
    surf->start_time_ns = current_time_ns;
    surf->last_frame_time_ns = current_time_ns;
  }

  double elapsed_sec =
      (double)(current_time_ns - surf->start_time_ns) / (double)KL_NS_PER_SEC;
  surf->last_frame_time_ns = current_time_ns;

  kl_buffer_prepare(buf);
  kl_render_engine_draw(surf->engine, buf->cr, surf->width, surf->height,
                        (double)surf->scale, elapsed_sec);
  kl_buffer_flush(buf);

  buf->busy = 1;

  wl_surface_set_buffer_scale(surf->wl_surface, surf->scale);
  wl_surface_attach(surf->wl_surface, buf->wl_buffer, 0, 0);
  wl_surface_damage(surf->wl_surface, 0, 0, (int32_t)surf->width,
                    (int32_t)surf->height);

  surf->frame_callback = wl_surface_frame(surf->wl_surface);
  if (!surf->frame_callback) {
    fprintf(stderr, "Failed to create wl_surface_frame callback\n");
    surf->frame_pending = false;
    wl_surface_commit(surf->wl_surface);
    return;
  }

  if (wl_callback_add_listener(surf->frame_callback, &kl_frame_listener, surf) <
      0) {
    fprintf(stderr, "Failed to add frame listener\n");
    wl_callback_destroy(surf->frame_callback);
    surf->frame_callback = NULL;
    surf->frame_pending = false;
    wl_surface_commit(surf->wl_surface);
    return;
  }

  surf->frame_pending = true;
  surf->dirty = false;
  wl_surface_commit(surf->wl_surface);
}

void kl_surface_destroy(struct kl_surface *surf) {
  if (!surf) {
    return;
  }

  kl_surface_detach_lock(surf);

  if (surf->engine) {
    kl_render_engine_destroy(surf->engine);
    surf->engine = NULL;
  }

  if (surf->wl_output) {
    if (wl_output_get_version(surf->wl_output) >=
        WL_OUTPUT_RELEASE_SINCE_VERSION) {
      wl_output_release(surf->wl_output);
    } else {
      wl_output_destroy(surf->wl_output);
    }
    surf->wl_output = NULL;
  }

  free(surf);
}
