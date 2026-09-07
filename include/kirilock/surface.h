#ifndef KIRILOCK_SURFACE_H
#define KIRILOCK_SURFACE_H

#include <stdbool.h>
#include <stdint.h>
#include <wayland-client.h>

#include "buffer.h"
#include "render.h"
#include "session-lock-client-protocol.h"

#define KL_SURFACE_BUFFER_COUNT 3

struct kl_context;

struct kl_surface {
  uint32_t global_name;
  struct wl_output *wl_output;
  struct wl_surface *wl_surface;
  struct ext_session_lock_surface_v1 *ext_lock_surface;
  struct wl_callback *frame_callback;

  struct kl_buffer buffers[KL_SURFACE_BUFFER_COUNT];
  int current_buffer;

  uint32_t width;
  uint32_t height;
  int32_t scale;
  bool configured;
  bool frame_pending;
  bool dirty;

  struct kl_render_engine *engine;

  uint64_t start_time_ns;
  uint64_t last_frame_time_ns;

  struct wl_list link;
  struct kl_context *ctx;
};

struct kl_surface *kl_surface_create(struct kl_context *ctx,
                                     struct wl_output *output, uint32_t name);
int kl_surface_attach_lock(struct kl_surface *surf);
void kl_surface_detach_lock(struct kl_surface *surf);
void kl_surface_request_render(struct kl_surface *surf);
void kl_surface_destroy(struct kl_surface *surf);

#endif /* KIRILOCK_SURFACE_H */
