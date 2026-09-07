#ifndef KIRILOCK_BUFFER_H
#define KIRILOCK_BUFFER_H

#include <cairo.h>
#include <stddef.h>
#include <stdint.h>
#include <wayland-client.h>

struct kl_buffer;

typedef void (*kl_buffer_release_cb)(struct kl_buffer *buf, void *user_data);

struct kl_buffer {
  struct wl_buffer *wl_buffer;
  uint32_t *data;
  size_t size;
  uint32_t width;
  uint32_t height;
  int32_t scale;
  uint32_t stride;
  int busy;

  cairo_surface_t *cairo_surface;
  cairo_t *cr;

  kl_buffer_release_cb on_release;
  void *user_data;
};

int kl_buffer_create(struct wl_shm *shm, struct kl_buffer *buf, uint32_t width,
                     uint32_t height, int32_t scale,
                     kl_buffer_release_cb on_release, void *user_data);
void kl_buffer_prepare(struct kl_buffer *buf);
void kl_buffer_flush(struct kl_buffer *buf);
void kl_buffer_destroy(struct kl_buffer *buf);

#endif /* KIRILOCK_BUFFER_H */
