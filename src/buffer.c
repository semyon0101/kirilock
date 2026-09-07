#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include "buffer.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void kl_buffer_handle_release(void *data, struct wl_buffer *wl_buffer) {
  (void)wl_buffer;
  if (!data) {
    return;
  }
  struct kl_buffer *buf = (struct kl_buffer *)data;
  buf->busy = 0;

  if (buf->on_release) {
    buf->on_release(buf, buf->user_data);
  }
}

static const struct wl_buffer_listener kl_buffer_listener = {
    .release = kl_buffer_handle_release,
};

static int kl_buffer_allocate_shm_file(size_t size) {
  if (size == 0) {
    return -1;
  }

  int fd = memfd_create("kirilock-shm", MFD_CLOEXEC | MFD_ALLOW_SEALING);
  if (fd < 0) {
    perror("memfd_create failed");
    return -1;
  }

  if (ftruncate(fd, (off_t)size) < 0) {
    perror("ftruncate failed");
    close(fd);
    return -1;
  }

  if (fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) < 0) {
    perror("fcntl F_ADD_SEALS failed");
    close(fd);
    return -1;
  }

  return fd;
}

int kl_buffer_create(struct wl_shm *shm, struct kl_buffer *buf, uint32_t width,
                     uint32_t height, int32_t scale,
                     kl_buffer_release_cb on_release, void *user_data) {
  if (!shm || !buf || width == 0 || height == 0 || scale <= 0) {
    return -1;
  }

  uint32_t phys_width = width * (uint32_t)scale;
  uint32_t phys_height = height * (uint32_t)scale;

  int stride_signed =
      cairo_format_stride_for_width(CAIRO_FORMAT_RGB24, (int)phys_width);
  if (stride_signed <= 0) {
    fprintf(stderr, "Invalid stride calculated for width %u\n", phys_width);
    return -1;
  }
  uint32_t stride = (uint32_t)stride_signed;

  if (phys_height > SIZE_MAX / (size_t)stride) {
    fprintf(stderr, "Buffer size calculation overflow\n");
    return -1;
  }
  size_t size = (size_t)stride * phys_height;

  int fd = kl_buffer_allocate_shm_file(size);
  if (fd < 0) {
    return -1;
  }

  uint32_t *data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (data == MAP_FAILED) {
    perror("mmap failed");
    close(fd);
    return -1;
  }

  struct wl_shm_pool *pool = wl_shm_create_pool(shm, fd, (int32_t)size);
  close(fd);

  if (!pool) {
    fprintf(stderr, "Failed to create SHM pool\n");
    munmap(data, size);
    return -1;
  }

  buf->wl_buffer = wl_shm_pool_create_buffer(
      pool, 0, (int32_t)phys_width, (int32_t)phys_height, (int32_t)stride,
      WL_SHM_FORMAT_XRGB8888);
  wl_shm_pool_destroy(pool);

  if (!buf->wl_buffer) {
    fprintf(stderr, "Failed to create wl_buffer from pool\n");
    munmap(data, size);
    return -1;
  }

  buf->cairo_surface = cairo_image_surface_create_for_data(
      (unsigned char *)data, CAIRO_FORMAT_RGB24, (int)phys_width,
      (int)phys_height, (int)stride);
  if (cairo_surface_status(buf->cairo_surface) != CAIRO_STATUS_SUCCESS) {
    fprintf(stderr, "Cairo surface creation failed: %s\n",
            cairo_status_to_string(cairo_surface_status(buf->cairo_surface)));
    wl_buffer_destroy(buf->wl_buffer);
    munmap(data, size);
    buf->wl_buffer = NULL;
    return -1;
  }

  buf->cr = cairo_create(buf->cairo_surface);
  if (cairo_status(buf->cr) != CAIRO_STATUS_SUCCESS) {
    fprintf(stderr, "Cairo context creation failed: %s\n",
            cairo_status_to_string(cairo_status(buf->cr)));
    cairo_destroy(buf->cr);
    buf->cr = NULL;
    cairo_surface_destroy(buf->cairo_surface);
    buf->cairo_surface = NULL;
    wl_buffer_destroy(buf->wl_buffer);
    buf->wl_buffer = NULL;
    munmap(data, size);
    return -1;
  }

  buf->data = data;
  buf->size = size;
  buf->width = width;
  buf->height = height;
  buf->scale = scale;
  buf->stride = stride;
  buf->busy = 0;
  buf->on_release = on_release;
  buf->user_data = user_data;

  if (wl_buffer_add_listener(buf->wl_buffer, &kl_buffer_listener, buf) < 0) {
    fprintf(stderr, "Failed to add wl_buffer listener\n");
    kl_buffer_destroy(buf);
    return -1;
  }

  return 0;
}

void kl_buffer_prepare(struct kl_buffer *buf) {
  if (!buf || !buf->cr) {
    return;
  }
  cairo_identity_matrix(buf->cr);
  if (buf->scale > 1) {
    cairo_scale(buf->cr, (double)buf->scale, (double)buf->scale);
  }
}

void kl_buffer_flush(struct kl_buffer *buf) {
  if (!buf || !buf->cairo_surface) {
    return;
  }
  cairo_surface_flush(buf->cairo_surface);
}

void kl_buffer_destroy(struct kl_buffer *buf) {
  if (!buf) {
    return;
  }

  if (buf->cr) {
    cairo_destroy(buf->cr);
    buf->cr = NULL;
  }

  if (buf->cairo_surface) {
    cairo_surface_destroy(buf->cairo_surface);
    buf->cairo_surface = NULL;
  }

  if (buf->wl_buffer) {
    wl_buffer_destroy(buf->wl_buffer);
    buf->wl_buffer = NULL;
  }

  if (buf->data && buf->data != MAP_FAILED) {
    munmap(buf->data, buf->size);
    buf->data = NULL;
  }

  buf->size = 0;
  buf->width = 0;
  buf->height = 0;
  buf->scale = 1;
  buf->stride = 0;
  buf->busy = 0;
  buf->on_release = NULL;
  buf->user_data = NULL;
}
