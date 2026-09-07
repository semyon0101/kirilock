#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#include "lock.h"

#define KL_NS_PER_SEC 1000000000L

static void kl_cleanup_debug_resources(void) {
#ifndef NDEBUG
  cairo_debug_reset_static_data();
#endif
}

static uint64_t kl_get_monotonic_time_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * KL_NS_PER_SEC + (uint64_t)ts.tv_nsec;
}

int main(void) {
  printf("Initializing kirilock...\n");

  struct kl_context ctx;
  if (kl_context_init(&ctx) < 0) {
    fprintf(stderr, "Fatal: Failed to initialize lock context\n");
    kl_cleanup_debug_resources();
    return -1;
  }

  if (kl_context_lock_session(&ctx) < 0) {
    fprintf(stderr, "Fatal: Failed to lock Wayland session\n");
    kl_context_destroy(&ctx);
    kl_cleanup_debug_resources();
    return -1;
  }

  int display_fd = wl_display_get_fd(ctx.display);
  if (display_fd < 0) {
    fprintf(stderr, "Fatal: Invalid Wayland display file descriptor\n");
    kl_context_unlock_session(&ctx);
    kl_context_destroy(&ctx);
    kl_cleanup_debug_resources();
    return -1;
  }

  int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (epoll_fd < 0) {
    perror("epoll_create1 failed");
    kl_context_unlock_session(&ctx);
    kl_context_destroy(&ctx);
    kl_cleanup_debug_resources();
    return -1;
  }

  struct epoll_event ev_wl = {
      .events = EPOLLIN | EPOLLHUP | EPOLLERR,
      .data.fd = display_fd,
  };
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, display_fd, &ev_wl) < 0) {
    perror("epoll_ctl display_fd failed");
    close(epoll_fd);
    kl_context_unlock_session(&ctx);
    kl_context_destroy(&ctx);
    kl_cleanup_debug_resources();
    return -1;
  }

  printf("Session locked. Pure event-driven V-Sync loop active (timeout = "
         "-1)...\n");

  uint64_t app_start_time_ns = kl_get_monotonic_time_ns();
  uint64_t total_demo_duration_ns = 5ULL * KL_NS_PER_SEC;

  struct epoll_event events[8];

  while (true) {
    uint64_t current_time_ns = kl_get_monotonic_time_ns();
    if (current_time_ns - app_start_time_ns >= total_demo_duration_ns) {
      break;
    }

    // 1. Dispatch pending events in queue
    while (wl_display_prepare_read(ctx.display) != 0) {
      if (wl_display_dispatch_pending(ctx.display) < 0) {
        fprintf(stderr, "Fatal: Error dispatching pending Wayland events\n");
        goto loop_exit;
      }
    }

    // 2. Flush outgoing requests
    if (wl_display_flush(ctx.display) < 0) {
      if (errno != EAGAIN) {
        perror("Fatal: wl_display_flush failed");
        wl_display_cancel_read(ctx.display);
        goto loop_exit;
      }
    }

    // 3. True event-driven sleep in kernel
    int num_events = epoll_wait(epoll_fd, events, 8, -1);
    if (num_events < 0) {
      wl_display_cancel_read(ctx.display);
      if (errno == EINTR) {
        continue;
      }
      perror("epoll_wait failed");
      goto loop_exit;
    }

    if (num_events == 0) {
      wl_display_cancel_read(ctx.display);
      continue;
    }

    bool wayland_readable = false;
    bool wayland_error = false;

    for (int i = 0; i < num_events; ++i) {
      if (events[i].data.fd == display_fd) {
        if (events[i].events & (EPOLLHUP | EPOLLERR)) {
          wayland_error = true;
        }
        if (events[i].events & EPOLLIN) {
          wayland_readable = true;
        }
      }
    }

    if (wayland_error) {
      fprintf(stderr,
              "Fatal error on Wayland display socket (compositor died)\n");
      wl_display_cancel_read(ctx.display);
      goto loop_exit;
    }

    if (wayland_readable) {
      if (wl_display_read_events(ctx.display) < 0) {
        fprintf(stderr, "Fatal: Failed to read events from Wayland socket\n");
        goto loop_exit;
      }
      if (wl_display_dispatch_pending(ctx.display) < 0) {
        fprintf(stderr, "Fatal: Failed to dispatch pending events\n");
        goto loop_exit;
      }
    } else {
      wl_display_cancel_read(ctx.display);
    }

    if (ctx.is_finished) {
      fprintf(stderr, "Session lock manager terminated the session\n");
      goto loop_exit;
    }
  }

loop_exit:
  close(epoll_fd);

  printf("Unlocking session and terminating cleanly...\n");
  if (kl_context_unlock_session(&ctx) < 0) {
    fprintf(stderr, "Warning: Failed to cleanly unlock session\n");
  }

  kl_context_destroy(&ctx);
  kl_cleanup_debug_resources();

  return 0;
}
