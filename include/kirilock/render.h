#ifndef KIRILOCK_RENDER_H
#define KIRILOCK_RENDER_H

#include <cairo.h>
#include <stdbool.h>
#include <stdint.h>

struct kl_render_engine;

struct kl_render_engine *kl_render_engine_create(void);
void kl_render_engine_draw(struct kl_render_engine *engine, cairo_t *cr,
                           uint32_t logical_width, uint32_t logical_height,
                           double scale, double elapsed_sec);
void kl_render_engine_destroy(struct kl_render_engine *engine);

#endif /* KIRILOCK_RENDER_H */
