#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include "render.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define KL_BASE_TEXTURE_DIM 256

struct kl_render_engine {
  cairo_surface_t *baked_surface;
  cairo_pattern_t *baked_pattern;
  int cached_scale;
  int baked_dim;
  double pulse_frequency;
};

static void kl_render_cleanup_baked(struct kl_render_engine *engine) {
  if (!engine) {
    return;
  }
  if (engine->baked_pattern) {
    cairo_pattern_destroy(engine->baked_pattern);
    engine->baked_pattern = NULL;
  }
  if (engine->baked_surface) {
    cairo_surface_destroy(engine->baked_surface);
    engine->baked_surface = NULL;
  }
  engine->cached_scale = 0;
  engine->baked_dim = 0;
}

static bool kl_render_ensure_baked_surface(struct kl_render_engine *engine,
                                           int scale) {
  if (engine->baked_surface && engine->baked_pattern &&
      engine->cached_scale == scale) {
    return true;
  }

  kl_render_cleanup_baked(engine);

  int dim = KL_BASE_TEXTURE_DIM * scale;
  engine->baked_surface =
      cairo_image_surface_create(CAIRO_FORMAT_ARGB32, dim, dim);
  if (cairo_surface_status(engine->baked_surface) != CAIRO_STATUS_SUCCESS) {
    kl_render_cleanup_baked(engine);
    return false;
  }

  cairo_t *cr = cairo_create(engine->baked_surface);
  if (cairo_status(cr) != CAIRO_STATUS_SUCCESS) {
    cairo_destroy(cr);
    kl_render_cleanup_baked(engine);
    return false;
  }

  cairo_scale(cr, (double)scale, (double)scale);
  double center = KL_BASE_TEXTURE_DIM / 2.0;

  // 1. Single-pass Outer Ring (Catppuccin Lavender: #b4befe with alpha)
  cairo_set_line_width(cr, 4.0);
  cairo_set_source_rgba(cr, 0.706, 0.745, 0.996, 0.85);
  cairo_arc(cr, center, center, 75.0, 0.0, 2.0 * M_PI);
  cairo_stroke(cr);

  // 2. Single-pass Center Circle (Catppuccin Mauve: #cba6f7)
  cairo_set_source_rgb(cr, 0.796, 0.651, 0.969);
  cairo_arc(cr, center, center, 50.0, 0.0, 2.0 * M_PI);
  cairo_fill(cr);

  cairo_destroy(cr);

  engine->baked_pattern =
      cairo_pattern_create_for_surface(engine->baked_surface);
  if (cairo_pattern_status(engine->baked_pattern) != CAIRO_STATUS_SUCCESS) {
    kl_render_cleanup_baked(engine);
    return false;
  }

  engine->cached_scale = scale;
  engine->baked_dim = dim;
  return true;
}

struct kl_render_engine *kl_render_engine_create(void) {
  struct kl_render_engine *engine =
      (struct kl_render_engine *)calloc(1, sizeof(struct kl_render_engine));
  if (!engine) {
    perror("calloc kl_render_engine failed");
    return NULL;
  }

  engine->pulse_frequency = 1.0;
  return engine;
}

void kl_render_engine_draw(struct kl_render_engine *engine, cairo_t *cr,
                           uint32_t logical_width, uint32_t logical_height,
                           double scale, double elapsed_sec) {
  if (!cr || !engine || logical_width == 0 || logical_height == 0) {
    return;
  }

  int scale_int = (int)scale;
  if (scale_int < 1) {
    scale_int = 1;
  }

  if (!kl_render_ensure_baked_surface(engine, scale_int)) {
    return;
  }

  // 1. Solid Background (Catppuccin Mocha Crust: #11111b)
  cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
  cairo_set_source_rgb(cr, 0.067, 0.067, 0.106);
  cairo_paint(cr);

  // 2. Scale Calculation
  double pulse = sin(elapsed_sec * engine->pulse_frequency * 2.0 * M_PI);
  double anim_scale = 1.0 + 0.15 * pulse;
  if (anim_scale <= 0.001) {
    anim_scale = 0.001;
  }

  double center_x = (double)logical_width / 2.0;
  double center_y = (double)logical_height / 2.0;
  double half_dim = (double)KL_BASE_TEXTURE_DIM / 2.0;

  cairo_set_operator(cr, CAIRO_OPERATOR_OVER);

  // 3. Single-pass Unified Sprite Blit
  cairo_save(cr);
  cairo_translate(cr, center_x, center_y);
  cairo_scale(cr, anim_scale / (double)scale_int,
              anim_scale / (double)scale_int);
  cairo_translate(cr, -half_dim * (double)scale_int,
                  -half_dim * (double)scale_int);

  cairo_set_source(cr, engine->baked_pattern);
  cairo_paint(cr);
  cairo_restore(cr);
}

void kl_render_engine_destroy(struct kl_render_engine *engine) {
  if (!engine) {
    return;
  }
  kl_render_cleanup_baked(engine);
  free(engine);
}
