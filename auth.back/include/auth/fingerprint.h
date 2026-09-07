#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include <stdbool.h>

typedef struct kl_fingerprint_ctx kl_fingerprint_ctx_t;

typedef enum { FP_ERR_NOT_MATCH, FP_ERR_NOT_FOUND, FP_ERR_SYSTEM } kl_fingerprint_error_t;

typedef struct {
    void (*on_init)(kl_fingerprint_ctx_t *ctx);
    void (*on_start)(kl_fingerprint_ctx_t *ctx);
    void (*on_loop)(kl_fingerprint_ctx_t *ctx); /* Renamed from on_loop */
    void (*on_finish)(kl_fingerprint_ctx_t *ctx);
    void (*on_error)(kl_fingerprint_ctx_t *ctx, kl_fingerprint_error_t err, const char *msg);
    void (*on_end)(kl_fingerprint_ctx_t *ctx);
    void (*on_stop)(kl_fingerprint_ctx_t *ctx);
    void (*on_delete)(kl_fingerprint_ctx_t *ctx);
} kl_fingerprint_handlers_t;

kl_fingerprint_ctx_t *kl_fingerprint_init(void *user_data, const char *username);
void kl_fingerprint_set_handlers(kl_fingerprint_ctx_t *ctx,
                              const kl_fingerprint_handlers_t *handlers);
int kl_fingerprint_start(kl_fingerprint_ctx_t *ctx);
void kl_fingerprint_stop(kl_fingerprint_ctx_t *ctx);
void kl_fingerprint_delete(kl_fingerprint_ctx_t *ctx);
bool kl_fingerprint_is_running(const kl_fingerprint_ctx_t *ctx);
void *kl_fingerprint_get_user_data(const kl_fingerprint_ctx_t *ctx);

#endif // FINGERPRINT_H
