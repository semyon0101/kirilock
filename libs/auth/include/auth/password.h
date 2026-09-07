#ifndef PASSWORD_H
#define PASSWORD_H

#include <stdbool.h>

typedef struct kl_password_ctx kl_password_ctx_t;

typedef enum { PW_ERR_AUTH_FAILED, PW_ERR_SYSTEM } kl_password_error_t;

typedef struct {
  void (*on_init)(kl_password_ctx_t *ctx);
  void (*on_begin)(kl_password_ctx_t *ctx);
  void (*on_finish)(kl_password_ctx_t *ctx);
  void (*on_error)(kl_password_ctx_t *ctx, kl_password_error_t err, const char *msg);
  void (*on_end)(kl_password_ctx_t *ctx);
  void (*on_stop)(kl_password_ctx_t *ctx);
  void (*on_delete)(kl_password_ctx_t *ctx);
} kl_password_handlers_t;

kl_password_ctx_t *kl_password_init(void *user_data, const char *username);
void kl_password_set_handlers(kl_password_ctx_t *ctx,
                           const kl_password_handlers_t *handlers);
int kl_password_verify(kl_password_ctx_t *ctx, const char *kl_password);
void kl_password_stop(kl_password_ctx_t *ctx);
void kl_password_delete(kl_password_ctx_t *ctx);
bool kl_password_is_running(const kl_password_ctx_t *ctx);
void *kl_password_get_user_data(const kl_password_ctx_t *ctx);

#endif // PASSWORD_H
