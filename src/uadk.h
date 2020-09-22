/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <uadk/wd.h>
#include <uadk/wd_digest.h>
#include <uadk/wd_cipher.h>

typedef struct uacce_dev_list *(*wd_get_accel_list_t)(char *alg_name);
typedef void (*wd_free_list_accels_t)(struct uacce_dev_list *list);
typedef handle_t (*wd_request_ctx_t)(struct uacce_dev *dev);
typedef void (*wd_release_ctx_t)(handle_t h_ctx);

typedef int (*wd_digest_init_t)(struct wd_ctx_config *config, struct wd_digest_sched *sched);
typedef void (*wd_digest_uninit_t)(void);

typedef int (*wd_cipher_init_t)(struct wd_ctx_config *config, struct wd_sched *sched);
typedef void (*wd_cipher_uninit_t)(void);
typedef handle_t (*wd_cipher_alloc_sess_t)(struct wd_cipher_sess_setup *setup);
typedef void (*wd_cipher_free_sess_t)(handle_t h_sess);
typedef int (*wd_cipher_set_key_t)(handle_t h_sess, const __u8 *key, __u32 key_len);
typedef int (*wd_do_cipher_sync_t)(handle_t h_sess, struct wd_cipher_req *req);
typedef int (*wd_do_cipher_async_t)(handle_t h_sess, struct wd_cipher_req *req);
typedef int (*wd_cipher_poll_ctx_t)(handle_t h_ctx, __u32 expt, __u32* count);

extern wd_get_accel_list_t p_wd_get_accel_list;
extern wd_free_list_accels_t p_wd_free_list_accels;
extern wd_request_ctx_t p_wd_request_ctx;
extern wd_release_ctx_t p_wd_release_ctx;
extern wd_digest_init_t p_wd_digest_init;
extern wd_digest_uninit_t p_wd_digest_uninit;
extern wd_cipher_init_t p_wd_cipher_init;
extern wd_cipher_uninit_t p_wd_cipher_uninit;
extern wd_cipher_alloc_sess_t p_wd_cipher_alloc_sess;
extern wd_cipher_free_sess_t p_wd_cipher_free_sess;
extern wd_cipher_set_key_t p_wd_cipher_set_key;
extern wd_do_cipher_sync_t p_wd_do_cipher_sync;
extern wd_do_cipher_async_t p_wd_do_cipher_async;
extern wd_cipher_poll_ctx_t p_wd_cipher_poll_ctx;

extern int uadk_bind_cipher(ENGINE *e);
extern void uadk_destroy_cipher();
extern int uadk_bind_digest(ENGINE *e);
extern void uadk_destroy_digest();

