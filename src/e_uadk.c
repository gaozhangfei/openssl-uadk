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

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/engine.h>
#include "uadk.h"

/* Constants used when creating the ENGINE */
static const char *engine_uadk_id = "uadk";
static const char *engine_uadk_name = "uadk hardware engine support";

wd_get_accel_list_t p_wd_get_accel_list;
wd_free_list_accels_t p_wd_free_list_accels;
wd_request_ctx_t p_wd_request_ctx;
wd_release_ctx_t p_wd_release_ctx;
wd_digest_init_t p_wd_digest_init;
wd_digest_uninit_t p_wd_digest_uninit;
wd_cipher_init_t p_wd_cipher_init;
wd_cipher_uninit_t p_wd_cipher_uninit;
wd_cipher_alloc_sess_t p_wd_cipher_alloc_sess;
wd_cipher_free_sess_t p_wd_cipher_free_sess;
wd_cipher_set_key_t p_wd_cipher_set_key;
wd_do_cipher_sync_t p_wd_do_cipher_sync;
wd_do_cipher_async_t p_wd_do_cipher_async;
wd_cipher_poll_ctx_t p_wd_cipher_poll_ctx;

#define BIND(dso, sym)	(p_##sym = (sym##_t)dlsym(dso, #sym))

__attribute__((constructor))
static void uadk_constructor(void)
{
	printf("gzf %s\n", __func__);
}

__attribute__((destructor))
static void uadk_destructor(void)
{
	printf("gzf %s\n", __func__);
}

/* Destructor (complements the "ENGINE_uadk()" constructor) */
static int uadk_destroy(ENGINE *e)
{
	printf("gzf %s\n", __func__);
	uadk_destroy_cipher();
	uadk_destroy_digest();

	return 1;
}


static int uadk_init(ENGINE *e)
{
	void *dso = NULL;
	void *wd_dso = NULL;
	void *wd_sec_dso = NULL;
	void *wd_crypto_dso = NULL;
	struct uacce_dev_list *list;
	int ret;

	printf("gzf %s\n", __func__);

	wd_dso = dlopen("libwd.so", RTLD_NOW);
	if (wd_dso == NULL)
		printf("dlopen - %s\n", dlerror());
	BIND(wd_dso, wd_get_accel_list);
	BIND(wd_dso, wd_free_list_accels);
	BIND(wd_dso, wd_request_ctx);
	BIND(wd_dso, wd_release_ctx);

	wd_sec_dso = dlopen("libhisi_sec.so", RTLD_NOW);
	if (wd_sec_dso == NULL)
		printf("dlopen - %s\n", dlerror());
	BIND(wd_sec_dso, wd_digest_init);
	BIND(wd_sec_dso, wd_digest_uninit);

	wd_crypto_dso = dlopen("libwd_crypto.so", RTLD_NOW);
	if (wd_crypto_dso == NULL)
		printf("dlopen - %s\n", dlerror());

	BIND(wd_crypto_dso, wd_cipher_init);
	BIND(wd_crypto_dso, wd_cipher_uninit);
	BIND(wd_crypto_dso, wd_cipher_alloc_sess);
	BIND(wd_crypto_dso, wd_cipher_free_sess);
	BIND(wd_crypto_dso, wd_cipher_set_key);
	BIND(wd_crypto_dso, wd_do_cipher_sync);
	BIND(wd_crypto_dso, wd_do_cipher_async);
	BIND(wd_crypto_dso, wd_cipher_poll_ctx);

	list = p_wd_get_accel_list("cipher");
	if (!list)
		return -ENODEV;

	return 1;
}

static int uadk_finish(ENGINE *e)
{
	printf("gzf %s\n", __func__);
	return 1;
}


/*
 * This stuff is needed if this ENGINE is being
 * compiled into a self-contained shared-library.
 */
static int bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_uadk_id) != 0)) {
        fprintf(stderr, "wrong engine id\n");
        fprintf(stderr, "id = %s wrong engine id\n", id);
        return 0;
    }

    if (!ENGINE_set_id(e, engine_uadk_id) ||
        !ENGINE_set_destroy_function(e, uadk_destroy) ||
        !ENGINE_set_init_function(e, uadk_init) ||
        !ENGINE_set_finish_function(e, uadk_finish) ||
        !ENGINE_set_name(e, engine_uadk_name)) {
        fprintf(stderr, "bind failed\n");
        return 0;
    }

    if (!uadk_bind_cipher(e))
	    fprintf(stderr, "uadk bind cipher failed\n");
    if (!uadk_bind_digest(e))
	    fprintf(stderr, "uadk bind digest failed\n");

    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
