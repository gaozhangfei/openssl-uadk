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

struct digest_priv_ctx {
	int enc;
};
typedef struct digest_priv_ctx digest_priv_ctx_t;

static int digest_nids[] = {
	NID_md5,
	0,
	};

static EVP_MD* uadk_md5;

static int uadk_engine_digests(ENGINE *e, const EVP_MD **digest,
			       const int **nids, int nid)
{
	int ok = 1;
	printf("gzf %s digest=0x%x nid=%d\n", __func__, digest, nid);

	if (!digest) {
		*nids = digest_nids;
		return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
	}
	printf("gzf %s digest=0x%x nid=%d\n", __func__, digest, nid);

	switch(nid) {
	case NID_md5:
		*digest = uadk_md5;
		break;
	default:
		ok = 0;
		*digest = NULL;
		break;
	}

	return ok;
}
static int uadk_digest_init(EVP_MD_CTX *ctx)
{
	printf("gzf %s\n", __func__);
	return 1;
}
static int uadk_digest_update(EVP_MD_CTX *ctx, const void *data, size_t data_len)
{
	printf("gzf %s\n", __func__);
	return 1;
}
static int uadk_digest_final(EVP_MD_CTX *ctx, unsigned char *digest)
{
	printf("gzf %s\n", __func__);
	return 1;
}
static int uadk_digest_cleanup(EVP_MD_CTX *ctx)
{
	printf("gzf %s\n", __func__);
	return 1;
}

#define UADK_CIPHER_DESCR(name, block_size, key_size, iv_len, flags,\
	init, digest, cleanup, set_params, get_params, ctrl)\
	uadk_##name = EVP_CIPHER_meth_new(NID_##name, block_size, key_size);\
	if (uadk_##name == 0 ||\
		!EVP_CIPHER_meth_set_iv_length(uadk_##name, iv_len) ||\
		!EVP_CIPHER_meth_set_flags(uadk_##name, flags) ||\
		!EVP_CIPHER_meth_set_impl_ctx_size(uadk_##name, sizeof(digest_priv_ctx_t)) ||\
		!EVP_CIPHER_meth_set_init(uadk_##name, init) ||\
		!EVP_CIPHER_meth_set_do_digest(uadk_##name, digest) ||\
		!EVP_CIPHER_meth_set_cleanup(uadk_##name, cleanup) ||\
		!EVP_CIPHER_meth_set_set_asn1_params(uadk_##name, set_params) ||\
		!EVP_CIPHER_meth_set_get_asn1_params(uadk_##name, get_params) ||\
		!EVP_CIPHER_meth_set_ctrl(uadk_##name, ctrl))\
		return 0;\

int uadk_bind_digest(ENGINE *e)
{
	EVP_MD *md = (EVP_MD *)EVP_MD_meth_dup(EVP_md5());
//	md = EVP_MD_meth_new(NID_##type, NID_md5);
//	EVP_MD_meth_set_result_size(md, md_size);
//	EVP_MD_meth_set_input_blocksize(md, block_size);
//	EVP_MD_meth_set_app_datasize(md, ctx_size);
//	EVP_MD_meth_set_flags(md, flags);
	EVP_MD_meth_set_init(md, uadk_digest_init);
	EVP_MD_meth_set_update(md, uadk_digest_update);
	EVP_MD_meth_set_final(md, uadk_digest_final);
	EVP_MD_meth_set_cleanup(md, uadk_digest_cleanup);

	uadk_md5 = md;
	printf("gzf %s uadk_md5=0x%x\n", __func__, uadk_md5);

	return ENGINE_set_digests(e, uadk_engine_digests);
}

void uadk_destroy_digest()
{
	EVP_MD_meth_free(uadk_md5);
	uadk_md5 = 0;
}
