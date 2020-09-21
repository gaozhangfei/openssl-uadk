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

static int cipher_nids[] = { NID_sm4_ctr, 0 };

static int uadk_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                               const int **nids, int nid)
{
	int ok = 1;
	printf("gzf %s cipher=0x%x\n", __func__, cipher);

	if (!cipher) {
		*nids = cipher_nids;
		return ((sizeof(cipher_nids) - 1) / sizeof(cipher_nids[0]));
	}

	switch(nid) {
	case NID_sm4_ctr:
		*cipher = (EVP_CIPHER *)EVP_sm4_ctr();
		break;
	default:
		ok = 0;
		*cipher = NULL;
		break;
	}

	return ok;
}

int uadk_bind_cipher(ENGINE *e)
{

    if (!ENGINE_set_ciphers(e, uadk_engine_ciphers))
	    return 0;
}
