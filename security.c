/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Author: Jeremy Compostella <jeremy.compostella@intel.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "userfastboot_ui.h"
#include "security.h"

static X509 *find_cert_in_pkcs7(PKCS7 *p7, const unsigned char *cert_sha256)
{
	STACK_OF(X509) *certs = NULL;
	X509 *x509;
	int id;
	unsigned int size;
	unsigned char digest[SHA256_DIGEST_LENGTH];
	const EVP_MD *fdig = EVP_sha256();
	int i;

	id = OBJ_obj2nid(p7->type);
	switch (id) {
	case NID_pkcs7_signed:
		certs = p7->d.sign->cert;
		break;
	case NID_pkcs7_signedAndEnveloped:
		certs = p7->d.signed_and_enveloped->cert;
		break;
	default:
		break;
	}

	if (!certs)
		return NULL;

	for (i = 0; i < sk_X509_num(certs); i++) {
		x509 = sk_X509_value(certs, i);
		if (!X509_digest(x509, fdig, digest, &size)) {
			pr_error("Failed to compute X509 digest\n");
			return NULL;
		}
		if (size != sizeof(digest))
			continue;
		if (!memcmp(cert_sha256, digest, sizeof(digest)))
			return x509;
	}

	return NULL;
}

static time_t get_signing_time(PKCS7 *p7)
{
	ASN1_TYPE *stime = NULL;
	STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
	PKCS7_SIGNER_INFO *sinfo;
	int i;
	struct tm t;
	unsigned char *str;

	sinfos = PKCS7_get_signer_info(p7);
	if (!sinfos) {
		pr_error("Failed to get signer info\n");
		return 0;
	}

	for (i = 0; i < SKM_sk_num(PKCS7_SIGNER_INFO, sinfos); i++) {
		sinfo = SKM_sk_value(PKCS7_SIGNER_INFO, sinfos, i);
		stime = PKCS7_get_signed_attribute(sinfo, NID_pkcs9_signingTime);
		if (stime)
			break;
	}

	if (!stime) {
		pr_error("Could not find signing time\n");
		return 0;
	}

	if (stime->type != V_ASN1_UTCTIME) {
		pr_error("Unsupported signing time type %d\n", stime->type);
		return 0;
	}

	str = stime->value.utctime->data;
	memset(&t, 0, sizeof(t));

	/* ASN1_UTCTIME format is "YYmmddHHMMSS" */
	t.tm_year = (str[0] - '0') * 10 + (str[1] - '0');
	if (t.tm_year < 70)
		t.tm_year += 100;

	t.tm_mon  = (str[2] - '0') * 10 + (str[3] - '0') - 1;
	t.tm_mday = (str[4] - '0') * 10 + (str[5] - '0');
	t.tm_hour = (str[6] - '0') * 10 + (str[7] - '0');
	t.tm_min  = (str[8] - '0') * 10 + (str[9] - '0');
	t.tm_sec  = (str[10] - '0') * 10 + (str[11] - '0');

	/* Note: no timezone management */
	return mktime(&t);
}

int verify_pkcs7(const unsigned char *cert_sha256, size_t cert_size,
		 const void *pkcs7, size_t pkcs7_size,
		 void **data_p, ssize_t *size)
{
	X509 *x509;
	PKCS7 *p7 = NULL;
	X509_STORE *store = NULL;
	BIO *p7_bio = NULL, *data_bio = NULL;
	time_t signing_time;
	void *payload = NULL;
	char *tmp;
	int ret;

	if (cert_size != SHA256_DIGEST_LENGTH) {
		pr_error("Invalid SHA256 length for trusted certificate\n");
		goto done;
	}

	p7_bio = BIO_new_mem_buf((void *)pkcs7, pkcs7_size);
	if (!p7_bio) {
		pr_error("Failed to create PKCS7 BIO\n");
		goto done;
	}

	p7 = d2i_PKCS7_bio(p7_bio, NULL);
	if (!p7) {
		pr_error("Failed to read PKCS7\n");
		goto done;
	}

	x509 = find_cert_in_pkcs7(p7, cert_sha256);
	if (!x509) {
		pr_error("Could not find the root certificate\n");
		goto done;
	}

	signing_time = get_signing_time(p7);
	if (!signing_time)
		goto done;

	store = X509_STORE_new();
	if (!store) {
		pr_error("Failed to create x509 store\n");
		goto done;
	}

	ret = X509_STORE_add_cert(store, x509);
	if (ret != 1) {
		pr_error("Failed to add trusted certificate to store\n");
		goto done;
	}

	data_bio = BIO_new(BIO_s_mem());
	if (!data_bio) {
		pr_error("Failed to create data BIO\n");
		goto done;
	}

	EVP_add_digest(EVP_sha256());
	X509_VERIFY_PARAM_set_time(store->param, signing_time);
	ret = PKCS7_verify(p7, NULL, store, NULL, data_bio, 0);
	if (ret != 1) {
		pr_error("PKCS7 verification failed\n");
		goto done;
	}

	*size = BIO_get_mem_data(data_bio, &tmp);
	if (*size == -1) {
		pr_error("Failed to get PKCS7 data\n");
		goto done;
	}

	payload = malloc(*size);
	if (!payload) {
		pr_error("Failed to allocate data buffer\n");
		goto done;
	}

	memcpy(payload, tmp, *size);
	*data_p = payload;

done:
	if (p7_bio)
		BIO_free(p7_bio);
	if (p7)
		PKCS7_free(p7);
	if (store)
		X509_STORE_free(store);
	if (data_bio)
		BIO_free(data_bio);

	return payload ? 0 : -1;
}

/* vim: softtabstop=8:shiftwidth=8:expandtab
 */

