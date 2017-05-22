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

#include <stdbool.h>
#include <lib.h>
#include <security.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include <cutils/properties.h>

#include "aboot.h"
#include "userfastboot.h"
#include "userfastboot_ui.h"
#include "blpolicy.h"
#include "authenticated_action.h"

#define NONCE_RANDOM_BYTE_LENGTH	16
#define NONCE_EXPIRATION_SEC		5 * 60 * 60;

typedef struct action {
	uint8_t id;
	const char *name;
	int (*do_it)(void);
} action_t;

static uint8_t VERSION = 0;
static char current_nonce[3 + NONCE_RANDOM_BYTE_LENGTH * 2 + 3 + PROPERTY_VALUE_MAX + 1];
static const struct action *current_action;
static time_t expiration_ctime;

static int force_unlock(void)
{
	return set_device_state(UNLOCKED, true);
}

static const action_t ACTIONS[] = {
	{ 0, "force-unlock", force_unlock }
};

static void bytes_to_hex_stra(unsigned char *bytes, size_t length, char *str)
{
	unsigned char hex;
	size_t i;

	if (!bytes || !str)
		return;

	for (i = 0; i < length * 2; i++) {
		hex = ((i & 1) ? bytes[i / 2] & 0xf : bytes[i / 2] >> 4);
		*str++ = (hex > 9 ? (hex + 'a' - 10) : (hex + '0'));
	}
	*str = '\0';
}

static int generate_random_numbers(unsigned char *data, size_t size)
{
	int ret;
	size_t i, j;
	unsigned int random;

	for (i = 0; i < size; ) {
		ret = __builtin_ia32_rdrand32_step(&random);
		if (ret != 1) {
			pr_error("rdrand random number generation failed\n");
			return -1;
		}

		for (j = 0; j < sizeof(random) && i < size; j++, i++)
			data[i] = ((unsigned char *)&random)[j];
	}

	return 0;
}

static char *get_serial_number(void)
{
	static char serial[PROPERTY_VALUE_MAX];

	if (!property_get("ro.serialno", serial, "unknown"))
		return NULL;

	return serial;
}

static void clear_nonce(void)
{
	expiration_ctime = 0;
	memset(current_nonce, 0, sizeof(current_nonce));
}

char *authenticated_action_new_nonce(char *action_name)
{
	char randomstr[NONCE_RANDOM_BYTE_LENGTH * 2 + 1];
	unsigned char random[NONCE_RANDOM_BYTE_LENGTH];
	char *serial;
	const struct action *action = NULL;
	int ret;
	struct timeval now;
	unsigned int i;

	clear_nonce();

	for (i = 0; i < ARRAY_SIZE(ACTIONS); i++)
		if (!strcmp(ACTIONS[i].name, action_name)) {
			action = &ACTIONS[i];
			break;
		}

	if (!action)
		return NULL;

	ret = gettimeofday(&now, NULL);
	if (ret == -1) {
		pr_error("Failed to get the current time\n");
		return NULL;
	}

	ret = generate_random_numbers(random, sizeof(random));
	if (ret) {
		pr_error("Failed to generate random numbers\n");
		return NULL;
	}

	bytes_to_hex_stra(random, sizeof(random), randomstr);

	current_action = action;
	expiration_ctime = now.tv_sec + NONCE_EXPIRATION_SEC;
	serial = get_serial_number();
	if (!serial) {
		pr_error("Failed to get the serial number\n");
		return NULL;
	}
	snprintf(current_nonce, sizeof(current_nonce),
		 "%02x:%s:%02x:%s", VERSION, get_serial_number(),
		 action->id, randomstr);

	return (char *)current_nonce;
}

static int verify_payload(const char *payload, ssize_t size)
{
	const char *host_random;

	if (payload[size - 1] != '\0' ||
	    memcmp(payload, current_nonce, strlen(current_nonce)) ||
	    payload[strlen(current_nonce)] != ':')
		goto parse_error;

	host_random = payload + strlen(current_nonce) + 1;
	if (strlen(host_random) != NONCE_RANDOM_BYTE_LENGTH * 2)
		goto parse_error;

	return 0;

parse_error:
	pr_debug("Failed to parse the token response payload\n");
	return -1;
}

static bool nonce_is_expired()
{
	int ret;
	struct timeval now;

	ret = gettimeofday(&now, NULL);
	if (ret == -1) {
		pr_error("Failed to get the current time\n");
		goto expired;
	}

	if (now.tv_sec >= expiration_ctime) {
		pr_error("Nonce is expired\n");
		goto expired;
	}

	return false;

expired:
	clear_nonce();
	return true;
}

static int verify_token(void *data, unsigned size)
{
	int ret;
	unsigned char *oak_data;
	size_t oak_size;
	char *payload;
	ssize_t payload_size;

	ret = get_oak_hash(&oak_data, &oak_size);
	if (ret) {
		pr_error("Failed to read OAK EFI variable\n");
		return -1;
	}

	ret = verify_pkcs7(oak_data, oak_size, data, size,
			   (void **)&payload, &payload_size);
	free(oak_data);
	if (ret) {
		pr_error("PKCS7 Verification failed\n");
		return -1;
	}

	ret = verify_payload(payload, payload_size);
	free(payload);
	if (ret) {
		pr_error("Token payload verification failed\n");
		return -1;
	}

	return 0;
}

int authenticated_action(Hashmap *params, int fd, void *data, unsigned size)
{
	int ret;
	unsigned int i;

	if (!data || nonce_is_expired())
		return -1;

	ret = verify_token(data, size);
	clear_nonce();
	if (ret)
		return ret;

	return current_action->do_it();
}
