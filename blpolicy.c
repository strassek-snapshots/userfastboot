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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>
#include <efivar.h>
#include <userfastboot_ui.h>
#include <aboot.h>

#include "userfastboot.h"
#include "blpolicy.h"

#define CLASS_A_DEVICE		1U
#define DEFAULT_BLPOLICY	0U

#ifdef BOOTLOADER_POLICY_EFI_VAR
const char *FASTBOOT_SECURED_VARS[] = { OAK_VARNAME, BPM_VARNAME };
const size_t FASTBOOT_SECURED_VARS_SIZE = ARRAY_SIZE(FASTBOOT_SECURED_VARS);

bool device_is_class_A(void)
{
	int ret;
	size_t size;
	uint32_t attributes;
	uint64_t *bpm_data;
	uint64_t bpm = DEFAULT_BLPOLICY;
	efi_guid_t fastboot_guid = FASTBOOT_GUID;

	ret = efi_get_variable(fastboot_guid, BPM_VARNAME,
			       (uint8_t **)&bpm_data, &size, &attributes);
	if (ret)
		goto out;

	if (size != sizeof(bpm) ||
	    !(attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)) {
		free(bpm_data);
		goto out;
	}

	bpm = *bpm_data;
	free(bpm_data);

out:
	return (bpm & CLASS_A_DEVICE) != 0;
}

int get_oak_hash(unsigned char **data_p, size_t *size)
{
	int ret;
	uint32_t attributes;
	efi_guid_t fastboot_guid = FASTBOOT_GUID;
	uint8_t *data;

	ret = efi_get_variable(fastboot_guid, OAK_VARNAME, &data,
			       size, &attributes);
	if (ret || !size)
		return -1;

	if (!(attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)) {
		free(data);
		return -1;
	}

	*data_p = data;

	return 0;
}
#else
bool device_is_class_A(void)
{
	return (BOOTLOADER_POLICY & CLASS_A_DEVICE) != 0;
}

int get_oak_hash(unsigned char **data_p, size_t *size)
{
	int ret;
	char *path;
	int fd;
	struct stat sb;

	if (!data_p || !size) {
		pr_error("get_oak_hash(): Invalid parameter");
		return -1;
	}

	ret = asprintf(&path, "/blpolicy/%s/OAK.sha256", get_device_id());
	if (ret < 0) {
		pr_error("Failed to build the path to the OAK SHA256 file");
		return ret;
	}

	fd = open(path, O_RDONLY);
	free(path);
	if (fd == -1) {
		pr_error("Failed to open OAK file: %s", strerror(errno));
		return -1;
	}

	ret = fstat(fd, &sb);
	if (ret == -1) {
		pr_error("Failed to get the OAK file stat: %s", strerror(errno));
		return ret;
	}

	*size = sb.st_size;
	*data_p = malloc(*size);
	if (!*data_p) {
		pr_error("Failed to allocate OAK SHA256 buffer");
		return -1;
	}

	ret = read(fd, *data_p, *size);
	if (ret != (int)*size) {
		pr_error("Failed to read OAK file");
		free(*data_p);
		return -1;
	}

	return 0;
}
#endif
