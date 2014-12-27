/* DANGER!
 *
 * This code snippets is not reliable and not secure at all.
 * It is not intended to be used in real world applications.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "hsm.h"

#define KEY_PIPE "/rsa2048pubkey"
#define DATA_PIPE "/data2sign"
#define SIG_PIPE "/signature"

void hsm_rsa2048_getpubkey(unsigned char **blob, unsigned int *blen)
{
	unsigned char source[279] = "\x00\x00\x00\x07\x73\x73\x68\x2d\x72\x73\x61\x00\x00\x00\x03\x01\x00\x01\x00\x00\x01\x01\x00\xc6\x68\x50\x6b\xd8\xc5\xed\x22\x38\xd8\xbd\x12\x54\xc3\xbd\xb5\xa6\xc2\x0c\xb5\x46\xcf\xc3\xec\xcb\x40\x4c\xd2\xd6\xdd\x72\x20\xf8\xa8\x2d\x93\x80\xf1\x6f\x0d\x67\xdf\x4e\x65\x4c\x2d\x1a\x56\x4b\xfb\x43\xc6\xec\x92\x40\x6d\x97\x34\x05\x45\x4c\x78\x6e\x28\x6c\x98\x2b\x4a\x38\xce\x86\xc4\x66\x90\xba\x83\xd1\x17\x92\x30\xba\x77\x24\x61\xce\x25\x34\x26\x66\x0d\x8b\x2f\x33\xb3\xed\xd5\xcb\xb5\xd1\x47\x25\x92\xe2\x65\x23\xa8\x8f\xc6\x4c\x64\x24\xa2\x53\xd5\xb9\x10\xc8\x90\xd9\xdc\xf2\xc8\x52\x21\xf3\x58\xc6\x05\x3b\x19\x40\xd5\x5c\x15\x6a\xe7\x7c\x6b\xfb\x17\xf3\xb7\xad\x07\x4a\xb7\xf0\x96\x7c\x59\x30\x84\x35\xbf\x48\xc7\x01\x0d\x4d\xf0\x03\xef\x51\xb3\x4d\xf7\x21\xd8\x85\xfe\xb0\x08\x38\x40\x18\x79\x16\x27\x2d\x2b\xde\x37\xc3\x0e\x98\xe4\x9b\x43\x37\x07\x1b\x0d\xb1\x16\x2b\x54\x4b\xab\xfe\x57\xb6\x40\xf5\xd8\x15\x47\x30\x99\x12\xf9\xd1\x0b\x1a\x9c\x0c\xa1\xda\x97\xd3\x2f\xe4\xbb\x04\x11\xf0\x86\xa8\xc4\x11\x80\xe2\xbe\xb5\x08\xcc\xb4\x64\xaa\x11\x51\x92\x17\x42\xf2\x70\x30\x3c\x7d\x2b\xf8\x00\x98\xf6\xc3\x11\x8b";

	*blen = 279;
	*blob = malloc(279);
	if (*blob != NULL) {
		memcpy(*blob, source, 279);
	}
}

int hsm_rsa2048_sign(
		unsigned char **signature, unsigned int *slen,
		const unsigned char *blob, unsigned int blen,
		const unsigned char *data, unsigned int dlen)
{
	FILE *fp = NULL;
	int ret;

	*slen = 271;
	*signature = malloc(271);
	if (*signature == NULL) {
		debug("Fail to malloc 271-byte memory for signature\n");
		return -1;
	}

	/* Step 1: Write out public key */
	fp = fopen(KEY_PIPE, "w");
	if (fp == NULL) {
		debug("Fail to open the file " KEY_PIPE "\n");
		return -1;
	}
	ret = fwrite(blob, 1, blen, fp);
	if (ret < (int) blen) {
		debug("Only write %d bytes to " KEY_PIPE "\n", ret);
		if (ferror(fp)) {
			debug("Fail to write to the file " KEY_PIPE "\n");
		}
		return -1;
	}
	fclose(fp);

	/* Step 2: Write out data */
	fp = fopen(DATA_PIPE, "w");
	if (fp == NULL) {
		debug("Fail to open the file " DATA_PIPE "\n");
		return -1;
	}
	ret = fwrite(data, 1, dlen, fp);
	if (ret < (int) dlen) {
		debug("Only write %d bytes to " DATA_PIPE "\n", ret);
		if (ferror(fp)) {
			debug("Fail to write to the file " DATA_PIPE "\n");
		}
		return -1;
	}
	fclose(fp);

	/* Step 3: Read in signature */
	fp = fopen(SIG_PIPE, "r");
	if (fp == NULL) {
		debug("Fail to open the file " SIG_PIPE "\n");
		return -1;
	}
	ret = fread(*signature, 1, 271, fp);
	if (ret != 271) {
		if (feof(fp)) {
			debug("Unexpected EOF when reading from " SIG_PIPE "\n");
		} else {
			debug("Something went wrong when reading from " SIG_PIPE "\n");
		}
		return -1;
	}

	return 0;
}
