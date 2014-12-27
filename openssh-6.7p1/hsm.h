/* DANGER!
 *
 * This code snippets is not reliable and not secure at all.
 * It is not intended to be used in real world applications.
 */
#ifndef SSH_HSM_H
#define SSH_HSM_H

void hsm_rsa2048_getpubkey(
		unsigned char **blob, unsigned int *blen);

int hsm_rsa2048_sign(
		unsigned char **signature, unsigned int *slen,
		const unsigned char *blob, unsigned int blen,
		const unsigned char *data, unsigned int dlen);

#endif
