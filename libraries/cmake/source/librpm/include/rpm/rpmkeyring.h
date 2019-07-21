#ifndef _RPMKEYRING_H
#define _RPMKEYRING_H

/** \ingroup rpmkeyring
 * \file rpmio/rpmkeyring.h
 *
 * RPM keyring API
 */

#include <rpm/rpmtypes.h>
#include <rpm/rpmpgp.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmkeyring
 * Create a new, empty keyring
 * @return	new keyring handle
 */
rpmKeyring rpmKeyringNew(void);

/** \ingroup rpmkeyring
 * Free keyring and the keys within it
 * @return	NULL always
 */
rpmKeyring rpmKeyringFree(rpmKeyring keyring);

/** \ingroup rpmkeyring
 * Add a public key to keyring.
 * @param keyring	keyring handle
 * @param key		pubkey handle
 * @return		0 on success, -1 on error, 1 if key already present
 */
int rpmKeyringAddKey(rpmKeyring keyring, rpmPubkey key);

/** \ingroup rpmkeyring
 * Perform keyring lookup for a key matching a signature
 * @param keyring	keyring handle
 * @param sig		OpenPGP packet container of signature
 * @return		RPMRC_OK if found, RPMRC_NOKEY otherwise
 */
rpmRC rpmKeyringLookup(rpmKeyring keyring, pgpDig sig);

/** \ingroup rpmkeyring
 * Perform combined keyring lookup and signature verification
 * @param keyring	keyring handle
 * @param sig		OpenPGP signature parameters
 * @param ctx		signature hash context
 * @return		RPMRC_OK / RPMRC_FAIL / RPMRC_NOKEY
 */
rpmRC rpmKeyringVerifySig(rpmKeyring keyring, pgpDigParams sig, DIGEST_CTX ctx);

/** \ingroup rpmkeyring
 * Reference a keyring.
 * @param keyring	keyring handle
 * @return		new keyring reference
 */
rpmKeyring rpmKeyringLink(rpmKeyring keyring);

/** \ingroup rpmkeyring
 * Create a new rpmPubkey from OpenPGP packet
 * @param pkt		OpenPGP packet data
 * @param pktlen	Data length
 * @return		new pubkey handle
 */
rpmPubkey rpmPubkeyNew(const uint8_t *pkt, size_t pktlen);

/** \ingroup rpmkeyring
 * Return array of subkeys belonging to maikey
 * param mainkey	main rpmPubkey
 * param count		count of returned subkeys
 * @return		an array of subkey's handles
 */
rpmPubkey *rpmGetSubkeys(rpmPubkey mainkey, int *count);

/** \ingroup rpmkeyring
 * Create a new rpmPubkey from ASCII-armored pubkey file
 * @param filename	Path to pubkey file
 * @return		new pubkey handle
 */
rpmPubkey rpmPubkeyRead(const char *filename);

/** \ingroup rpmkeyring
 * Free a pubkey.
 * @param key		Pubkey to free
 * @return		NULL always
 */
rpmPubkey rpmPubkeyFree(rpmPubkey key);

/** \ingroup rpmkeyring
 * Reference a pubkey.
 * @param key		Pubkey
 * @return		new pubkey reference
 */
rpmPubkey rpmPubkeyLink(rpmPubkey key);

/** \ingroup rpmkeyring
 * Parse OpenPGP pubkey parameters.
 * @param key           Pubkey
 * @return              parsed output of pubkey packet parameters
 */
pgpDig rpmPubkeyDig(rpmPubkey key);

/** \ingroup rpmkeyring
 * Return base64 encoding of pubkey
 * @param key           Pubkey
 * @return              base64 encoded pubkey (malloced), NULL on error
 */
char * rpmPubkeyBase64(rpmPubkey key);

/** \ingroup rpmkeyring
 * Return pgp params of key
 * @param key		Pubkey
 * @return		pgp params, NULL on error
 */
pgpDigParams rpmPubkeyPgpDigParams(rpmPubkey key);

#ifdef __cplusplus
}
#endif
#endif /* _RPMKEYDB_H */
