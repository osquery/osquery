#ifndef	H_RPMPGP
#define	H_RPMPGP

/** \ingroup rpmpgp
 * \file rpmio/rpmpgp.h
 *
 * OpenPGP constants and structures from RFC-2440.
 *
 * Text from RFC-2440 in comments is
 *	Copyright (C) The Internet Society (1998).  All Rights Reserved.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <rpm/rpmtypes.h>
#include <rpm/rpmstring.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmpgp
 */
typedef struct DIGEST_CTX_s * DIGEST_CTX;
typedef struct rpmDigestBundle_s * rpmDigestBundle;

/** \ingroup rpmpgp
 */
typedef struct pgpDig_s * pgpDig;

/** \ingroup rpmpgp
 */
typedef struct pgpDigParams_s * pgpDigParams;

typedef uint8_t pgpKeyID_t[8];
typedef uint8_t pgpTime_t[4];

/** \ingroup rpmpgp
 * 4.3. Packet Tags
 * 
 * The packet tag denotes what type of packet the body holds. Note that
 * old format headers can only have tags less than 16, whereas new
 * format headers can have tags as great as 63.
 */
typedef enum pgpTag_e {
    PGPTAG_RESERVED		=  0, /*!< Reserved/Invalid */
    PGPTAG_PUBLIC_SESSION_KEY	=  1, /*!< Public-Key Encrypted Session Key */
    PGPTAG_SIGNATURE		=  2, /*!< Signature */
    PGPTAG_SYMMETRIC_SESSION_KEY=  3, /*!< Symmetric-Key Encrypted Session Key*/
    PGPTAG_ONEPASS_SIGNATURE	=  4, /*!< One-Pass Signature */
    PGPTAG_SECRET_KEY		=  5, /*!< Secret Key */
    PGPTAG_PUBLIC_KEY		=  6, /*!< Public Key */
    PGPTAG_SECRET_SUBKEY	=  7, /*!< Secret Subkey */
    PGPTAG_COMPRESSED_DATA	=  8, /*!< Compressed Data */
    PGPTAG_SYMMETRIC_DATA	=  9, /*!< Symmetrically Encrypted Data */
    PGPTAG_MARKER		= 10, /*!< Marker */
    PGPTAG_LITERAL_DATA		= 11, /*!< Literal Data */
    PGPTAG_TRUST		= 12, /*!< Trust */
    PGPTAG_USER_ID		= 13, /*!< User ID */
    PGPTAG_PUBLIC_SUBKEY	= 14, /*!< Public Subkey */
    PGPTAG_COMMENT_OLD		= 16, /*!< Comment (from OpenPGP draft) */
    PGPTAG_PHOTOID		= 17, /*!< PGP's photo ID */
    PGPTAG_ENCRYPTED_MDC	= 18, /*!< Integrity protected encrypted data */
    PGPTAG_MDC			= 19, /*!< Manipulaion detection code packet */
    PGPTAG_PRIVATE_60		= 60, /*!< Private or Experimental Values */
    PGPTAG_COMMENT		= 61, /*!< Comment */
    PGPTAG_PRIVATE_62		= 62, /*!< Private or Experimental Values */
    PGPTAG_CONTROL		= 63  /*!< Control (GPG) */
} pgpTag;

/** \ingroup rpmpgp
 * 5.1. Public-Key Encrypted Session Key Packets (Tag 1)
 *
 * A Public-Key Encrypted Session Key packet holds the session key used
 * to encrypt a message. Zero or more Encrypted Session Key packets
 * (either Public-Key or Symmetric-Key) may precede a Symmetrically
 * Encrypted Data Packet, which holds an encrypted message.  The message
 * is encrypted with the session key, and the session key is itself
 * encrypted and stored in the Encrypted Session Key packet(s).  The
 * Symmetrically Encrypted Data Packet is preceded by one Public-Key
 * Encrypted Session Key packet for each OpenPGP key to which the
 * message is encrypted.  The recipient of the message finds a session
 * key that is encrypted to their public key, decrypts the session key,
 * and then uses the session key to decrypt the message.
 *
 * The body of this packet consists of:
 *   - A one-octet number giving the version number of the packet type.
 *     The currently defined value for packet version is 3. An
 *     implementation should accept, but not generate a version of 2,
 *     which is equivalent to V3 in all other respects.
 *   - An eight-octet number that gives the key ID of the public key
 *     that the session key is encrypted to.
 *   - A one-octet number giving the public key algorithm used.
 *   - A string of octets that is the encrypted session key. This string
 *     takes up the remainder of the packet, and its contents are
 *     dependent on the public key algorithm used.
 *
 * Algorithm Specific Fields for RSA encryption
 *   - multiprecision integer (MPI) of RSA encrypted value m**e mod n.
 *
 * Algorithm Specific Fields for Elgamal encryption:
 *   - MPI of Elgamal (Diffie-Hellman) value g**k mod p.
 *   - MPI of Elgamal (Diffie-Hellman) value m * y**k mod p.
 */
typedef struct pgpPktPubkey_s {
    uint8_t version;	/*!< version number (generate 3, accept 2). */
    pgpKeyID_t keyid;	/*!< key ID of the public key for session key. */
    uint8_t algo;		/*!< public key algorithm used. */
} pgpPktPubkey;


/** \ingroup rpmpgp
 * 5.2.1. Signature Types
 * 
 * There are a number of possible meanings for a signature, which are
 * specified in a signature type octet in any given signature.
 */
typedef enum pgpSigType_e {
    PGPSIGTYPE_BINARY		 = 0x00, /*!< Binary document */
    PGPSIGTYPE_TEXT		 = 0x01, /*!< Canonical text document */
    PGPSIGTYPE_STANDALONE	 = 0x02, /*!< Standalone */
    PGPSIGTYPE_GENERIC_CERT	 = 0x10,
		/*!< Generic certification of a User ID & Public Key */
    PGPSIGTYPE_PERSONA_CERT	 = 0x11,
		/*!< Persona certification of a User ID & Public Key */
    PGPSIGTYPE_CASUAL_CERT	 = 0x12,
		/*!< Casual certification of a User ID & Public Key */
    PGPSIGTYPE_POSITIVE_CERT	 = 0x13,
		/*!< Positive certification of a User ID & Public Key */
    PGPSIGTYPE_SUBKEY_BINDING	 = 0x18, /*!< Subkey Binding */
    PGPSIGTYPE_SIGNED_KEY	 = 0x1F, /*!< Signature directly on a key */
    PGPSIGTYPE_KEY_REVOKE	 = 0x20, /*!< Key revocation */
    PGPSIGTYPE_SUBKEY_REVOKE	 = 0x28, /*!< Subkey revocation */
    PGPSIGTYPE_CERT_REVOKE	 = 0x30, /*!< Certification revocation */
    PGPSIGTYPE_TIMESTAMP	 = 0x40  /*!< Timestamp */
} pgpSigType;

/** \ingroup rpmpgp
 * 9.1. Public Key Algorithms
 *
\verbatim
       ID           Algorithm
       --           ---------
       1          - RSA (Encrypt or Sign)
       2          - RSA Encrypt-Only
       3          - RSA Sign-Only
       16         - Elgamal (Encrypt-Only), see [ELGAMAL]
       17         - DSA (Digital Signature Standard)
       18         - Reserved for Elliptic Curve
       19         - Reserved for ECDSA
       20         - Elgamal (Encrypt or Sign)
       21         - Reserved for Diffie-Hellman (X9.42,
                    as defined for IETF-S/MIME)
       100 to 110 - Private/Experimental algorithm.
\endverbatim
 *
 * Implementations MUST implement DSA for signatures, and Elgamal for
 * encryption. Implementations SHOULD implement RSA keys.
 * Implementations MAY implement any other algorithm.
 */
typedef enum pgpPubkeyAlgo_e {
    PGPPUBKEYALGO_RSA		=  1,	/*!< RSA */
    PGPPUBKEYALGO_RSA_ENCRYPT	=  2,	/*!< RSA(Encrypt-Only) */
    PGPPUBKEYALGO_RSA_SIGN	=  3,	/*!< RSA(Sign-Only) */
    PGPPUBKEYALGO_ELGAMAL_ENCRYPT = 16,	/*!< Elgamal(Encrypt-Only) */
    PGPPUBKEYALGO_DSA		= 17,	/*!< DSA */
    PGPPUBKEYALGO_EC		= 18,	/*!< Elliptic Curve */
    PGPPUBKEYALGO_ECDSA		= 19,	/*!< ECDSA */
    PGPPUBKEYALGO_ELGAMAL	= 20,	/*!< Elgamal */
    PGPPUBKEYALGO_DH		= 21	/*!< Diffie-Hellman (X9.42) */
} pgpPubkeyAlgo;

/** \ingroup rpmpgp
 * 9.2. Symmetric Key Algorithms
 *
\verbatim
       ID           Algorithm
       --           ---------
       0          - Plaintext or unencrypted data
       1          - IDEA [IDEA]
       2          - Triple-DES (DES-EDE, as per spec -
                    168 bit key derived from 192)
       3          - CAST5 (128 bit key, as per RFC 2144)
       4          - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
       5          - SAFER-SK128 (13 rounds) [SAFER]
       6          - Reserved for DES/SK
       7          - Reserved for AES with 128-bit key
       8          - Reserved for AES with 192-bit key
       9          - Reserved for AES with 256-bit key
       100 to 110 - Private/Experimental algorithm.
\endverbatim
 *
 * Implementations MUST implement Triple-DES. Implementations SHOULD
 * implement IDEA and CAST5. Implementations MAY implement any other
 * algorithm.
 */
typedef enum pgpSymkeyAlgo_e {
    PGPSYMKEYALGO_PLAINTEXT	=  0,	/*!< Plaintext */
    PGPSYMKEYALGO_IDEA		=  1,	/*!< IDEA */
    PGPSYMKEYALGO_TRIPLE_DES	=  2,	/*!< 3DES */
    PGPSYMKEYALGO_CAST5		=  3,	/*!< CAST5 */
    PGPSYMKEYALGO_BLOWFISH	=  4,	/*!< BLOWFISH */
    PGPSYMKEYALGO_SAFER		=  5,	/*!< SAFER */
    PGPSYMKEYALGO_DES_SK	=  6,	/*!< DES/SK */
    PGPSYMKEYALGO_AES_128	=  7,	/*!< AES(128-bit key) */
    PGPSYMKEYALGO_AES_192	=  8,	/*!< AES(192-bit key) */
    PGPSYMKEYALGO_AES_256	=  9,	/*!< AES(256-bit key) */
    PGPSYMKEYALGO_TWOFISH	= 10,	/*!< TWOFISH(256-bit key) */
    PGPSYMKEYALGO_NOENCRYPT	= 110	/*!< no encryption */
} pgpSymkeyAlgo;

/** \ingroup rpmpgp
 * 9.3. Compression Algorithms
 *
\verbatim
       ID           Algorithm
       --           ---------
       0          - Uncompressed
       1          - ZIP (RFC 1951)
       2          - ZLIB (RFC 1950)
       100 to 110 - Private/Experimental algorithm.
\endverbatim
 *
 * Implementations MUST implement uncompressed data. Implementations
 * SHOULD implement ZIP. Implementations MAY implement ZLIB.
 */
typedef enum pgpCompressAlgo_e {
    PGPCOMPRESSALGO_NONE	=  0,	/*!< Uncompressed */
    PGPCOMPRESSALGO_ZIP		=  1,	/*!< ZIP */
    PGPCOMPRESSALGO_ZLIB	=  2,	/*!< ZLIB */
    PGPCOMPRESSALGO_BZIP2	=  3	/*!< BZIP2 */
} pgpCompressAlgo;

/** \ingroup rpmpgp
 * 9.4. Hash Algorithms
 *
\verbatim
       ID           Algorithm                              Text Name
       --           ---------                              ---- ----
       1          - MD5                                    "MD5"
       2          - SHA-1                                  "SHA1"
       3          - RIPE-MD/160                            "RIPEMD160"
       4          - Reserved for double-width SHA (experimental)
       5          - MD2                                    "MD2"
       6          - Reserved for TIGER/192                 "TIGER192"
       7          - Reserved for HAVAL (5 pass, 160-bit)    "HAVAL-5-160"
       8          - SHA-256                                "SHA256"
       9          - SHA-384                                "SHA384"
       10         - SHA-512                                "SHA512"
       11         - SHA-224                                "SHA224"
       100 to 110 - Private/Experimental algorithm.
\endverbatim
 *
 * Implementations MUST implement SHA-1. Implementations SHOULD
 * implement MD5.
 */
typedef enum pgpHashAlgo_e {
    PGPHASHALGO_MD5		=  1,	/*!< MD5 */
    PGPHASHALGO_SHA1		=  2,	/*!< SHA1 */
    PGPHASHALGO_RIPEMD160	=  3,	/*!< RIPEMD160 */
    PGPHASHALGO_MD2		=  5,	/*!< MD2 */
    PGPHASHALGO_TIGER192	=  6,	/*!< TIGER192 */
    PGPHASHALGO_HAVAL_5_160	=  7,	/*!< HAVAL-5-160 */
    PGPHASHALGO_SHA256		=  8,	/*!< SHA256 */
    PGPHASHALGO_SHA384		=  9,	/*!< SHA384 */
    PGPHASHALGO_SHA512		= 10,	/*!< SHA512 */
    PGPHASHALGO_SHA224		= 11,	/*!< SHA224 */
} pgpHashAlgo;

/** \ingroup rpmpgp
 * 5.2.2. Version 3 Signature Packet Format
 * 
 * The body of a version 3 Signature Packet contains:
 *   - One-octet version number (3).
 *   - One-octet length of following hashed material.  MUST be 5.
 *       - One-octet signature type.
 *       - Four-octet creation time.
 *   - Eight-octet key ID of signer.
 *   - One-octet public key algorithm.
 *   - One-octet hash algorithm.
 *   - Two-octet field holding left 16 bits of signed hash value.
 *   - One or more multi-precision integers comprising the signature.
 *
 * Algorithm Specific Fields for RSA signatures:
 *   - multiprecision integer (MPI) of RSA signature value m**d.
 *
 * Algorithm Specific Fields for DSA signatures:
 *   - MPI of DSA value r.
 *   - MPI of DSA value s.
 */
typedef struct pgpPktSigV3_s {
    uint8_t version;	/*!< version number (3). */
    uint8_t hashlen;	/*!< length of following hashed material. MUST be 5. */
    uint8_t sigtype;	/*!< signature type. */
    pgpTime_t time;	/*!< 4 byte creation time. */
    pgpKeyID_t signid;	/*!< key ID of signer. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
    uint8_t hash_algo;	/*!< hash algorithm. */
    uint8_t signhash16[2];	/*!< left 16 bits of signed hash value. */
} * pgpPktSigV3;

/** \ingroup rpmpgp
 * 5.2.3. Version 4 Signature Packet Format
 * 
 * The body of a version 4 Signature Packet contains:
 *   - One-octet version number (4).
 *   - One-octet signature type.
 *   - One-octet public key algorithm.
 *   - One-octet hash algorithm.
 *   - Two-octet scalar octet count for following hashed subpacket
 *     data. Note that this is the length in octets of all of the hashed
 *     subpackets; a pointer incremented by this number will skip over
 *     the hashed subpackets.
 *   - Hashed subpacket data. (zero or more subpackets)
 *   - Two-octet scalar octet count for following unhashed subpacket
 *     data. Note that this is the length in octets of all of the
 *     unhashed subpackets; a pointer incremented by this number will
 *     skip over the unhashed subpackets.
 *   - Unhashed subpacket data. (zero or more subpackets)
 *   - Two-octet field holding left 16 bits of signed hash value.
 *   - One or more multi-precision integers comprising the signature.
 */
typedef struct pgpPktSigV4_s {
    uint8_t version;	/*!< version number (4). */
    uint8_t sigtype;	/*!< signature type. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
    uint8_t hash_algo;	/*!< hash algorithm. */
    uint8_t hashlen[2];	/*!< length of following hashed material. */
} * pgpPktSigV4;

/** \ingroup rpmpgp
 * 5.2.3.1. Signature Subpacket Specification
 * 
 * The subpacket fields consist of zero or more signature subpackets.
 * Each set of subpackets is preceded by a two-octet scalar count of the
 * length of the set of subpackets.
 *
 * Each subpacket consists of a subpacket header and a body.  The header
 * consists of:
 *   - the subpacket length (1,  2, or 5 octets)
 *   - the subpacket type (1 octet)
 * and is followed by the subpacket specific data.
 *
 * The length includes the type octet but not this length. Its format is
 * similar to the "new" format packet header lengths, but cannot have
 * partial body lengths. That is:
\verbatim
       if the 1st octet <  192, then
           lengthOfLength = 1
           subpacketLen = 1st_octet

       if the 1st octet >= 192 and < 255, then
           lengthOfLength = 2
           subpacketLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192

       if the 1st octet = 255, then
           lengthOfLength = 5
           subpacket length = [four-octet scalar starting at 2nd_octet]
\endverbatim
 *
 * The value of the subpacket type octet may be:
 *
\verbatim
       2 = signature creation time
       3 = signature expiration time
       4 = exportable certification
       5 = trust signature
       6 = regular expression
       7 = revocable
       9 = key expiration time
       10 = placeholder for backward compatibility
       11 = preferred symmetric algorithms
       12 = revocation key
       16 = issuer key ID
       20 = notation data
       21 = preferred hash algorithms
       22 = preferred compression algorithms
       23 = key server preferences
       24 = preferred key server
       25 = primary user id
       26 = policy URL
       27 = key flags
       28 = signer's user id
       29 = reason for revocation
       100 to 110 = internal or user-defined
\endverbatim
 *
 * An implementation SHOULD ignore any subpacket of a type that it does
 * not recognize.
 *
 * Bit 7 of the subpacket type is the "critical" bit.  If set, it
 * denotes that the subpacket is one that is critical for the evaluator
 * of the signature to recognize.  If a subpacket is encountered that is
 * marked critical but is unknown to the evaluating software, the
 * evaluator SHOULD consider the signature to be in error.
 */
typedef enum pgpSubType_e {
    PGPSUBTYPE_NONE		=   0, /*!< none */
    PGPSUBTYPE_SIG_CREATE_TIME	=   2, /*!< signature creation time */
    PGPSUBTYPE_SIG_EXPIRE_TIME	=   3, /*!< signature expiration time */
    PGPSUBTYPE_EXPORTABLE_CERT	=   4, /*!< exportable certification */
    PGPSUBTYPE_TRUST_SIG	=   5, /*!< trust signature */
    PGPSUBTYPE_REGEX		=   6, /*!< regular expression */
    PGPSUBTYPE_REVOCABLE	=   7, /*!< revocable */
    PGPSUBTYPE_KEY_EXPIRE_TIME	=   9, /*!< key expiration time */
    PGPSUBTYPE_ARR		=  10, /*!< additional recipient request */
    PGPSUBTYPE_PREFER_SYMKEY	=  11, /*!< preferred symmetric algorithms */
    PGPSUBTYPE_REVOKE_KEY	=  12, /*!< revocation key */
    PGPSUBTYPE_ISSUER_KEYID	=  16, /*!< issuer key ID */
    PGPSUBTYPE_NOTATION		=  20, /*!< notation data */
    PGPSUBTYPE_PREFER_HASH	=  21, /*!< preferred hash algorithms */
    PGPSUBTYPE_PREFER_COMPRESS	=  22, /*!< preferred compression algorithms */
    PGPSUBTYPE_KEYSERVER_PREFERS=  23, /*!< key server preferences */
    PGPSUBTYPE_PREFER_KEYSERVER	=  24, /*!< preferred key server */
    PGPSUBTYPE_PRIMARY_USERID	=  25, /*!< primary user id */
    PGPSUBTYPE_POLICY_URL	=  26, /*!< policy URL */
    PGPSUBTYPE_KEY_FLAGS	=  27, /*!< key flags */
    PGPSUBTYPE_SIGNER_USERID	=  28, /*!< signer's user id */
    PGPSUBTYPE_REVOKE_REASON	=  29, /*!< reason for revocation */
    PGPSUBTYPE_FEATURES		=  30, /*!< feature flags (gpg) */
    PGPSUBTYPE_EMBEDDED_SIG	=  32, /*!< embedded signature (gpg) */

    PGPSUBTYPE_INTERNAL_100	= 100, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_101	= 101, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_102	= 102, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_103	= 103, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_104	= 104, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_105	= 105, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_106	= 106, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_107	= 107, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_108	= 108, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_109	= 109, /*!< internal or user-defined */
    PGPSUBTYPE_INTERNAL_110	= 110, /*!< internal or user-defined */

    PGPSUBTYPE_CRITICAL		= 128  /*!< critical subpacket marker */
} pgpSubType;

/** \ingroup rpmpgp
 * 5.2. Signature Packet (Tag 2)
 *
 * A signature packet describes a binding between some public key and
 * some data. The most common signatures are a signature of a file or a
 * block of text, and a signature that is a certification of a user ID.
 *
 * Two versions of signature packets are defined.  Version 3 provides
 * basic signature information, while version 4 provides an expandable
 * format with subpackets that can specify more information about the
 * signature. PGP 2.6.x only accepts version 3 signatures.
 *
 * Implementations MUST accept V3 signatures. Implementations SHOULD
 * generate V4 signatures.  Implementations MAY generate a V3 signature
 * that can be verified by PGP 2.6.x.
 *
 * Note that if an implementation is creating an encrypted and signed
 * message that is encrypted to a V3 key, it is reasonable to create a
 * V3 signature.
 */
typedef union pgpPktSig_u {
    struct pgpPktSigV3_s v3;
    struct pgpPktSigV4_s v4;
} * pgpPktSig;

/**
 * 5.3. Symmetric-Key Encrypted Session-Key Packets (Tag 3)
 *
 * The Symmetric-Key Encrypted Session Key packet holds the symmetric-
 * key encryption of a session key used to encrypt a message.  Zero or
 * more Encrypted Session Key packets and/or Symmetric-Key Encrypted
 * Session Key packets may precede a Symmetrically Encrypted Data Packet
 * that holds an encrypted message.  The message is encrypted with a
 * session key, and the session key is itself encrypted and stored in
 * the Encrypted Session Key packet or the Symmetric-Key Encrypted
 * Session Key packet.
 *
 * If the Symmetrically Encrypted Data Packet is preceded by one or more
 * Symmetric-Key Encrypted Session Key packets, each specifies a
 * passphrase that may be used to decrypt the message.  This allows a
 * message to be encrypted to a number of public keys, and also to one
 * or more pass phrases. This packet type is new, and is not generated
 * by PGP 2.x or PGP 5.0.
 *
 * The body of this packet consists of:
 *   - A one-octet version number. The only currently defined version
 *     is 4.
 *   - A one-octet number describing the symmetric algorithm used.
 *   - A string-to-key (S2K) specifier, length as defined above.
 *   - Optionally, the encrypted session key itself, which is decrypted
 *     with the string-to-key object.
 *
 */
typedef struct pgpPktSymkey_s {
    uint8_t version;	/*!< version number (4). */
    uint8_t symkey_algo;
    uint8_t s2k[1];
} pgpPktSymkey;

/** \ingroup rpmpgp
 * 5.4. One-Pass Signature Packets (Tag 4)
 *
 * The One-Pass Signature packet precedes the signed data and contains
 * enough information to allow the receiver to begin calculating any
 * hashes needed to verify the signature.  It allows the Signature
 * Packet to be placed at the end of the message, so that the signer can
 * compute the entire signed message in one pass.
 *
 * A One-Pass Signature does not interoperate with PGP 2.6.x or earlier.
 *
 * The body of this packet consists of:
 *   - A one-octet version number. The current version is 3.
 *   - A one-octet signature type. Signature types are described in
 *     section 5.2.1.
 *   - A one-octet number describing the hash algorithm used.
 *   - A one-octet number describing the public key algorithm used.
 *   - An eight-octet number holding the key ID of the signing key.
 *   - A one-octet number holding a flag showing whether the signature
 *     is nested.  A zero value indicates that the next packet is
 *     another One-Pass Signature packet that describes another
 *     signature to be applied to the same message data.
 *
 * Note that if a message contains more than one one-pass signature,
 * then the signature packets bracket the message; that is, the first
 * signature packet after the message corresponds to the last one-pass
 * packet and the final signature packet corresponds to the first one-
 * pass packet.
 */
typedef struct pgpPktOnepass_s {
    uint8_t version;	/*!< version number (3). */
    uint8_t sigtype;	/*!< signature type. */
    uint8_t hash_algo;	/*!< hash algorithm. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
    pgpKeyID_t signid;	/*!< key ID of signer. */
    uint8_t nested;
} * pgpPktOnepass;

/** \ingroup rpmpgp
 * 5.5.1. Key Packet Variants
 *
 * 5.5.1.1. Public Key Packet (Tag 6)
 *
 * A Public Key packet starts a series of packets that forms an OpenPGP
 * key (sometimes called an OpenPGP certificate).
 *
 * 5.5.1.2. Public Subkey Packet (Tag 14)
 *
 * A Public Subkey packet (tag 14) has exactly the same format as a
 * Public Key packet, but denotes a subkey. One or more subkeys may be
 * associated with a top-level key.  By convention, the top-level key
 * provides signature services, and the subkeys provide encryption
 * services.
 *
 * Note: in PGP 2.6.x, tag 14 was intended to indicate a comment packet.
 * This tag was selected for reuse because no previous version of PGP
 * ever emitted comment packets but they did properly ignore them.
 * Public Subkey packets are ignored by PGP 2.6.x and do not cause it to
 * fail, providing a limited degree of backward compatibility.
 *
 * 5.5.1.3. Secret Key Packet (Tag 5)
 *
 * A Secret Key packet contains all the information that is found in a
 * Public Key packet, including the public key material, but also
 * includes the secret key material after all the public key fields.
 *
 * 5.5.1.4. Secret Subkey Packet (Tag 7)
 *
 * A Secret Subkey packet (tag 7) is the subkey analog of the Secret Key
 * packet, and has exactly the same format.
 *
 * 5.5.2. Public Key Packet Formats
 *
 * There are two versions of key-material packets. Version 3 packets
 * were first generated by PGP 2.6. Version 2 packets are identical in
 * format to Version 3 packets, but are generated by PGP 2.5 or before.
 * V2 packets are deprecated and they MUST NOT be generated.  PGP 5.0
 * introduced version 4 packets, with new fields and semantics.  PGP
 * 2.6.x will not accept key-material packets with versions greater than
 * 3.
 *
 * OpenPGP implementations SHOULD create keys with version 4 format. An
 * implementation MAY generate a V3 key to ensure interoperability with
 * old software; note, however, that V4 keys correct some security
 * deficiencies in V3 keys. These deficiencies are described below. An
 * implementation MUST NOT create a V3 key with a public key algorithm
 * other than RSA.
 *
 * A version 3 public key or public subkey packet contains:
 *   - A one-octet version number (3).
 *   - A four-octet number denoting the time that the key was created.
 *   - A two-octet number denoting the time in days that this key is
 *     valid. If this number is zero, then it does not expire.
 *   - A one-octet number denoting the public key algorithm of this key
 *   - A series of multi-precision integers comprising the key
 *     material:
 *       - a multiprecision integer (MPI) of RSA public modulus n;
 *       - an MPI of RSA public encryption exponent e.
 *
 * V3 keys SHOULD only be used for backward compatibility because of
 * three weaknesses in them. First, it is relatively easy to construct a
 * V3 key that has the same key ID as any other key because the key ID
 * is simply the low 64 bits of the public modulus. Secondly, because
 * the fingerprint of a V3 key hashes the key material, but not its
 * length, which increases the opportunity for fingerprint collisions.
 * Third, there are minor weaknesses in the MD5 hash algorithm that make
 * developers prefer other algorithms. See below for a fuller discussion
 * of key IDs and fingerprints.
 *
 */
typedef struct pgpPktKeyV3_s {
    uint8_t version;	/*!< version number (3). */
    pgpTime_t time;	/*!< time that the key was created. */
    uint8_t valid[2];	/*!< time in days that this key is valid. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
} * pgpPktKeyV3;

/** \ingroup rpmpgp
 * The version 4 format is similar to the version 3 format except for
 * the absence of a validity period.  This has been moved to the
 * signature packet.  In addition, fingerprints of version 4 keys are
 * calculated differently from version 3 keys, as described in section
 * "Enhanced Key Formats."
 *
 * A version 4 packet contains:
 *   - A one-octet version number (4).
 *   - A four-octet number denoting the time that the key was created.
 *   - A one-octet number denoting the public key algorithm of this key
 *   - A series of multi-precision integers comprising the key
 *     material.  This algorithm-specific portion is:
 *
 *     Algorithm Specific Fields for RSA public keys:
 *       - multiprecision integer (MPI) of RSA public modulus n;
 *       - MPI of RSA public encryption exponent e.
 *
 *     Algorithm Specific Fields for DSA public keys:
 *       - MPI of DSA prime p;
 *       - MPI of DSA group order q (q is a prime divisor of p-1);
 *       - MPI of DSA group generator g;
 *       - MPI of DSA public key value y (= g**x where x is secret).
 *
 *     Algorithm Specific Fields for Elgamal public keys:
 *       - MPI of Elgamal prime p;
 *       - MPI of Elgamal group generator g;
 *       - MPI of Elgamal public key value y (= g**x where x is
 *         secret).
 *
 */
typedef struct pgpPktKeyV4_s {
    uint8_t version;	/*!< version number (4). */
    pgpTime_t time;	/*!< time that the key was created. */
    uint8_t pubkey_algo;	/*!< public key algorithm. */
} * pgpPktKeyV4;

/** \ingroup rpmpgp
 * 5.5.3. Secret Key Packet Formats
 *
 * The Secret Key and Secret Subkey packets contain all the data of the
 * Public Key and Public Subkey packets, with additional algorithm-
 * specific secret key data appended, in encrypted form.
 *
 * The packet contains:
 *   - A Public Key or Public Subkey packet, as described above
 *   - One octet indicating string-to-key usage conventions.  0
 *     indicates that the secret key data is not encrypted.  255
 *     indicates that a string-to-key specifier is being given.  Any
 *     other value is a symmetric-key encryption algorithm specifier.
 *   - [Optional] If string-to-key usage octet was 255, a one-octet
 *     symmetric encryption algorithm.
 *   - [Optional] If string-to-key usage octet was 255, a string-to-key
 *     specifier.  The length of the string-to-key specifier is implied
 *     by its type, as described above.
 *   - [Optional] If secret data is encrypted, eight-octet Initial
 *     Vector (IV).
 *   - Encrypted multi-precision integers comprising the secret key
 *     data. These algorithm-specific fields are as described below.
 *   - Two-octet checksum of the plaintext of the algorithm-specific
 *     portion (sum of all octets, mod 65536).
 *
 *     Algorithm Specific Fields for RSA secret keys:
 *     - multiprecision integer (MPI) of RSA secret exponent d.
 *     - MPI of RSA secret prime value p.
 *     - MPI of RSA secret prime value q (p < q).
 *     - MPI of u, the multiplicative inverse of p, mod q.
 *
 *     Algorithm Specific Fields for DSA secret keys:
 *     - MPI of DSA secret exponent x.
 *
 *     Algorithm Specific Fields for Elgamal secret keys:
 *     - MPI of Elgamal secret exponent x.
 *
 * Secret MPI values can be encrypted using a passphrase.  If a string-
 * to-key specifier is given, that describes the algorithm for
 * converting the passphrase to a key, else a simple MD5 hash of the
 * passphrase is used.  Implementations SHOULD use a string-to-key
 * specifier; the simple hash is for backward compatibility. The cipher
 * for encrypting the MPIs is specified in the secret key packet.
 *
 * Encryption/decryption of the secret data is done in CFB mode using
 * the key created from the passphrase and the Initial Vector from the
 * packet. A different mode is used with V3 keys (which are only RSA)
 * than with other key formats. With V3 keys, the MPI bit count prefix
 * (i.e., the first two octets) is not encrypted.  Only the MPI non-
 * prefix data is encrypted.  Furthermore, the CFB state is
 * resynchronized at the beginning of each new MPI value, so that the
 * CFB block boundary is aligned with the start of the MPI data.
 *
 * With V4 keys, a simpler method is used.  All secret MPI values are
 * encrypted in CFB mode, including the MPI bitcount prefix.
 *
 * The 16-bit checksum that follows the algorithm-specific portion is
 * the algebraic sum, mod 65536, of the plaintext of all the algorithm-
 * specific octets (including MPI prefix and data).  With V3 keys, the
 * checksum is stored in the clear.  With V4 keys, the checksum is
 * encrypted like the algorithm-specific data.  This value is used to
 * check that the passphrase was correct.
 *
 */
typedef union pgpPktKey_u {
    struct pgpPktKeyV3_s v3;
    struct pgpPktKeyV4_s v4;
} pgpPktKey;

/* \ingroup rpmpgp
 * 5.6. Compressed Data Packet (Tag 8)
 *
 * The Compressed Data packet contains compressed data. Typically, this
 * packet is found as the contents of an encrypted packet, or following
 * a Signature or One-Pass Signature packet, and contains literal data
 * packets.
 *
 * The body of this packet consists of:
 *   - One octet that gives the algorithm used to compress the packet.
 *   - The remainder of the packet is compressed data.
 *
 * A Compressed Data Packet's body contains an block that compresses
 * some set of packets. See section "Packet Composition" for details on
 * how messages are formed.
 *
 * ZIP-compressed packets are compressed with raw RFC 1951 DEFLATE
 * blocks. Note that PGP V2.6 uses 13 bits of compression. If an
 * implementation uses more bits of compression, PGP V2.6 cannot
 * decompress it.
 *
 * ZLIB-compressed packets are compressed with RFC 1950 ZLIB-style
 * blocks.
 */
typedef struct pgpPktCdata_s {
    uint8_t compressalgo;
    uint8_t data[1];
} pgpPktCdata;

/* \ingroup rpmpgp
 * 5.7. Symmetrically Encrypted Data Packet (Tag 9)
 *
 * The Symmetrically Encrypted Data packet contains data encrypted with
 * a symmetric-key algorithm. When it has been decrypted, it will
 * typically contain other packets (often literal data packets or
 * compressed data packets).
 *
 * The body of this packet consists of:
 *   - Encrypted data, the output of the selected symmetric-key cipher
 *     operating in PGP's variant of Cipher Feedback (CFB) mode.
 *
 * The symmetric cipher used may be specified in an Public-Key or
 * Symmetric-Key Encrypted Session Key packet that precedes the
 * Symmetrically Encrypted Data Packet.  In that case, the cipher
 * algorithm octet is prefixed to the session key before it is
 * encrypted.  If no packets of these types precede the encrypted data,
 * the IDEA algorithm is used with the session key calculated as the MD5
 * hash of the passphrase.
 *
 * The data is encrypted in CFB mode, with a CFB shift size equal to the
 * cipher's block size.  The Initial Vector (IV) is specified as all
 * zeros.  Instead of using an IV, OpenPGP prefixes a 10-octet string to
 * the data before it is encrypted.  The first eight octets are random,
 * and the 9th and 10th octets are copies of the 7th and 8th octets,
 * respectively. After encrypting the first 10 octets, the CFB state is
 * resynchronized if the cipher block size is 8 octets or less.  The
 * last 8 octets of ciphertext are passed through the cipher and the
 * block boundary is reset.
 *
 * The repetition of 16 bits in the 80 bits of random data prefixed to
 * the message allows the receiver to immediately check whether the
 * session key is incorrect.
 */
typedef struct pgpPktEdata_s {
    uint8_t data[1];
} pgpPktEdata;

/* \ingroup rpmpgp
 * 5.8. Marker Packet (Obsolete Literal Packet) (Tag 10)
 *
 * An experimental version of PGP used this packet as the Literal
 * packet, but no released version of PGP generated Literal packets with
 * this tag. With PGP 5.x, this packet has been re-assigned and is
 * reserved for use as the Marker packet.
 *
 * The body of this packet consists of:
 *   - The three octets 0x50, 0x47, 0x50 (which spell "PGP" in UTF-8).
 *
 * Such a packet MUST be ignored when received.  It may be placed at the
 * beginning of a message that uses features not available in PGP 2.6.x
 * in order to cause that version to report that newer software is
 * necessary to process the message.
 */
/* \ingroup rpmpgp
 * 5.9. Literal Data Packet (Tag 11)
 *
 * A Literal Data packet contains the body of a message; data that is
 * not to be further interpreted.
 *
 * The body of this packet consists of:
 *   - A one-octet field that describes how the data is formatted.
 *
 * If it is a 'b' (0x62), then the literal packet contains binary data.
 * If it is a 't' (0x74), then it contains text data, and thus may need
 * line ends converted to local form, or other text-mode changes.  RFC
 * 1991 also defined a value of 'l' as a 'local' mode for machine-local
 * conversions.  This use is now deprecated.
 *   - File name as a string (one-octet length, followed by file name),
 *     if the encrypted data should be saved as a file.
 *
 * If the special name "_CONSOLE" is used, the message is considered to
 * be "for your eyes only".  This advises that the message data is
 * unusually sensitive, and the receiving program should process it more
 * carefully, perhaps avoiding storing the received data to disk, for
 * example.
 *   - A four-octet number that indicates the modification date of the
 *     file, or the creation time of the packet, or a zero that
 *     indicates the present time.
 *   - The remainder of the packet is literal data.
 *
 * Text data is stored with <CR><LF> text endings (i.e. network-normal
 * line endings).  These should be converted to native line endings by
 * the receiving software.
 */
typedef struct pgpPktLdata_s {
    uint8_t format;
    uint8_t filenamelen;
    uint8_t filename[1];
} pgpPktLdata;

/* \ingroup rpmpgp
 * 5.10. Trust Packet (Tag 12)
 *
 * The Trust packet is used only within keyrings and is not normally
 * exported.  Trust packets contain data that record the user's
 * specifications of which key holders are trustworthy introducers,
 * along with other information that implementing software uses for
 * trust information.
 *
 * Trust packets SHOULD NOT be emitted to output streams that are
 * transferred to other users, and they SHOULD be ignored on any input
 * other than local keyring files.
 */
typedef struct pgpPktTrust_s {
    uint8_t flag;
} pgpPktTrust;

/* \ingroup rpmpgp
 * 5.11. User ID Packet (Tag 13)
 *
 * A User ID packet consists of data that is intended to represent the
 * name and email address of the key holder.  By convention, it includes
 * an RFC 822 mail name, but there are no restrictions on its content.
 * The packet length in the header specifies the length of the user id.
 * If it is text, it is encoded in UTF-8.
 *
 */
typedef struct pgpPktUid_s {
    uint8_t userid[1];
} pgpPktUid;

/** \ingroup rpmpgp
 */
union pgpPktPre_u {
    pgpPktPubkey pubkey;	/*!< 5.1. Public-Key Encrypted Session Key */
    pgpPktSig sig;		/*!< 5.2. Signature */
    pgpPktSymkey symkey;	/*!< 5.3. Symmetric-Key Encrypted Session-Key */
    pgpPktOnepass onepass;	/*!< 5.4. One-Pass Signature */
    pgpPktKey key;		/*!< 5.5. Key Material */
    pgpPktCdata cdata;		/*!< 5.6. Compressed Data */
    pgpPktEdata edata;		/*!< 5.7. Symmetrically Encrypted Data */
				/*!< 5.8. Marker (obsolete) */
    pgpPktLdata ldata;		/*!< 5.9. Literal Data */
    pgpPktTrust tdata;		/*!< 5.10. Trust */
    pgpPktUid uid;		/*!< 5.11. User ID */
};

/** \ingroup rpmpgp
 */
typedef enum pgpArmor_e {
    PGPARMOR_ERR_CRC_CHECK		= -7,
    PGPARMOR_ERR_BODY_DECODE		= -6,
    PGPARMOR_ERR_CRC_DECODE		= -5,
    PGPARMOR_ERR_NO_END_PGP		= -4,
    PGPARMOR_ERR_UNKNOWN_PREAMBLE_TAG	= -3,
    PGPARMOR_ERR_UNKNOWN_ARMOR_TYPE	= -2,
    PGPARMOR_ERR_NO_BEGIN_PGP		= -1,
#define	PGPARMOR_ERROR	PGPARMOR_ERR_NO_BEGIN_PGP
    PGPARMOR_NONE		=  0,
    PGPARMOR_MESSAGE		=  1, /*!< MESSAGE */
    PGPARMOR_PUBKEY		=  2, /*!< PUBLIC KEY BLOCK */
    PGPARMOR_SIGNATURE		=  3, /*!< SIGNATURE */
    PGPARMOR_SIGNED_MESSAGE	=  4, /*!< SIGNED MESSAGE */
    PGPARMOR_FILE		=  5, /*!< ARMORED FILE */
    PGPARMOR_PRIVKEY		=  6, /*!< PRIVATE KEY BLOCK */
    PGPARMOR_SECKEY		=  7  /*!< SECRET KEY BLOCK */
} pgpArmor;

/** \ingroup rpmpgp
 */
typedef enum pgpArmorKey_e {
    PGPARMORKEY_VERSION		= 1, /*!< Version: */
    PGPARMORKEY_COMMENT		= 2, /*!< Comment: */
    PGPARMORKEY_MESSAGEID	= 3, /*!< MessageID: */
    PGPARMORKEY_HASH		= 4, /*!< Hash: */
    PGPARMORKEY_CHARSET		= 5  /*!< Charset: */
} pgpArmorKey;

typedef enum pgpValType_e {
    PGPVAL_TAG			= 1,
    PGPVAL_ARMORBLOCK		= 2,
    PGPVAL_ARMORKEY		= 3,
    PGPVAL_SIGTYPE		= 4,
    PGPVAL_SUBTYPE		= 5,
    PGPVAL_PUBKEYALGO		= 6,
    PGPVAL_SYMKEYALGO		= 7,
    PGPVAL_COMPRESSALGO		= 8,
    PGPVAL_HASHALGO		= 9,
    PGPVAL_SERVERPREFS		= 10,
} pgpValType;

/** \ingroup rpmpgp
 * Bit(s) to control digest operation.
 */
enum rpmDigestFlags_e {
    RPMDIGEST_NONE	= 0
};

typedef rpmFlags rpmDigestFlags;

/** \ingroup rpmpgp
 * Return string representation of am OpenPGP value.
 * @param type		type of value
 * @param val		byte value to lookup
 * @return		string value of byte
 */
const char * pgpValString(pgpValType type, uint8_t val);

/** \ingroup rpmpgp
 * Return (native-endian) integer from big-endian representation.
 * @param s		pointer to big-endian integer
 * @param nbytes	no. of bytes
 * @return		native-endian integer
 */
static inline
unsigned int pgpGrab(const uint8_t *s, size_t nbytes)
{
    size_t i = 0;
    size_t nb = (nbytes <= sizeof(i) ? nbytes : sizeof(i));
    while (nb--)
	i = (i << 8) | *s++;
    return i;
}

/** \ingroup rpmpgp
 * Return hex formatted representation of bytes.
 * @param p		bytes
 * @param plen		no. of bytes
 * @return		hex formatted string (malloc'ed)
 */
char * pgpHexStr(const uint8_t *p, size_t plen);

/** \ingroup rpmpgp
 * Calculate OpenPGP public key fingerprint.
 * @param pkt		OpenPGP packet (i.e. PGPTAG_PUBLIC_KEY)
 * @param pktlen	OpenPGP packet length (no. of bytes)
 * @retval fp		public key fingerprint
 * @retval fplen	public key fingerprint length
 * @return		0 on success, else -1
 */
int pgpPubkeyFingerprint(const uint8_t * pkt, size_t pktlen,
			 uint8_t **fp, size_t *fplen);

/** \ingroup rpmpgp
 * Calculate OpenPGP public key Key ID
 * @param pkt		OpenPGP packet (i.e. PGPTAG_PUBLIC_KEY)
 * @param pktlen	OpenPGP packet length (no. of bytes)
 * @retval keyid	public key Key ID
 * @return		0 on success, else -1
 */
int pgpPubkeyKeyID(const uint8_t * pkt, size_t pktlen, pgpKeyID_t keyid);

/** \ingroup rpmpgp
 * Parse a OpenPGP packet(s).
 * @param pkts		OpenPGP packet(s)
 * @param pktlen	OpenPGP packet(s) length (no. of bytes)
 * @param pkttype	Expected packet type (signature/key) or 0 for any
 * @retval ret		signature/pubkey packet parameters on success (alloced)
 * @return		-1 on error, 0 on success
 */
int pgpPrtParams(const uint8_t *pkts, size_t pktlen, unsigned int pkttype,
		 pgpDigParams * ret);

/** \ingroup rpmpgp
 * Parse subkey parameters from OpenPGP packet(s).
 * @param pkts		OpenPGP packet(s)
 * @param pktlen	OpenPGP packet(s) length (no. of bytes)
 * @param mainkey	parameters of main key
 * @param subkeys	array of subkey parameters (alloced)
 * @param subkeysCount	count of subkeys
 * @return		-1 on error, 0 on success
 */
int pgpPrtParamsSubkeys(const uint8_t *pkts, size_t pktlen,
			pgpDigParams mainkey, pgpDigParams **subkeys,
			int *subkeysCount);
/** \ingroup rpmpgp
 * Print/parse a OpenPGP packet(s).
 * @param pkts		OpenPGP packet(s)
 * @param pktlen	OpenPGP packet(s) length (no. of bytes)
 * @retval dig		parsed output of signature/pubkey packet parameters
 * @param printing	should packets be printed?
 * @return		-1 on error, 0 on success
 */
int pgpPrtPkts(const uint8_t *pkts, size_t pktlen, pgpDig dig, int printing);

/** \ingroup rpmpgp
 * Parse armored OpenPGP packets from a file.
 * @param fn		file name
 * @retval pkt		dearmored OpenPGP packet(s) (malloced)
 * @retval pktlen	dearmored OpenPGP packet(s) length in bytes
 * @return		type of armor found
 */
pgpArmor pgpReadPkts(const char * fn, uint8_t ** pkt, size_t * pktlen);

/** \ingroup rpmpgp
 * Parse armored OpenPGP packets from memory.
 * @param armor		armored OpenPGP packet string
 * @retval pkt		dearmored OpenPGP packet(s) (malloced)
 * @retval pktlen	dearmored OpenPGP packet(s) length in bytes
 * @return		type of armor found
 */
pgpArmor pgpParsePkts(const char *armor, uint8_t ** pkt, size_t * pktlen);

/** \ingroup rpmpgp
 * Return a length of the first public key certificate in a buffer given
 * by pkts that contains one or more certificates. A public key certificate
 * consits of packets like Public key packet, User ID packet and so on.
 * In a buffer every certificate starts with Public key packet and it ends
 * with the start of the next certificate or with the end of the buffer.
 *
 * @param pkts		pointer to a buffer with certificates
 * @param pktslen	length of the buffer with certificates
 * @param certlen	length of the first certificate in the buffer
 * @return		0 on success
 */
int pgpPubKeyCertLen(const uint8_t *pkts, size_t pktslen, size_t *certlen);

/** \ingroup rpmpgp
 * Wrap a OpenPGP packets in ascii armor for transport.
 * @param atype		type of armor
 * @param s		binary pkt data
 * @param ns		binary pkt data length
 * @return		formatted string
 */
char * pgpArmorWrap(int atype, const unsigned char * s, size_t ns);

/** \ingroup rpmpgp
 * Create a container for parsed OpenPGP packet(s).
 * @return		container
 */
pgpDig pgpNewDig(void);

/** \ingroup rpmpgp
 * Release (malloc'd) data from container.
 * @param dig		container
 */
void pgpCleanDig(pgpDig dig);

/** \ingroup rpmpgp
 * Destroy a container for parsed OpenPGP packet(s).
 * @param dig		container
 * @return		NULL always
 */
pgpDig pgpFreeDig(pgpDig dig);

/** \ingroup rpmpgp
 * Retrieve parameters for parsed OpenPGP packet(s).
 * @param dig		container
 * @param pkttype	type of params to retrieve (signature / pubkey)
 * @return		pointer to OpenPGP parameters, NULL on error/not found
 */
pgpDigParams pgpDigGetParams(pgpDig dig, unsigned int pkttype);

/** \ingroup rpmpgp
 * Compare OpenPGP packet parameters
 * param p1		1st parameter container
 * param p2		2nd parameter container
 * return		1 if the parameters differ, 0 otherwise
 */
int pgpDigParamsCmp(pgpDigParams p1, pgpDigParams p2);

/** \ingroup rpmpgp
 * Retrieve OpenPGP algorithm parameters
 * param digp		parameter container
 * param algotype	PGPVAL_HASHALGO / PGPVAL_PUBKEYALGO
 * return		algorithm value, 0 on error
 */
unsigned int pgpDigParamsAlgo(pgpDigParams digp, unsigned int algotype);

/** \ingroup rpmpgp
 * Destroy parsed OpenPGP packet parameter(s).
 * @param digp		parameter container
 * @return		NULL always
 */
pgpDigParams pgpDigParamsFree(pgpDigParams digp);

/** \ingroup rpmpgp
 * Verify a PGP signature.
 * @param key		public key
 * @param sig		signature
 * @param hashctx	digest context
 * @return 		RPMRC_OK on success 
 */
rpmRC pgpVerifySignature(pgpDigParams key, pgpDigParams sig, DIGEST_CTX hashctx);

/** \ingroup rpmpgp
 * Verify a PGP signature.
 * @deprecated		use pgpVerifySignature() instead
 *
 * @param dig		container
 * @param hashctx	digest context
 * @return 		RPMRC_OK on success 
 */
rpmRC pgpVerifySig(pgpDig dig, DIGEST_CTX hashctx);

/** \ingroup rpmpgp
 * Return a string identification of a PGP signature/pubkey.
 * @param digp		signature/pubkey container
 * @return		string describing the item and parameters
 */
char *pgpIdentItem(pgpDigParams digp);

/** \ingroup rpmpgp
 * Perform cryptography initialization.
 * It must be called before any cryptography can be used within rpm.
 * It's not normally necessary to call it directly as it's called in
 * general rpm initialization routines.
 * @return		0 on success, -1 on failure
 */
int rpmInitCrypto(void);

/** \ingroup rpmpgp
 * Shutdown cryptography
 */
int rpmFreeCrypto(void);

/** \ingroup rpmpgp
 * Duplicate a digest context.
 * @param octx		existing digest context
 * @return		duplicated digest context
 */
DIGEST_CTX rpmDigestDup(DIGEST_CTX octx);

/** \ingroup rpmpgp
 * Obtain digest length in bytes.
 * @param hashalgo	type of digest
 * @return		digest length, zero on invalid algorithm
 */
size_t rpmDigestLength(int hashalgo);

/** \ingroup rpmpgp
 * Initialize digest.
 * Set bit count to 0 and buffer to mysterious initialization constants.
 * @param hashalgo	type of digest
 * @param flags		bit(s) to control digest operation
 * @return		digest context
 */
DIGEST_CTX rpmDigestInit(int hashalgo, rpmDigestFlags flags);

/** \ingroup rpmpgp
 * Update context with next plain text buffer.
 * @param ctx		digest context
 * @param data		next data buffer
 * @param len		no. bytes of data
 * @return		0 on success
 */
int rpmDigestUpdate(DIGEST_CTX ctx, const void * data, size_t len);

/** \ingroup rpmpgp
 * Return digest and destroy context.
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first)
 *
 * @param ctx		digest context
 * @retval datap	address of returned digest
 * @retval lenp		address of digest length
 * @param asAscii	return digest as ascii string?
 * @return		0 on success
 */
int rpmDigestFinal(DIGEST_CTX ctx,
	void ** datap,
	size_t * lenp, int asAscii);

/** \ingroup rpmpgp
 * Create a new digest bundle.
 * @return		New digest bundle
 */
rpmDigestBundle rpmDigestBundleNew(void);

/** \ingroup rpmpgp
 * Free a digest bundle and all contained digest contexts.
 * @param bundle	digest bundle
 * @return		NULL always
 */
rpmDigestBundle rpmDigestBundleFree(rpmDigestBundle bundle);

/** \ingroup rpmpgp
 * Add a new type of digest to a bundle. Same as calling
 * rpmDigestBundleAddID() with algo == id value.
 * @param bundle	digest bundle
 * @param algo		type of digest
 * @param flags		bit(s) to control digest operation
 * @return		0 on success
 */
int rpmDigestBundleAdd(rpmDigestBundle bundle, int algo,
			rpmDigestFlags flags);

/** \ingroup rpmpgp
 * Add a new type of digest to a bundle.
 * @param bundle	digest bundle
 * @param algo		type of digest
 * @param id		id of digest (arbitrary, must be > 0)
 * @param flags		bit(s) to control digest operation
 * @return		0 on success
 */
int rpmDigestBundleAddID(rpmDigestBundle bundle, int algo, int id,
			 rpmDigestFlags flags);

/** \ingroup rpmpgp
 * Update contexts within bundle with next plain text buffer.
 * @param bundle	digest bundle
 * @param data		next data buffer
 * @param len		no. bytes of data
 * @return		0 on success
 */
int rpmDigestBundleUpdate(rpmDigestBundle bundle, const void *data, size_t len);

/** \ingroup rpmpgp
 * Return digest from a bundle and destroy context, see rpmDigestFinal().
 *
 * @param bundle	digest bundle
 * @param id		id of digest to return
 * @retval datap	address of returned digest
 * @retval lenp		address of digest length
 * @param asAscii	return digest as ascii string?
 * @return		0 on success
 */
int rpmDigestBundleFinal(rpmDigestBundle bundle, int id,
			 void ** datap, size_t * lenp, int asAscii);

/** \ingroup rpmpgp
 * Duplicate a digest context from a bundle.
 * @param bundle	digest bundle
 * @param id		id of digest to dup
 * @return		duplicated digest context
 */
DIGEST_CTX rpmDigestBundleDupCtx(rpmDigestBundle bundle, int id);

#ifdef __cplusplus
}
#endif

#endif	/* H_RPMPGP */
