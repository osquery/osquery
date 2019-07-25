/* Output of mkstrtable.awk.  DO NOT EDIT.  */

/* err-codes.h - List of error codes and their description.
   Copyright (C) 2003, 2004 g10 Code GmbH

   This file is part of libgpg-error.

   libgpg-error is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   libgpg-error is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with libgpg-error; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */


/* The purpose of this complex string table is to produce
   optimal code with a minimum of relocations.  */

static const char msgstr[] = 
  gettext_noop ("Success") "\0"
  gettext_noop ("General error") "\0"
  gettext_noop ("Unknown packet") "\0"
  gettext_noop ("Unknown version in packet") "\0"
  gettext_noop ("Invalid public key algorithm") "\0"
  gettext_noop ("Invalid digest algorithm") "\0"
  gettext_noop ("Bad public key") "\0"
  gettext_noop ("Bad secret key") "\0"
  gettext_noop ("Bad signature") "\0"
  gettext_noop ("No public key") "\0"
  gettext_noop ("Checksum error") "\0"
  gettext_noop ("Bad passphrase") "\0"
  gettext_noop ("Invalid cipher algorithm") "\0"
  gettext_noop ("Cannot open keyring") "\0"
  gettext_noop ("Invalid packet") "\0"
  gettext_noop ("Invalid armor") "\0"
  gettext_noop ("No user ID") "\0"
  gettext_noop ("No secret key") "\0"
  gettext_noop ("Wrong secret key used") "\0"
  gettext_noop ("Bad session key") "\0"
  gettext_noop ("Unknown compression algorithm") "\0"
  gettext_noop ("Number is not prime") "\0"
  gettext_noop ("Invalid encoding method") "\0"
  gettext_noop ("Invalid encryption scheme") "\0"
  gettext_noop ("Invalid signature scheme") "\0"
  gettext_noop ("Invalid attribute") "\0"
  gettext_noop ("No value") "\0"
  gettext_noop ("Not found") "\0"
  gettext_noop ("Value not found") "\0"
  gettext_noop ("Syntax error") "\0"
  gettext_noop ("Bad MPI value") "\0"
  gettext_noop ("Invalid passphrase") "\0"
  gettext_noop ("Invalid signature class") "\0"
  gettext_noop ("Resources exhausted") "\0"
  gettext_noop ("Invalid keyring") "\0"
  gettext_noop ("Trust DB error") "\0"
  gettext_noop ("Bad certificate") "\0"
  gettext_noop ("Invalid user ID") "\0"
  gettext_noop ("Unexpected error") "\0"
  gettext_noop ("Time conflict") "\0"
  gettext_noop ("Keyserver error") "\0"
  gettext_noop ("Wrong public key algorithm") "\0"
  gettext_noop ("Tribute to D. A.") "\0"
  gettext_noop ("Weak encryption key") "\0"
  gettext_noop ("Invalid key length") "\0"
  gettext_noop ("Invalid argument") "\0"
  gettext_noop ("Syntax error in URI") "\0"
  gettext_noop ("Invalid URI") "\0"
  gettext_noop ("Network error") "\0"
  gettext_noop ("Unknown host") "\0"
  gettext_noop ("Selftest failed") "\0"
  gettext_noop ("Data not encrypted") "\0"
  gettext_noop ("Data not processed") "\0"
  gettext_noop ("Unusable public key") "\0"
  gettext_noop ("Unusable secret key") "\0"
  gettext_noop ("Invalid value") "\0"
  gettext_noop ("Bad certificate chain") "\0"
  gettext_noop ("Missing certificate") "\0"
  gettext_noop ("No data") "\0"
  gettext_noop ("Bug") "\0"
  gettext_noop ("Not supported") "\0"
  gettext_noop ("Invalid operation code") "\0"
  gettext_noop ("Timeout") "\0"
  gettext_noop ("Internal error") "\0"
  gettext_noop ("EOF (gcrypt)") "\0"
  gettext_noop ("Invalid object") "\0"
  gettext_noop ("Provided object is too short") "\0"
  gettext_noop ("Provided object is too large") "\0"
  gettext_noop ("Missing item in object") "\0"
  gettext_noop ("Not implemented") "\0"
  gettext_noop ("Conflicting use") "\0"
  gettext_noop ("Invalid cipher mode") "\0"
  gettext_noop ("Invalid flag") "\0"
  gettext_noop ("Invalid handle") "\0"
  gettext_noop ("Result truncated") "\0"
  gettext_noop ("Incomplete line") "\0"
  gettext_noop ("Invalid response") "\0"
  gettext_noop ("No agent running") "\0"
  gettext_noop ("Agent error") "\0"
  gettext_noop ("Invalid data") "\0"
  gettext_noop ("Unspecific Assuan server fault") "\0"
  gettext_noop ("General Assuan error") "\0"
  gettext_noop ("Invalid session key") "\0"
  gettext_noop ("Invalid S-expression") "\0"
  gettext_noop ("Unsupported algorithm") "\0"
  gettext_noop ("No pinentry") "\0"
  gettext_noop ("pinentry error") "\0"
  gettext_noop ("Bad PIN") "\0"
  gettext_noop ("Invalid name") "\0"
  gettext_noop ("Bad data") "\0"
  gettext_noop ("Invalid parameter") "\0"
  gettext_noop ("Wrong card") "\0"
  gettext_noop ("No dirmngr") "\0"
  gettext_noop ("dirmngr error") "\0"
  gettext_noop ("Certificate revoked") "\0"
  gettext_noop ("No CRL known") "\0"
  gettext_noop ("CRL too old") "\0"
  gettext_noop ("Line too long") "\0"
  gettext_noop ("Not trusted") "\0"
  gettext_noop ("Operation cancelled") "\0"
  gettext_noop ("Bad CA certificate") "\0"
  gettext_noop ("Certificate expired") "\0"
  gettext_noop ("Certificate too young") "\0"
  gettext_noop ("Unsupported certificate") "\0"
  gettext_noop ("Unknown S-expression") "\0"
  gettext_noop ("Unsupported protection") "\0"
  gettext_noop ("Corrupted protection") "\0"
  gettext_noop ("Ambiguous name") "\0"
  gettext_noop ("Card error") "\0"
  gettext_noop ("Card reset required") "\0"
  gettext_noop ("Card removed") "\0"
  gettext_noop ("Invalid card") "\0"
  gettext_noop ("Card not present") "\0"
  gettext_noop ("No PKCS15 application") "\0"
  gettext_noop ("Not confirmed") "\0"
  gettext_noop ("Configuration error") "\0"
  gettext_noop ("No policy match") "\0"
  gettext_noop ("Invalid index") "\0"
  gettext_noop ("Invalid ID") "\0"
  gettext_noop ("No SmartCard daemon") "\0"
  gettext_noop ("SmartCard daemon error") "\0"
  gettext_noop ("Unsupported protocol") "\0"
  gettext_noop ("Bad PIN method") "\0"
  gettext_noop ("Card not initialized") "\0"
  gettext_noop ("Unsupported operation") "\0"
  gettext_noop ("Wrong key usage") "\0"
  gettext_noop ("Nothing found") "\0"
  gettext_noop ("Wrong blob type") "\0"
  gettext_noop ("Missing value") "\0"
  gettext_noop ("Hardware problem") "\0"
  gettext_noop ("PIN blocked") "\0"
  gettext_noop ("Conditions of use not satisfied") "\0"
  gettext_noop ("PINs are not synced") "\0"
  gettext_noop ("Invalid CRL") "\0"
  gettext_noop ("BER error") "\0"
  gettext_noop ("Invalid BER") "\0"
  gettext_noop ("Element not found") "\0"
  gettext_noop ("Identifier not found") "\0"
  gettext_noop ("Invalid tag") "\0"
  gettext_noop ("Invalid length") "\0"
  gettext_noop ("Invalid key info") "\0"
  gettext_noop ("Unexpected tag") "\0"
  gettext_noop ("Not DER encoded") "\0"
  gettext_noop ("No CMS object") "\0"
  gettext_noop ("Invalid CMS object") "\0"
  gettext_noop ("Unknown CMS object") "\0"
  gettext_noop ("Unsupported CMS object") "\0"
  gettext_noop ("Unsupported encoding") "\0"
  gettext_noop ("Unsupported CMS version") "\0"
  gettext_noop ("Unknown algorithm") "\0"
  gettext_noop ("Invalid crypto engine") "\0"
  gettext_noop ("Public key not trusted") "\0"
  gettext_noop ("Decryption failed") "\0"
  gettext_noop ("Key expired") "\0"
  gettext_noop ("Signature expired") "\0"
  gettext_noop ("Encoding problem") "\0"
  gettext_noop ("Invalid state") "\0"
  gettext_noop ("Duplicated value") "\0"
  gettext_noop ("Missing action") "\0"
  gettext_noop ("ASN.1 module not found") "\0"
  gettext_noop ("Invalid OID string") "\0"
  gettext_noop ("Invalid time") "\0"
  gettext_noop ("Invalid CRL object") "\0"
  gettext_noop ("Unsupported CRL version") "\0"
  gettext_noop ("Invalid certificate object") "\0"
  gettext_noop ("Unknown name") "\0"
  gettext_noop ("A locale function failed") "\0"
  gettext_noop ("Not locked") "\0"
  gettext_noop ("Protocol violation") "\0"
  gettext_noop ("Invalid MAC") "\0"
  gettext_noop ("Invalid request") "\0"
  gettext_noop ("Unknown extension") "\0"
  gettext_noop ("Unknown critical extension") "\0"
  gettext_noop ("Locked") "\0"
  gettext_noop ("Unknown option") "\0"
  gettext_noop ("Unknown command") "\0"
  gettext_noop ("Not operational") "\0"
  gettext_noop ("No passphrase given") "\0"
  gettext_noop ("No PIN given") "\0"
  gettext_noop ("Not enabled") "\0"
  gettext_noop ("No crypto engine") "\0"
  gettext_noop ("Missing key") "\0"
  gettext_noop ("Too many objects") "\0"
  gettext_noop ("Limit reached") "\0"
  gettext_noop ("Not initialized") "\0"
  gettext_noop ("Missing issuer certificate") "\0"
  gettext_noop ("No keyserver available") "\0"
  gettext_noop ("Invalid elliptic curve") "\0"
  gettext_noop ("Unknown elliptic curve") "\0"
  gettext_noop ("Duplicated key") "\0"
  gettext_noop ("Ambiguous result") "\0"
  gettext_noop ("No crypto context") "\0"
  gettext_noop ("Wrong crypto context") "\0"
  gettext_noop ("Bad crypto context") "\0"
  gettext_noop ("Conflict in the crypto context") "\0"
  gettext_noop ("Broken public key") "\0"
  gettext_noop ("Broken secret key") "\0"
  gettext_noop ("Invalid MAC algorithm") "\0"
  gettext_noop ("Operation fully cancelled") "\0"
  gettext_noop ("Operation not yet finished") "\0"
  gettext_noop ("Buffer too short") "\0"
  gettext_noop ("Invalid length specifier in S-expression") "\0"
  gettext_noop ("String too long in S-expression") "\0"
  gettext_noop ("Unmatched parentheses in S-expression") "\0"
  gettext_noop ("S-expression not canonical") "\0"
  gettext_noop ("Bad character in S-expression") "\0"
  gettext_noop ("Bad quotation in S-expression") "\0"
  gettext_noop ("Zero prefix in S-expression") "\0"
  gettext_noop ("Nested display hints in S-expression") "\0"
  gettext_noop ("Unmatched display hints") "\0"
  gettext_noop ("Unexpected reserved punctuation in S-expression") "\0"
  gettext_noop ("Bad hexadecimal character in S-expression") "\0"
  gettext_noop ("Odd hexadecimal numbers in S-expression") "\0"
  gettext_noop ("Bad octal character in S-expression") "\0"
  gettext_noop ("All subkeys are expired or revoked") "\0"
  gettext_noop ("Database is corrupted") "\0"
  gettext_noop ("Server indicated a failure") "\0"
  gettext_noop ("No name") "\0"
  gettext_noop ("No key") "\0"
  gettext_noop ("Legacy key") "\0"
  gettext_noop ("Request too short") "\0"
  gettext_noop ("Request too long") "\0"
  gettext_noop ("Object is in termination state") "\0"
  gettext_noop ("No certificate chain") "\0"
  gettext_noop ("Certificate is too large") "\0"
  gettext_noop ("Invalid record") "\0"
  gettext_noop ("The MAC does not verify") "\0"
  gettext_noop ("Unexpected message") "\0"
  gettext_noop ("Compression or decompression failed") "\0"
  gettext_noop ("A counter would wrap") "\0"
  gettext_noop ("Fatal alert message received") "\0"
  gettext_noop ("No cipher algorithm") "\0"
  gettext_noop ("Missing client certificate") "\0"
  gettext_noop ("Close notification received") "\0"
  gettext_noop ("Ticket expired") "\0"
  gettext_noop ("Bad ticket") "\0"
  gettext_noop ("Unknown identity") "\0"
  gettext_noop ("Bad certificate message in handshake") "\0"
  gettext_noop ("Bad certificate request message in handshake") "\0"
  gettext_noop ("Bad certificate verify message in handshake") "\0"
  gettext_noop ("Bad change cipher message in handshake") "\0"
  gettext_noop ("Bad client hello message in handshake") "\0"
  gettext_noop ("Bad server hello message in handshake") "\0"
  gettext_noop ("Bad server hello done message in handshake") "\0"
  gettext_noop ("Bad finished message in handshake") "\0"
  gettext_noop ("Bad server key exchange message in handshake") "\0"
  gettext_noop ("Bad client key exchange message in handshake") "\0"
  gettext_noop ("Bogus string") "\0"
  gettext_noop ("Forbidden") "\0"
  gettext_noop ("Key disabled") "\0"
  gettext_noop ("Not possible with a card based key") "\0"
  gettext_noop ("Invalid lock object") "\0"
  gettext_noop ("True") "\0"
  gettext_noop ("False") "\0"
  gettext_noop ("General IPC error") "\0"
  gettext_noop ("IPC accept call failed") "\0"
  gettext_noop ("IPC connect call failed") "\0"
  gettext_noop ("Invalid IPC response") "\0"
  gettext_noop ("Invalid value passed to IPC") "\0"
  gettext_noop ("Incomplete line passed to IPC") "\0"
  gettext_noop ("Line passed to IPC too long") "\0"
  gettext_noop ("Nested IPC commands") "\0"
  gettext_noop ("No data callback in IPC") "\0"
  gettext_noop ("No inquire callback in IPC") "\0"
  gettext_noop ("Not an IPC server") "\0"
  gettext_noop ("Not an IPC client") "\0"
  gettext_noop ("Problem starting IPC server") "\0"
  gettext_noop ("IPC read error") "\0"
  gettext_noop ("IPC write error") "\0"
  gettext_noop ("Too much data for IPC layer") "\0"
  gettext_noop ("Unexpected IPC command") "\0"
  gettext_noop ("Unknown IPC command") "\0"
  gettext_noop ("IPC syntax error") "\0"
  gettext_noop ("IPC call has been cancelled") "\0"
  gettext_noop ("No input source for IPC") "\0"
  gettext_noop ("No output source for IPC") "\0"
  gettext_noop ("IPC parameter error") "\0"
  gettext_noop ("Unknown IPC inquire") "\0"
  gettext_noop ("Crypto engine too old") "\0"
  gettext_noop ("Screen or window too small") "\0"
  gettext_noop ("Screen or window too large") "\0"
  gettext_noop ("Required environment variable not set") "\0"
  gettext_noop ("User ID already exists") "\0"
  gettext_noop ("Name already exists") "\0"
  gettext_noop ("Duplicated name") "\0"
  gettext_noop ("Object is too young") "\0"
  gettext_noop ("Object is too old") "\0"
  gettext_noop ("Unknown flag") "\0"
  gettext_noop ("Invalid execution order") "\0"
  gettext_noop ("Already fetched") "\0"
  gettext_noop ("Try again later") "\0"
  gettext_noop ("Wrong name") "\0"
  gettext_noop ("System bug detected") "\0"
  gettext_noop ("Unknown DNS error") "\0"
  gettext_noop ("Invalid DNS section") "\0"
  gettext_noop ("Invalid textual address form") "\0"
  gettext_noop ("Missing DNS query packet") "\0"
  gettext_noop ("Missing DNS answer packet") "\0"
  gettext_noop ("Connection closed in DNS") "\0"
  gettext_noop ("Verification failed in DNS") "\0"
  gettext_noop ("DNS Timeout") "\0"
  gettext_noop ("General LDAP error") "\0"
  gettext_noop ("General LDAP attribute error") "\0"
  gettext_noop ("General LDAP name error") "\0"
  gettext_noop ("General LDAP security error") "\0"
  gettext_noop ("General LDAP service error") "\0"
  gettext_noop ("General LDAP update error") "\0"
  gettext_noop ("Experimental LDAP error code") "\0"
  gettext_noop ("Private LDAP error code") "\0"
  gettext_noop ("Other general LDAP error") "\0"
  gettext_noop ("LDAP connecting failed (X)") "\0"
  gettext_noop ("LDAP referral limit exceeded") "\0"
  gettext_noop ("LDAP client loop") "\0"
  gettext_noop ("No LDAP results returned") "\0"
  gettext_noop ("LDAP control not found") "\0"
  gettext_noop ("Not supported by LDAP") "\0"
  gettext_noop ("LDAP connect error") "\0"
  gettext_noop ("Out of memory in LDAP") "\0"
  gettext_noop ("Bad parameter to an LDAP routine") "\0"
  gettext_noop ("User cancelled LDAP operation") "\0"
  gettext_noop ("Bad LDAP search filter") "\0"
  gettext_noop ("Unknown LDAP authentication method") "\0"
  gettext_noop ("Timeout in LDAP") "\0"
  gettext_noop ("LDAP decoding error") "\0"
  gettext_noop ("LDAP encoding error") "\0"
  gettext_noop ("LDAP local error") "\0"
  gettext_noop ("Cannot contact LDAP server") "\0"
  gettext_noop ("LDAP success") "\0"
  gettext_noop ("LDAP operations error") "\0"
  gettext_noop ("LDAP protocol error") "\0"
  gettext_noop ("Time limit exceeded in LDAP") "\0"
  gettext_noop ("Size limit exceeded in LDAP") "\0"
  gettext_noop ("LDAP compare false") "\0"
  gettext_noop ("LDAP compare true") "\0"
  gettext_noop ("LDAP authentication method not supported") "\0"
  gettext_noop ("Strong(er) LDAP authentication required") "\0"
  gettext_noop ("Partial LDAP results+referral received") "\0"
  gettext_noop ("LDAP referral") "\0"
  gettext_noop ("Administrative LDAP limit exceeded") "\0"
  gettext_noop ("Critical LDAP extension is unavailable") "\0"
  gettext_noop ("Confidentiality required by LDAP") "\0"
  gettext_noop ("LDAP SASL bind in progress") "\0"
  gettext_noop ("No such LDAP attribute") "\0"
  gettext_noop ("Undefined LDAP attribute type") "\0"
  gettext_noop ("Inappropriate matching in LDAP") "\0"
  gettext_noop ("Constraint violation in LDAP") "\0"
  gettext_noop ("LDAP type or value exists") "\0"
  gettext_noop ("Invalid syntax in LDAP") "\0"
  gettext_noop ("No such LDAP object") "\0"
  gettext_noop ("LDAP alias problem") "\0"
  gettext_noop ("Invalid DN syntax in LDAP") "\0"
  gettext_noop ("LDAP entry is a leaf") "\0"
  gettext_noop ("LDAP alias dereferencing problem") "\0"
  gettext_noop ("LDAP proxy authorization failure (X)") "\0"
  gettext_noop ("Inappropriate LDAP authentication") "\0"
  gettext_noop ("Invalid LDAP credentials") "\0"
  gettext_noop ("Insufficient access for LDAP") "\0"
  gettext_noop ("LDAP server is busy") "\0"
  gettext_noop ("LDAP server is unavailable") "\0"
  gettext_noop ("LDAP server is unwilling to perform") "\0"
  gettext_noop ("Loop detected by LDAP") "\0"
  gettext_noop ("LDAP naming violation") "\0"
  gettext_noop ("LDAP object class violation") "\0"
  gettext_noop ("LDAP operation not allowed on non-leaf") "\0"
  gettext_noop ("LDAP operation not allowed on RDN") "\0"
  gettext_noop ("Already exists (LDAP)") "\0"
  gettext_noop ("Cannot modify LDAP object class") "\0"
  gettext_noop ("LDAP results too large") "\0"
  gettext_noop ("LDAP operation affects multiple DSAs") "\0"
  gettext_noop ("Virtual LDAP list view error") "\0"
  gettext_noop ("Other LDAP error") "\0"
  gettext_noop ("Resources exhausted in LCUP") "\0"
  gettext_noop ("Security violation in LCUP") "\0"
  gettext_noop ("Invalid data in LCUP") "\0"
  gettext_noop ("Unsupported scheme in LCUP") "\0"
  gettext_noop ("Reload required in LCUP") "\0"
  gettext_noop ("LDAP cancelled") "\0"
  gettext_noop ("No LDAP operation to cancel") "\0"
  gettext_noop ("Too late to cancel LDAP") "\0"
  gettext_noop ("Cannot cancel LDAP") "\0"
  gettext_noop ("LDAP assertion failed") "\0"
  gettext_noop ("Proxied authorization denied by LDAP") "\0"
  gettext_noop ("User defined error code 1") "\0"
  gettext_noop ("User defined error code 2") "\0"
  gettext_noop ("User defined error code 3") "\0"
  gettext_noop ("User defined error code 4") "\0"
  gettext_noop ("User defined error code 5") "\0"
  gettext_noop ("User defined error code 6") "\0"
  gettext_noop ("User defined error code 7") "\0"
  gettext_noop ("User defined error code 8") "\0"
  gettext_noop ("User defined error code 9") "\0"
  gettext_noop ("User defined error code 10") "\0"
  gettext_noop ("User defined error code 11") "\0"
  gettext_noop ("User defined error code 12") "\0"
  gettext_noop ("User defined error code 13") "\0"
  gettext_noop ("User defined error code 14") "\0"
  gettext_noop ("User defined error code 15") "\0"
  gettext_noop ("User defined error code 16") "\0"
  gettext_noop ("System error w/o errno") "\0"
  gettext_noop ("Unknown system error") "\0"
  gettext_noop ("End of file") "\0"
  gettext_noop ("Unknown error code");

static const int msgidx[] =
  {
    0,
    8,
    22,
    37,
    63,
    92,
    117,
    132,
    147,
    161,
    175,
    190,
    205,
    230,
    250,
    265,
    279,
    290,
    304,
    326,
    342,
    372,
    392,
    416,
    442,
    467,
    485,
    494,
    504,
    520,
    533,
    547,
    566,
    590,
    610,
    626,
    641,
    657,
    673,
    690,
    704,
    720,
    747,
    764,
    784,
    803,
    820,
    840,
    852,
    866,
    879,
    895,
    914,
    933,
    953,
    973,
    987,
    1009,
    1029,
    1037,
    1041,
    1055,
    1078,
    1086,
    1101,
    1114,
    1129,
    1158,
    1187,
    1210,
    1226,
    1242,
    1262,
    1275,
    1290,
    1307,
    1323,
    1340,
    1357,
    1369,
    1382,
    1413,
    1434,
    1454,
    1475,
    1497,
    1509,
    1524,
    1532,
    1545,
    1554,
    1572,
    1583,
    1594,
    1608,
    1628,
    1641,
    1653,
    1667,
    1679,
    1699,
    1718,
    1738,
    1760,
    1784,
    1805,
    1828,
    1849,
    1864,
    1875,
    1895,
    1908,
    1921,
    1938,
    1960,
    1974,
    1994,
    2010,
    2024,
    2035,
    2055,
    2078,
    2099,
    2114,
    2135,
    2157,
    2173,
    2187,
    2203,
    2217,
    2234,
    2246,
    2278,
    2298,
    2310,
    2320,
    2332,
    2350,
    2371,
    2383,
    2398,
    2415,
    2430,
    2446,
    2460,
    2479,
    2498,
    2521,
    2542,
    2566,
    2584,
    2606,
    2629,
    2647,
    2659,
    2677,
    2694,
    2708,
    2725,
    2740,
    2763,
    2782,
    2795,
    2814,
    2838,
    2865,
    2878,
    2903,
    2914,
    2933,
    2945,
    2961,
    2979,
    3006,
    3013,
    3028,
    3044,
    3060,
    3080,
    3093,
    3105,
    3122,
    3134,
    3151,
    3165,
    3181,
    3208,
    3231,
    3254,
    3277,
    3292,
    3309,
    3327,
    3348,
    3367,
    3398,
    3416,
    3434,
    3456,
    3482,
    3509,
    3526,
    3567,
    3599,
    3637,
    3664,
    3694,
    3724,
    3752,
    3789,
    3813,
    3861,
    3903,
    3943,
    3979,
    4014,
    4036,
    4063,
    4071,
    4078,
    4089,
    4107,
    4124,
    4155,
    4176,
    4201,
    4216,
    4240,
    4259,
    4295,
    4316,
    4345,
    4365,
    4392,
    4420,
    4435,
    4446,
    4463,
    4500,
    4545,
    4589,
    4628,
    4666,
    4704,
    4747,
    4781,
    4826,
    4871,
    4884,
    4894,
    4907,
    4942,
    4962,
    4967,
    4973,
    4991,
    5014,
    5038,
    5059,
    5087,
    5117,
    5145,
    5165,
    5189,
    5216,
    5234,
    5252,
    5280,
    5295,
    5311,
    5339,
    5362,
    5382,
    5399,
    5427,
    5451,
    5476,
    5496,
    5516,
    5538,
    5565,
    5592,
    5630,
    5653,
    5673,
    5689,
    5709,
    5727,
    5740,
    5764,
    5780,
    5796,
    5807,
    5827,
    5845,
    5865,
    5894,
    5919,
    5945,
    5970,
    5997,
    6009,
    6028,
    6057,
    6081,
    6109,
    6136,
    6162,
    6191,
    6215,
    6240,
    6267,
    6296,
    6313,
    6338,
    6361,
    6383,
    6402,
    6424,
    6457,
    6487,
    6510,
    6545,
    6561,
    6581,
    6601,
    6618,
    6645,
    6658,
    6680,
    6700,
    6728,
    6756,
    6775,
    6793,
    6834,
    6874,
    6913,
    6927,
    6962,
    7001,
    7034,
    7061,
    7084,
    7114,
    7145,
    7174,
    7200,
    7223,
    7243,
    7262,
    7288,
    7309,
    7342,
    7379,
    7413,
    7438,
    7467,
    7487,
    7514,
    7550,
    7572,
    7594,
    7622,
    7661,
    7695,
    7717,
    7749,
    7772,
    7809,
    7838,
    7855,
    7883,
    7910,
    7931,
    7958,
    7982,
    7997,
    8025,
    8049,
    8068,
    8090,
    8127,
    8153,
    8179,
    8205,
    8231,
    8257,
    8283,
    8309,
    8335,
    8361,
    8388,
    8415,
    8442,
    8469,
    8496,
    8523,
    8550,
    8573,
    8594,
    8606
  };

static GPG_ERR_INLINE int
msgidxof (int code)
{
  return (0 ? 0
  : ((code >= 0) && (code <= 213)) ? (code - 0)
  : ((code >= 217) && (code <= 271)) ? (code - 3)
  : ((code >= 273) && (code <= 281)) ? (code - 4)
  : ((code >= 300) && (code <= 313)) ? (code - 22)
  : ((code >= 666) && (code <= 666)) ? (code - 374)
  : ((code >= 711) && (code <= 718)) ? (code - 418)
  : ((code >= 721) && (code <= 729)) ? (code - 420)
  : ((code >= 750) && (code <= 752)) ? (code - 440)
  : ((code >= 754) && (code <= 782)) ? (code - 441)
  : ((code >= 784) && (code <= 789)) ? (code - 442)
  : ((code >= 800) && (code <= 804)) ? (code - 452)
  : ((code >= 815) && (code <= 822)) ? (code - 462)
  : ((code >= 832) && (code <= 839)) ? (code - 471)
  : ((code >= 844) && (code <= 844)) ? (code - 475)
  : ((code >= 848) && (code <= 848)) ? (code - 478)
  : ((code >= 881) && (code <= 891)) ? (code - 510)
  : ((code >= 1024) && (code <= 1039)) ? (code - 642)
  : ((code >= 16381) && (code <= 16383)) ? (code - 15983)
  : 16384 - 15983);
}
