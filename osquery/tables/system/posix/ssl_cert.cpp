/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
 
#include <stdio.h>
#include <string.h>
#include <string>

#include <osquery/tables.h>

#include <openssl/bn.h>
#include <openssl/asn1.h>  
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#define SHORT_STR 256

namespace osquery {
namespace tables {

namespace fs = boost::filesystem;

static void fillRow ( Row &r, X509 *cert ) {
  char temp[ SHORT_STR + 1 ];
  
  // set certificate subject information
  X509_NAME *subject_name = X509_get_subject_name( cert );
  X509_NAME_get_text_by_NID( subject_name, NID_commonName, temp, SHORT_STR );
  r["issued_common_name"] = std::string( temp );
  
  X509_NAME_get_text_by_NID( subject_name, NID_organizationName, temp, SHORT_STR );
  r["issued_organization"] = std::string( temp );
  
  X509_NAME_get_text_by_NID( subject_name, NID_organizationalUnitName, temp, SHORT_STR );
  r["issued_organization_unit"] = std::string( temp );
  
  ASN1_INTEGER *serial = X509_get_serialNumber( cert );
  BIGNUM *bn = ASN1_INTEGER_to_BN( serial, NULL );
  char *dec_str = BN_bn2dec( bn );
  r["issued_serial_number"] = std::string( dec_str );
  BN_free( bn );
  OPENSSL_free( dec_str );
  
  // set certificate issuer information 
  X509_NAME *issuer_name = X509_get_issuer_name( cert );
  X509_NAME_get_text_by_NID( issuer_name, NID_commonName, temp, SHORT_STR );
  r["issuer_cn"] = std::string( temp );
  
  X509_NAME_get_text_by_NID( issuer_name, NID_organizationName, temp, SHORT_STR );
  r["issuer_organization"] = std::string( temp );
  
  X509_NAME_get_text_by_NID( issuer_name, NID_organizationalUnitName, temp, SHORT_STR );
  r["issuer_organization_unit"] = std::string( temp );
  
  // set period of validity
  ASN1_TIME *valid_from = X509_get_notBefore( cert );
  ASN1_TIME *valid_to = X509_get_notAfter( cert );
  BIO *b = BIO_new( BIO_s_mem() );
  
	ASN1_TIME_print( b, valid_from );
	BIO_gets( b, temp, SHORT_STR );
	r["valid_from"] = std::string( temp );
	
	ASN1_TIME_print( b, valid_to );
	BIO_gets( b, temp, SHORT_STR );
	r["valid_to"] = std::string( temp );
	BIO_free( b );
	
	// set sha 256 & 1 fingerprint
	EVP_MD *digest = ( EVP_MD * ) EVP_sha256();
	unsigned len = SHORT_STR;
	X509_digest( cert, digest, ( unsigned char* ) temp, &len );
	char sha_text[ SHORT_STR + 1 ];
	
	for ( unsigned i=0; i < len; i++ ) {
    char byt[5];
	  sprintf( byt,"%02X%c", temp[i], (i+1 == len) ?'\0':':' );
	  strcat( sha_text, byt );
  }
  
	r["sha256_fingerprint"] = std::string( sha_text );	
	digest = ( EVP_MD * ) EVP_sha1();
	X509_digest( cert, digest, ( unsigned char* ) temp, &len );
	memcpy( sha_text, "\0", sizeof( sha_text ) );
	
	for ( unsigned i=0; i < len; i++ ) {
	  char byt[5];
	  sprintf( byt,"%02X%c", temp[i], (i+1 == len) ?'\0':':' );
	  strcat( sha_text, byt );
  }
  
	r["sha1_fingerprint"] = std::string( sha_text ); 
	
	return;
} 

static void getSslCert( const char * domain, QueryData &results ) {
  const char *def_cert_dir;
  def_cert_dir = getenv( X509_get_default_cert_dir_env() );
  
  if ( !def_cert_dir ) {
    def_cert_dir = X509_get_default_cert_dir();
  }
  
  fs::path full_path( fs::initial_path<fs::path>() );
  
  full_path = fs::system_complete( fs::path( def_cert_dir ) );
  
  if ( fs::exists( full_path ) ) {
    
    if ( fs::is_directory( full_path ) ) {
      fs::directory_iterator end_iter;
      
      FILE *fp;
      // parse each certificate in the default directory
      for ( fs::directory_iterator dir_itr( full_path ); dir_itr != end_iter; ++dir_itr ) {
        
        if ( fs::is_regular_file( dir_itr->status() ) ) {
          std::stringstream ss;
          char ch = ( def_cert_dir[strlen(def_cert_dir) -1] == '/' ) ? '\0' : '/'; 
          ss << def_cert_dir <<  ch << dir_itr->path().filename().string();
          char issued_cn[SHORT_STR];
          fp = fopen( (ss.str()).c_str(), "r" );
          if ( fp == NULL ) continue;
          X509 *cert = PEM_read_X509( fp, NULL, NULL, NULL );
          if ( cert == NULL ) continue;
          X509_NAME *subject_name = X509_get_subject_name( cert );
          X509_NAME_get_text_by_NID( subject_name, NID_commonName, issued_cn, 255 );
    
          if ( strcmp( issued_cn, domain ) == 0 ) {
            Row r;
            fillRow( r, cert );
            results.push_back( r );
          }
          
          X509_free( cert );
          fclose( fp );
        }  
      }
    }
  }
  
  return;
}

QueryData genSslCert( QueryContext &context ) {
  QueryData results;
  auto domains = context.constraints["domain"].getAll( EQUALS );
  
  for ( const auto& domain : domains ) {
    getSslCert( domain.c_str(), results );
  }
  
  return results;
}

}
}

















