package godtls

/*
#cgo pkg-config: openssl
#cgo CFLAGS: -Wno-deprecated

#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>

#define SHA256_FINGERPRINT_SIZE (95 + 1)

static EVP_PKEY *gen_key() {
  EVP_PKEY *pkey = EVP_PKEY_new();
  BIGNUM *exponent = BN_new();
  RSA *rsa = RSA_new();
  if (!pkey || !exponent || !rsa ||
      !BN_set_word(exponent, 0x10001) ||
      !RSA_generate_key_ex(rsa, 1024, exponent, NULL) ||
      !EVP_PKEY_assign_RSA(pkey, rsa)) {
    EVP_PKEY_free(pkey);
    BN_free(exponent);
    RSA_free(rsa);
    return NULL;
  }
  BN_free(exponent);
  return pkey;
}

static X509 *gen_cert(EVP_PKEY* pkey, const char *common, int days) {
  X509 *x509 = NULL;
  BIGNUM *serial_number = NULL;
  X509_NAME *name = NULL;

  if ((x509 = X509_new()) == NULL)
    return NULL;

  if (!X509_set_pubkey(x509, pkey))
    return NULL;

  ASN1_INTEGER* asn1_serial_number;
  if ((serial_number = BN_new()) == NULL ||
      !BN_pseudo_rand(serial_number, 64, 0, 0) ||
      (asn1_serial_number = X509_get_serialNumber(x509)) == NULL ||
      !BN_to_ASN1_INTEGER(serial_number, asn1_serial_number))
    goto cert_err;

  if (!X509_set_version(x509, 0L))
    goto cert_err;

  if ((name = X509_NAME_new()) == NULL ||
      !X509_NAME_add_entry_by_NID(
          name, NID_commonName, MBSTRING_UTF8,
          (unsigned char*)common, -1, -1, 0) ||
      !X509_set_subject_name(x509, name) ||
      !X509_set_issuer_name(x509, name))
    goto cert_err;

  if (!X509_gmtime_adj(X509_get_notBefore(x509), 0) ||
      !X509_gmtime_adj(X509_get_notAfter(x509), days * 24 * 3600))
    goto cert_err;

  if (!X509_sign(x509, pkey, EVP_sha1()))
    goto cert_err;

  if (0) {
cert_err:  
    X509_free(x509);
    x509 = NULL;
  }
  BN_free(serial_number);
  X509_NAME_free(name);

  return x509;
}

static int verify_peer_certificate_cb(int ok, X509_STORE_CTX *ctx) {
  return 1;
}

static int ssl_init = 0;

typedef struct {
  SSL_CTX *ctx;
  char fp[SHA256_FINGERPRINT_SIZE];
} dtls_context;

dtls_context *new_dtls_context(const char *common, int days) {
  if (common == NULL)
    return NULL;

  dtls_context *context = (dtls_context *)calloc(1, sizeof *context);
  if (context == NULL)
    return NULL;

  if (!ssl_init) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ssl_init = 1;
  }

  SSL_CTX *ctx = SSL_CTX_new(DTLSv1_method());
  if (ctx == NULL)
    goto ctx_err;
  context->ctx = ctx;

  // ALL:NULL:eNULL:aNULL
  if (SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH") != 1)
    goto ctx_err;

  SSL_CTX_set_read_ahead(ctx, 1); // for DTLS
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_peer_certificate_cb);

  EVP_PKEY *key = gen_key();
  if (key == NULL)
    goto ctx_err;
  SSL_CTX_use_PrivateKey(ctx, key);

  X509 *cert = gen_cert(key, common, days);
  if (cert == NULL)
    goto ctx_err;
  SSL_CTX_use_certificate(ctx, cert);
  
  if (SSL_CTX_check_private_key(ctx) != 1)
    goto ctx_err;

  unsigned int len;
  unsigned char buf[1024];
  X509_digest(cert, EVP_sha256(), buf, &len);

  char *p = context->fp;
  for (int i = 0; i < len; ++i) {
    snprintf(p, 4, "%02X:", buf[i]);
    p += 3;
  }
  *(p - 1) = 0;

  if (0) {
ctx_err:
    SSL_CTX_free(ctx);
    free(context);
    context = NULL;
  }

  return context;
}

typedef struct {
  SSL *ssl;
  BIO *ibio;
  BIO *obio;
} dtls_transport;


*/
import "C"

import (
  "errors"
  "unsafe"
)

type DtlsContext struct {
  ctx *C.dtls_context
}

func NewContext(common string, days int) (*DtlsContext, error) {
  s := C.CString(common)
  defer C.free(unsafe.Pointer(s))
  ctx := C.new_dtls_context(s, C.int(days))
  if ctx == nil {
    return nil, errors.New("failed to create DTLS context")
  }
  return &DtlsContext{ctx}, nil
}

func (c *DtlsContext) Destroy() error {
  C.SSL_CTX_free(c.ctx.ctx);
  C.free(unsafe.Pointer(c.ctx));
  return nil
}

type DtlsTransport struct {
  trans *C.dtls_transport
}
