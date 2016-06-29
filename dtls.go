package godtls

/*
#cgo pkg-config: openssl
#cgo CFLAGS: -Wno-deprecated -I/usr/local/Cellar/openssl/1.0.2g/include

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
  if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
    goto ctx_err;

  SSL_CTX_set_read_ahead(ctx, 1); // for DTLS
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

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

  SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80");

  unsigned int len;
  unsigned char buf[1024];
  X509_digest(cert, EVP_sha256(), buf, &len);

  char *p = context->fp;
  int i;
  for (i = 0; i < len; ++i) {
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

dtls_transport *new_dtls_transport(dtls_context *context)
{
  dtls_transport *dtls = (dtls_transport *)calloc(1, sizeof *dtls);
  if (dtls == NULL)
    return NULL;

  SSL *ssl = SSL_new(context->ctx);
  if (ssl == NULL)
    goto trans_err;
  dtls->ssl = ssl;

  BIO *bio = BIO_new(BIO_s_mem());
  if (bio == NULL)
    goto trans_err;
  BIO_set_mem_eof_return(bio, -1);
  dtls->ibio = bio;

  bio = BIO_new(BIO_s_mem());
  if (bio == NULL)
    goto trans_err;
  BIO_set_mem_eof_return(bio, -1);
  dtls->obio = bio;

  SSL_set_bio(dtls->ssl, dtls->ibio, dtls->obio);
  SSL_set_mode(dtls->ssl, SSL_MODE_AUTO_RETRY);
  SSL_set_read_ahead(dtls->ssl, 1);
  SSL_set_verify(dtls->ssl, SSL_VERIFY_NONE, NULL);

  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  SSL_set_options(dtls->ssl, SSL_OP_SINGLE_ECDH_USE);
  SSL_set_tmp_ecdh(dtls->ssl, ecdh);
  EC_KEY_free(ecdh);

  if (0) {
trans_err:
    SSL_free(ssl);
    free(dtls);
    dtls = NULL;
  }

  return dtls;
}
*/
import "C"

import (
	"errors"
	"io"
	"sync"
	"time"
	"unsafe"
)

var (
	tryAgainError = errors.New("try again")
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

func (c *DtlsContext) Destroy() {
	C.SSL_CTX_free(c.ctx.ctx)
	C.free(unsafe.Pointer(c.ctx))
}

type DtlsTransport struct {
	dtls        *C.dtls_transport
	Fingerprint string
	mtx         sync.Mutex
}

func (c *DtlsContext) NewTransport() (*DtlsTransport, error) {
	dtls := C.new_dtls_transport(c.ctx)
	if dtls == nil {
		return nil, errors.New("failed to create DTLS transport")
	}
	fingerprint := C.GoString(&c.ctx.fp[0])
	t := &DtlsTransport{dtls: dtls, Fingerprint: fingerprint}
	return t, nil
}

func (t *DtlsTransport) Destroy() {
	C.SSL_free(t.dtls.ssl)
	C.free(unsafe.Pointer(t.dtls))
}

func (t *DtlsTransport) SetConnectState() {
	C.SSL_set_connect_state(t.dtls.ssl)
}

func (t *DtlsTransport) SetAcceptState() {
	C.SSL_set_accept_state(t.dtls.ssl)
}

func (t *DtlsTransport) handshake() error {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	rv := C.SSL_do_handshake(t.dtls.ssl)
	if rv == 1 {
		return nil
	}

	code := C.SSL_get_error(t.dtls.ssl, rv)
	switch code {
	case C.SSL_ERROR_WANT_READ:
		fallthrough
	case C.SSL_ERROR_WANT_WRITE:
		return tryAgainError
	}
	return errors.New("failed to handshake")
}

func (t *DtlsTransport) Handshake() error {
	err := tryAgainError
	for err == tryAgainError {
		time.Sleep(4 * time.Millisecond)
		err = t.handshake()
	}
	return err
}

func (t *DtlsTransport) Write(data []byte) (int, error) {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	n := C.SSL_write(t.dtls.ssl, unsafe.Pointer(&data[0]), C.int(len(data)))
	if n < 0 {
		return 0, errors.New("failed to write data")
	}
	return int(n), nil
}

func (t *DtlsTransport) Read(buf []byte) (int, error) {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	n := C.SSL_read(t.dtls.ssl, unsafe.Pointer(&buf[0]), C.int(len(buf)))
	if n > 0 {
		return int(n), nil
	}

	err := t.getError(n)
	return 0, err
}

func (t *DtlsTransport) Feed(data []byte) (int, error) {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	n := C.BIO_write(t.dtls.ibio, unsafe.Pointer(&data[0]), C.int(len(data)))
	if n > 0 {
		return int(n), nil
	}

	err := t.getError(n)
	return 0, err
}

func (t *DtlsTransport) Spew(buf []byte) (int, error) {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	n := C.BIO_read(t.dtls.obio, unsafe.Pointer(&buf[0]), C.int(len(buf)))
	if n < 0 {
		return 0, errors.New("no data")
	}
	return int(n), nil
}

func (t *DtlsTransport) getError(ret C.int) error {
	err := C.SSL_get_error(t.dtls.ssl, ret)
	switch err {
	case C.SSL_ERROR_NONE:
		return nil
	case C.SSL_ERROR_ZERO_RETURN:
		return io.EOF
	case C.SSL_ERROR_SYSCALL:
		if int(C.ERR_peek_error()) != 0 {
			return errors.New("ssl syscall error")
			// return syscall.Errno(int(C.get_errno()))
		}
	case C.SSL_ERROR_SSL:
		return errors.New("ssl error ssl")
	case C.SSL_ERROR_WANT_READ:
		return errors.New("ssl error want read")
	case C.SSL_ERROR_WANT_WRITE:
		return errors.New("ssl error want write")
	default:
		return errors.New("error occured")
	}
	return nil
}
