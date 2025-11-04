local ffi = require('ffi')
require("nghttp2")

ffi.cdef[[
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef long long ssize_t;
typedef unsigned char uint8_t;
typedef signed char int8_t;
typedef unsigned short uint16_t;
typedef short int16_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned long size_t;
typedef long time_t;

typedef void BIO;
typedef void BIO_METHOD;
typedef void EVP_PKEY;
typedef void EVP_PKEY_CTX;
typedef void EVP_MD;
typedef void EVP_MD_CTX;
typedef void EVP_CIPHER;
typedef void EVP_CIPHER_CTX;
typedef void RSA;
typedef void BIGNUM;
typedef void BN_GENCB;
typedef void ASN1_STRING;
typedef void ASN1_OBJECT;
typedef void ASN1_OCTET_STRING;
typedef void ASN1_TIME;
typedef void ASN1_INTEGER;
typedef void X509;
typedef void X509_NAME;
typedef void X509_EXTENSION;
typedef void X509_NAME_ENTRY;
typedef void SSL;
typedef void SSL_CTX;
typedef void SSL_METHOD;
typedef void X509_STORE;
typedef void X509_STORE_CTX;
typedef void SSL_SESSION;
typedef void STACK_OF_X509;
typedef void X509V3_CTX;
typedef void GENERAL_NAME;
typedef void STACK_OF_GENERAL_NAME;

typedef int (*nghttp2_select_next_protocol_cb)(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg);

long ERR_get_error(void);
void ERR_error_string(long e, char *buf);
void ERR_clear_error(void);

const SSL_METHOD *TLS_method(void);
const SSL_METHOD *TLS_client_method(void);
const SSL_METHOD *TLS_server_method(void);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
void SSL_CTX_free(SSL_CTX *ctx);
long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
int SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int version);
int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x);
int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);
int SSL_CTX_check_private_key(SSL_CTX *ctx);
int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const unsigned char *protos, unsigned int protos_len);
void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx, nghttp2_select_next_protocol_cb cb, void *arg);

SSL *SSL_new(SSL_CTX *ctx);
void SSL_free(SSL *ssl);
int SSL_set_fd(SSL *ssl, int fd);
int SSL_accept(SSL *ssl);
int SSL_connect(SSL *ssl);
int SSL_read(SSL *ssl, void *buf, int num);
int SSL_write(SSL *ssl, const void *buf, int num);
int SSL_shutdown(SSL *ssl);
int SSL_get_error(const SSL *ssl, int ret);
long SSL_get_verify_result(const SSL *ssl);
void SSL_set_connect_state(SSL *s);
void SSL_set_accept_state(SSL *s);
void SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data, unsigned int *len);

EVP_PKEY *EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *pkey);
int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, void *e);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *ctx, int mbits);

RSA *RSA_new(void);
void RSA_free(RSA *r);
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key);
BIGNUM *BN_new(void);
void BN_free(BIGNUM *a);
int BN_set_word(BIGNUM *a, unsigned long w);

X509 *X509_new(void);
void X509_free(X509 *a);
int X509_set_version(X509 *x, long version);
ASN1_INTEGER *X509_get_serialNumber(X509 *x);
int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
X509_NAME *X509_get_subject_name(X509 *x);
X509_NAME *X509_get_issuer_name(X509 *x);
int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type, const unsigned char *bytes, int len, int loc, int set);
int X509_set_issuer_name(X509 *x, X509_NAME *name);
int X509_set_pubkey(X509 *x, EVP_PKEY *pkey);
ASN1_TIME *X509_getm_notBefore(X509 *x);
ASN1_TIME *X509_getm_notAfter(X509 *x);
void *X509_gmtime_adj(ASN1_TIME *s, long adj);
int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
EVP_PKEY *X509_get_pubkey(X509 *x);
X509_EXTENSION *X509_EXTENSION_new(void);
void X509_EXTENSION_free(X509_EXTENSION *ex);
X509_EXTENSION *X509V3_EXT_conf_nid(void *lconf, X509V3_CTX *ctx, int ext_nid, const char *value);
int X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc);
void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subject, void *req, void *crl, int flags);
int X509V3_set_ctx_nodb(X509V3_CTX *ctx);

const EVP_MD *EVP_sha256(void);

BIO *BIO_new(BIO_METHOD *type);
void BIO_free_all(BIO *a);
BIO_METHOD *BIO_s_mem(void);
int BIO_read(BIO *b, void *buf, int len);
int BIO_write(BIO *b, const void *buf, int len);
long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);

typedef struct BUF_MEM_st {
    size_t length;
    char *data;
    size_t max;
    unsigned long flags;
} BUF_MEM;

X509 *PEM_read_bio_X509(BIO *bp, X509 **x, void *cb, void *u);
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, void *cb, void *u);
int PEM_write_bio_X509(BIO *bp, X509 *x);
int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, void *cb, void *u);
int PEM_write_bio_PKCS8PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, char *kstr, int klen, void *cb, void *u);

const char *OpenSSL_version(int type);
int OPENSSL_init_crypto(uint64_t opts, const void *settings);
int OPENSSL_init_ssl(uint64_t opts, const void *settings);

]]

local M = {}
local loaded = {}

local function try_load(lib_names)
    local all_errors = {}
    for _, name in ipairs(lib_names) do
        local ok, lib_obj = pcall(ffi.load, name)
        if ok then
            loaded[name] = lib_obj
            return lib_obj
        end
        table.insert(all_errors, "  - " .. name .. ": " .. tostring(lib_obj))
    end
    
    local lib_list = table.concat(lib_names, ", ")
    return nil, "Failed to load any of: [" .. lib_list .. "]\n" .. table.concat(all_errors, "\n")
end

M.crypto, M.crypto_err = try_load({
    "libcrypto-3-x64",
    "libcrypto.so.3",
    "libcrypto"
})

M.ssl, M.ssl_err = try_load({
    "libssl-3-x64",
    "libssl.so.3",
    "libssl"
})

M.nghttp2, M.nghttp2_err = try_load({
    "nghttp2",
    "libnghttp2.so.14",
    "libnghttp2-14"
})

if not M.ssl or not M.crypto or not M.nghttp2 then
    error("Failed to load FFI libraries:\n" ..
        (M.crypto_err or "") .. "\n" ..
        (M.ssl_err or "") .. "\n" ..
        (M.nghttp2_err or "")
    )
end

M.crypto.OPENSSL_init_crypto(0, ffi.NULL)
M.ssl.OPENSSL_init_ssl(0, ffi.NULL)

M.NGHTTP2_ERR_WOULDBLOCK = -504
M.NGHTTP2_ERR_CALLBACK_FAILURE = -902
M.NGHTTP2_ERR_DEFERRED = -508
M.NGHTTP2_DATA_FLAG_EOF = 0x01
M.NGHTTP2_FLAG_END_STREAM = 0x01
M.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x03
M.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 0x04
M.NGHTTP2_NO_ERROR = 0x00
M.NGHTTP2_FLAG_NONE = 0

M.SSL_CTRL_SET_READ_AHEAD = 41
M.SSL_ERROR_WANT_READ = 2
M.SSL_ERROR_WANT_WRITE = 3
M.MBSTRING_ASC = 1
M.NID_subject_alt_name = 85
M.EVP_PKEY_RSA = 6

return M