#include "ies.h"

static VALUE eIESError;

static EC_KEY *require_ec_key(VALUE self)
{
    const EVP_PKEY *pkey;
    const EC_KEY *ec;
    Data_Get_Struct(self, EVP_PKEY, pkey);
    if (!pkey) {
	rb_raise(rb_eRuntimeError, "PKEY wasn't initialized!");
    }
    if (EVP_PKEY_type(pkey->type) != EVP_PKEY_EC) {
	rb_raise(rb_eRuntimeError, "THIS IS NOT A EC PKEY!");
    }
    ec = pkey->pkey.ec;
    if (ec == NULL)
	rb_raise(eIESError, "EC_KEY is not initialized");
    return ec;
}

static ies_ctx_t *create_context(VALUE self)
{
    ies_ctx_t* ctx = malloc(sizeof(ies_ctx_t));
    ctx->cipher = EVP_aes_128_cbc();
    ctx->md = EVP_sha1();
    ctx->kdf_md = EVP_sha1();
    ctx->stored_key_length = 25;
    ctx->user_key = require_ec_key(self);

    return ctx;
}

static VALUE ies_cryptogram_to_rb_string(const ies_ctx_t *ctx,const cryptogram_t *cryptogram)
{
    return rb_str_new((char *)cryptogram_key_data(cryptogram), cryptogram_data_sum_length(cryptogram));
}

static cryptogram_t *ies_rb_string_to_cryptogram(const ies_ctx_t *ctx, const VALUE string)
{
    size_t data_len = RSTRING_LEN(string);
    const char * data = RSTRING_PTR(string);

    size_t key_length = ctx->stored_key_length;
    size_t mac_length = EVP_MD_size(ctx->md);
    const cryptogram_t *cryptogram = cryptogram_alloc(key_length, mac_length, data_len - key_length - mac_length);

    memcpy(cryptogram_key_data(cryptogram), data, data_len);

    return cryptogram;
}

/*
 *  call-seq:
 *     OpenSSL::PKey::EC::IES.new(key, algorithm_spec)
 *
 *  Algorithm spec is currently ignored.
 */
static VALUE ies_initialize(VALUE self, VALUE key, VALUE algo)
{
    VALUE args[1];

    rb_iv_set(self, "@algorithm", algo);

    args[0] = key;
    return rb_call_super(1, args);
}

/*
 *  call-seq:
 *     ecies.public_encrypt(plaintext) => String
 *
 *  The pem_string given in init must contain public key.
 */
static VALUE ies_public_encrypt(VALUE self, VALUE clear_text)
{
    ies_ctx_t *ctx;
    char error[1024] = "Unknown error";
    VALUE cipher_text;
    cryptogram_t *cryptogram;

    StringValue(clear_text);

    ctx = create_context(self);
    if (!EC_KEY_get0_public_key(ctx->user_key))
	rb_raise(eIESError, "Given EC key is not public key");

    cryptogram = ecies_encrypt(ctx, (unsigned char*)RSTRING_PTR(clear_text), RSTRING_LEN(clear_text), error);
    if (cryptogram == NULL) {
	free(ctx);
	ctx = NULL;
	rb_raise(eIESError, "Error in encryption: %s", error);
    }
    cipher_text = ies_cryptogram_to_rb_string(ctx, cryptogram);
    cryptogram_free(cryptogram);
    free(ctx);
    return cipher_text;
}

/*
 *  call-seq:
 *     ecies.private_decrypt(plaintext) => String
 *
 *  The pem_string given in init must contain private key.
 */
static VALUE ies_private_decrypt(VALUE self, VALUE cipher_text)
{
    ies_ctx_t *ctx;
    char error[1024] = "Unknown error";
    VALUE clear_text;
    cryptogram_t *cryptogram;
    size_t length;
    unsigned char *data;

    StringValue(cipher_text);

    ctx = create_context(self);
    if (!EC_KEY_get0_private_key(ctx->user_key))
	rb_raise(eIESError, "Given EC key is not private key");

    cryptogram = ies_rb_string_to_cryptogram(ctx, cipher_text);
    data = ecies_decrypt(ctx, cryptogram, &length, error);
    cryptogram_free(cryptogram);
    free(ctx);

    if (data == NULL) {
	rb_raise(eIESError, "Error in decryption: %s", error);
    }

    clear_text = rb_str_new((char *)data, length);
    free(data);

    return clear_text;
}

/*
 * INIT
 */
void
Init_ies(void)
{
    static VALUE cIES;
    VALUE cEC;

    rb_require("openssl");
    cEC = rb_path2class("OpenSSL::PKey::EC");

    /* Document-class: OpenSSL::PKey::EC::IES
     *
     * An implementation of ECIES cryptography.
     */
    cIES = rb_define_class_under(cEC, "IES", cEC);

    rb_define_method(cIES, "initialize", ies_initialize, 2);
    rb_define_method(cIES, "public_encrypt", ies_public_encrypt, 1);
    rb_define_method(cIES, "private_decrypt", ies_private_decrypt, 1);

    eIESError = rb_define_class_under(cIES, "IESError", rb_eRuntimeError);
}
