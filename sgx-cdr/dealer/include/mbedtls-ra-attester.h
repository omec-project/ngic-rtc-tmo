void create_key_and_x509
(
    mbedtls_pk_context* key,
    mbedtls_x509_crt* cert,
    uint8_t* der_cert,
    int* der_cert_len,
    uint8_t* der_key,
    int* der_key_len
);
