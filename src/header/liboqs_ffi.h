typedef int OQS_STATUS;

typedef struct OQS_KEM {
    const char *method_name;
    const char *alg_version;
    uint8_t claimed_nist_level;
    bool ind_cca;
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_ciphertext;
    size_t length_shared_secret;
    size_t length_keypair_seed;
    size_t length_encaps_seed;
    void *keypair_derand;
    void *keypair;
    void *encaps_derand;
    void *encaps;
    void *decaps;
} OQS_KEM;

OQS_KEM *OQS_KEM_new(const char *method_name);
OQS_STATUS OQS_KEM_keypair(const OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key);
OQS_STATUS OQS_KEM_encaps(const OQS_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_STATUS OQS_KEM_decaps(const OQS_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
void OQS_KEM_free(OQS_KEM *kem);