/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "suit_priv.h"

static const char *TAG = SUIT_TAG;

/* SUIT_Digest = [ -16, bstr(32) ] */
static esp_err_t parse_digest(const uint8_t *p, size_t len, const uint8_t **digest)
{
    suit_cbor_t c;
    suit_cbor_init(&c, p, len);
    size_t n;
    int64_t alg;
    const uint8_t *d;
    size_t dlen;
    if (suit_cbor_get_array(&c, &n) != ESP_OK || n != 2 ||
            suit_cbor_get_int(&c, &alg) != ESP_OK ||
            suit_cbor_get_bstr(&c, &d, &dlen) != ESP_OK || !suit_cbor_at_end(&c)) {
        return ESP_ERR_SUIT_OTA_AUTH;
    }
    if (alg != SUIT_DIGEST_ALG_SHA256) {
        return ESP_ERR_SUIT_OTA_UNSUPPORTED;
    }
    if (dlen != SUIT_DIGEST_LEN) {
        return ESP_ERR_SUIT_OTA_AUTH;
    }
    *digest = d;
    return ESP_OK;
}

/* protected header map: alg (1) required, kid (4) optional */
static esp_err_t parse_protected(const uint8_t *p, size_t len, int64_t *alg, const uint8_t **kid, size_t *kid_len)
{
    suit_cbor_t c;
    suit_cbor_init(&c, p, len);
    size_t n;
    if (suit_cbor_get_map(&c, &n) != ESP_OK) {
        return ESP_ERR_SUIT_OTA_AUTH;
    }
    bool have_alg = false;
    for (size_t i = 0; i < n; i++) {
        int64_t k;
        if (suit_cbor_get_int(&c, &k) != ESP_OK) {
            return ESP_ERR_SUIT_OTA_AUTH;
        }
        if (k == 1) {
            if (suit_cbor_get_int(&c, alg) != ESP_OK) {
                return ESP_ERR_SUIT_OTA_AUTH;
            }
            have_alg = true;
        } else if (k == 4) {
            if (suit_cbor_get_bstr(&c, kid, kid_len) != ESP_OK) {
                return ESP_ERR_SUIT_OTA_AUTH;
            }
        } else if (suit_cbor_skip(&c) != ESP_OK) {
            return ESP_ERR_SUIT_OTA_AUTH;
        }
    }
    return have_alg ? ESP_OK : ESP_ERR_SUIT_OTA_AUTH;
}

static esp_err_t parse_unprotected_kid(const uint8_t *p, size_t len, const uint8_t **kid, size_t *kid_len)
{
    suit_cbor_t c;
    suit_cbor_init(&c, p, len);
    size_t n;
    if (suit_cbor_get_map(&c, &n) != ESP_OK) {
        return ESP_ERR_SUIT_OTA_AUTH;
    }
    for (size_t i = 0; i < n; i++) {
        int64_t k;
        if (suit_cbor_get_int(&c, &k) != ESP_OK) {
            return ESP_ERR_SUIT_OTA_AUTH;
        }
        if (k == 4 && *kid == NULL) {
            if (suit_cbor_get_bstr(&c, kid, kid_len) != ESP_OK) {
                return ESP_ERR_SUIT_OTA_AUTH;
            }
        } else if (suit_cbor_skip(&c) != ESP_OK) {
            return ESP_ERR_SUIT_OTA_AUTH;
        }
    }
    return ESP_OK;
}

static void put_head(suit_hash_t *h, uint8_t major, uint64_t v)
{
    uint8_t b[9];
    size_t n;
    if (v < 24) {
        b[0] = (uint8_t)((major << 5) | v);
        n = 1;
    } else if (v < 0x100) {
        b[0] = (uint8_t)((major << 5) | 24);
        b[1] = (uint8_t)v;
        n = 2;
    } else if (v < 0x10000) {
        b[0] = (uint8_t)((major << 5) | 25);
        b[1] = (uint8_t)(v >> 8);
        b[2] = (uint8_t)v;
        n = 3;
    } else {
        b[0] = (uint8_t)((major << 5) | 26);
        b[1] = (uint8_t)(v >> 24);
        b[2] = (uint8_t)(v >> 16);
        b[3] = (uint8_t)(v >> 8);
        b[4] = (uint8_t)v;
        n = 5;
    }
    suit_hash_update(h, b, n);
}

/*
 * Sig_structure = ["Signature1", protected, external_aad = h'', payload = bstr(SUIT_Digest bytes)]
 * hashed incrementally, then ECDSA over the hash.
 */
static esp_err_t verify_block(const uint8_t *block, size_t block_len, const uint8_t *digest_cbor, size_t digest_cbor_len,
                              const esp_suit_ota_key_t *keys, size_t num_keys)
{
    suit_cbor_t c;
    suit_cbor_init(&c, block, block_len);
    uint64_t tag;
    if (suit_cbor_get_tag(&c, &tag) != ESP_OK) {
        return ESP_ERR_SUIT_OTA_AUTH;
    }
    if (tag != SUIT_COSE_SIGN1_TAG) {
        ESP_LOGE(TAG, "authentication block tag %llu is not COSE_Sign1", (unsigned long long)tag);
        return ESP_ERR_SUIT_OTA_UNSUPPORTED;
    }
    size_t n;
    const uint8_t *prot, *unprot, *sig;
    size_t prot_len, unprot_len, sig_len;
    if (suit_cbor_get_array(&c, &n) != ESP_OK || n != 4 ||
            suit_cbor_get_bstr(&c, &prot, &prot_len) != ESP_OK ||
            suit_cbor_get_raw(&c, &unprot, &unprot_len) != ESP_OK ||
            suit_cbor_get_nil(&c) != ESP_OK ||
            suit_cbor_get_bstr(&c, &sig, &sig_len) != ESP_OK || !suit_cbor_at_end(&c)) {
        return ESP_ERR_SUIT_OTA_AUTH;
    }
    int64_t alg = 0;
    const uint8_t *kid = NULL;
    size_t kid_len = 0;
    esp_err_t err = parse_protected(prot, prot_len, &alg, &kid, &kid_len);
    if (err != ESP_OK) {
        return err;
    }
    if (alg != SUIT_COSE_ALG_ES256 && alg != SUIT_COSE_ALG_ESP256) {
        ESP_LOGE(TAG, "COSE algorithm %lld is not ES256", (long long)alg);
        return ESP_ERR_SUIT_OTA_UNSUPPORTED;
    }
    if (kid == NULL) {
        err = parse_unprotected_kid(unprot, unprot_len, &kid, &kid_len);
        if (err != ESP_OK) {
            return err;
        }
    }
    if (sig_len != 64) {
        return ESP_ERR_SUIT_OTA_AUTH;
    }

    suit_hash_t h;
    if (suit_hash_start(&h) != ESP_OK) {
        return ESP_FAIL;
    }
    static const uint8_t ctx_str[] = { 0x84, 0x6a, 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1' };
    suit_hash_update(&h, ctx_str, sizeof(ctx_str));
    put_head(&h, SUIT_CBOR_BSTR, prot_len);
    suit_hash_update(&h, prot, prot_len);
    static const uint8_t empty_aad = 0x40;
    suit_hash_update(&h, &empty_aad, 1);
    put_head(&h, SUIT_CBOR_BSTR, digest_cbor_len);
    suit_hash_update(&h, digest_cbor, digest_cbor_len);
    uint8_t tbs[SUIT_DIGEST_LEN];
    if (suit_hash_finish(&h, tbs) != ESP_OK) {
        return ESP_FAIL;
    }

    bool tried = false;
    for (size_t i = 0; i < num_keys; i++) {
        const esp_suit_ota_key_t *k = &keys[i];
        if (kid != NULL && k->kid != NULL && (k->kid_len != kid_len || memcmp(k->kid, kid, kid_len) != 0)) {
            continue;
        }
        tried = true;
        err = suit_ecdsa_p256_verify(k->point, k->point_len, tbs, sig);
        if (err == ESP_OK) {
            return ESP_OK;
        }
        if (err != ESP_ERR_SUIT_OTA_AUTH) {
            return err;
        }
    }
    if (!tried) {
        ESP_LOGE(TAG, "no trusted key matches the block's kid");
    }
    return ESP_ERR_SUIT_OTA_AUTH;
}

esp_err_t suit_cose_verify(const uint8_t *auth, size_t auth_len,
                           const uint8_t *manifest_bstr, size_t manifest_bstr_len,
                           const esp_suit_ota_key_t *keys, size_t num_keys,
                           uint8_t manifest_digest[SUIT_DIGEST_LEN])
{
    suit_cbor_t c;
    suit_cbor_init(&c, auth, auth_len);
    size_t n;
    if (suit_cbor_get_array(&c, &n) != ESP_OK || n < 2) {
        ESP_LOGE(TAG, "authentication wrapper needs a digest and at least one block");
        return ESP_ERR_SUIT_OTA_AUTH;
    }
    const uint8_t *digest_cbor;
    size_t digest_cbor_len;
    if (suit_cbor_get_bstr(&c, &digest_cbor, &digest_cbor_len) != ESP_OK) {
        return ESP_ERR_SUIT_OTA_AUTH;
    }
    const uint8_t *expected;
    esp_err_t err = parse_digest(digest_cbor, digest_cbor_len, &expected);
    if (err != ESP_OK) {
        return err;
    }
    uint8_t actual[SUIT_DIGEST_LEN];
    if (suit_sha256(manifest_bstr, manifest_bstr_len, actual) != ESP_OK) {
        return ESP_FAIL;
    }
    if (memcmp(actual, expected, SUIT_DIGEST_LEN) != 0) {
        ESP_LOGE(TAG, "manifest digest mismatch");
        return ESP_ERR_SUIT_OTA_AUTH;
    }
    /*
     * A wrapper may carry a block per signer. One block that verifies with a key this device
     * trusts is enough; the others may be for authorities it does not know. The wrapper is read to
     * its end either way, so an array that claims more blocks than it holds is refused.
     */
    esp_err_t last = ESP_ERR_SUIT_OTA_AUTH;
    bool accepted = false;
    for (size_t i = 1; i < n; i++) {
        const uint8_t *block;
        size_t block_len;
        if (suit_cbor_get_bstr(&c, &block, &block_len) != ESP_OK) {
            return ESP_ERR_SUIT_OTA_AUTH;
        }
        if (accepted) {
            continue;
        }
        err = verify_block(block, block_len, digest_cbor, digest_cbor_len, keys, num_keys);
        if (err == ESP_OK) {
            accepted = true;
            continue;
        }
        ESP_LOGW(TAG, "authentication block %u not accepted: 0x%x", (unsigned)(i - 1), err);
        last = err;
    }
    if (!suit_cbor_at_end(&c)) {
        ESP_LOGE(TAG, "authentication wrapper has bytes after its last block");
        return ESP_ERR_SUIT_OTA_AUTH;
    }
    if (!accepted) {
        ESP_LOGE(TAG, "no authentication block verified with a trusted key");
        return last;
    }
    memcpy(manifest_digest, expected, SUIT_DIGEST_LEN);
    return ESP_OK;
}
