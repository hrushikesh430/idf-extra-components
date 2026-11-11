/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "suit_priv.h"
#include "psa/crypto.h"

static esp_err_t ensure_psa(void)
{
    psa_status_t st = psa_crypto_init();
    return st == PSA_SUCCESS ? ESP_OK : ESP_FAIL;
}

esp_err_t suit_hash_start(suit_hash_t *h)
{
    if (ensure_psa() != ESP_OK) {
        return ESP_FAIL;
    }
    psa_hash_operation_t *op = &h->op;
    *op = psa_hash_operation_init();
    if (psa_hash_setup(op, PSA_ALG_SHA_256) != PSA_SUCCESS) {
        return ESP_FAIL;
    }
    h->active = true;
    return ESP_OK;
}

esp_err_t suit_hash_update(suit_hash_t *h, const void *data, size_t len)
{
    if (!h->active) {
        return ESP_ERR_INVALID_STATE;
    }
    if (len == 0) {
        return ESP_OK;
    }
    return psa_hash_update(&h->op, data, len) == PSA_SUCCESS ? ESP_OK : ESP_FAIL;
}

esp_err_t suit_hash_finish(suit_hash_t *h, uint8_t out[SUIT_DIGEST_LEN])
{
    if (!h->active) {
        return ESP_ERR_INVALID_STATE;
    }
    size_t olen = 0;
    psa_status_t st = psa_hash_finish(&h->op, out, SUIT_DIGEST_LEN, &olen);
    h->active = false;
    return (st == PSA_SUCCESS && olen == SUIT_DIGEST_LEN) ? ESP_OK : ESP_FAIL;
}

void suit_hash_abort(suit_hash_t *h)
{
    if (h->active) {
        psa_hash_abort(&h->op);
        h->active = false;
    }
}

esp_err_t suit_sha256(const void *data, size_t len, uint8_t out[SUIT_DIGEST_LEN])
{
    if (ensure_psa() != ESP_OK) {
        return ESP_FAIL;
    }
    size_t olen = 0;
    return psa_hash_compute(PSA_ALG_SHA_256, data, len, out, SUIT_DIGEST_LEN, &olen) == PSA_SUCCESS ? ESP_OK : ESP_FAIL;
}

esp_err_t suit_ecdsa_p256_verify(const uint8_t *point, size_t point_len, const uint8_t hash[SUIT_DIGEST_LEN],
                                 const uint8_t sig[64])
{
    if (point == NULL || point_len != 65 || point[0] != 0x04) {
        return ESP_ERR_INVALID_ARG;
    }
    if (ensure_psa() != ESP_OK) {
        return ESP_FAIL;
    }
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_key_id_t key = 0;
    psa_status_t st = psa_import_key(&attr, point, point_len, &key);
    psa_reset_key_attributes(&attr);
    if (st != PSA_SUCCESS) {
        return ESP_FAIL;
    }
    st = psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, SUIT_DIGEST_LEN, sig, 64);
    psa_destroy_key(key);
    if (st == PSA_SUCCESS) {
        return ESP_OK;
    }
    return st == PSA_ERROR_INVALID_SIGNATURE ? ESP_ERR_SUIT_OTA_AUTH : ESP_FAIL;
}
