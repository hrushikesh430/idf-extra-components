/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "suit_cbor.h"
#include "esp_suit_ota_err.h"

int suit_cbor_head(const uint8_t *p, size_t n, suit_cbor_head_t *h)
{
    if (n < 1) {
        return 0;
    }
    uint8_t ib = p[0];
    h->major = ib >> 5;
    h->ai = ib & 0x1f;
    if (h->ai < 24) {
        h->val = h->ai;
        h->len = 1;
        return 1;
    }
    size_t need;
    switch (h->ai) {
    case 24: need = 1; break;
    case 25: need = 2; break;
    case 26: need = 4; break;
    case 27: need = 8; break;
    default: return -1;             /* 28..30 reserved, 31 indefinite */
    }
    if (n < 1 + need) {
        return 0;
    }
    uint64_t v = 0;
    for (size_t i = 0; i < need; i++) {
        v = (v << 8) | p[1 + i];
    }
    if (h->major == SUIT_CBOR_SIMPLE) {
        if (h->ai != 24 || v < 32) {
            return -1;              /* floats are not part of the profile; simple values 0..31 use ai directly */
        }
    } else {
        /* shortest form: the value must not fit a smaller argument */
        uint64_t floor = (need == 1) ? 24 : (need == 2) ? 0x100 : (need == 4) ? 0x10000 : 0x100000000ULL;
        if (v < floor) {
            return -1;
        }
    }
    h->val = v;
    h->len = (uint8_t)(1 + need);
    return h->len;
}

esp_err_t suit_cbor_peek(const suit_cbor_t *c, suit_cbor_head_t *h)
{
    int r = suit_cbor_head(c->p, (size_t)(c->end - c->p), h);
    return r > 0 ? ESP_OK : ESP_ERR_SUIT_OTA_FORMAT;
}

static esp_err_t take_head(suit_cbor_t *c, uint8_t major, suit_cbor_head_t *h)
{
    esp_err_t err = suit_cbor_peek(c, h);
    if (err != ESP_OK) {
        return err;
    }
    if (h->major != major) {
        return ESP_ERR_SUIT_OTA_FORMAT;
    }
    c->p += h->len;
    return ESP_OK;
}

esp_err_t suit_cbor_get_uint(suit_cbor_t *c, uint64_t *v)
{
    suit_cbor_head_t h;
    esp_err_t err = take_head(c, SUIT_CBOR_UINT, &h);
    if (err == ESP_OK) {
        *v = h.val;
    }
    return err;
}

esp_err_t suit_cbor_get_int(suit_cbor_t *c, int64_t *v)
{
    suit_cbor_head_t h;
    esp_err_t err = suit_cbor_peek(c, &h);
    if (err != ESP_OK) {
        return err;
    }
    if (h.major == SUIT_CBOR_UINT) {
        if (h.val > INT64_MAX) {
            return ESP_ERR_SUIT_OTA_FORMAT;
        }
        *v = (int64_t)h.val;
    } else if (h.major == SUIT_CBOR_NINT) {
        if (h.val > INT64_MAX) {
            return ESP_ERR_SUIT_OTA_FORMAT;
        }
        *v = -1 - (int64_t)h.val;
    } else {
        return ESP_ERR_SUIT_OTA_FORMAT;
    }
    c->p += h.len;
    return ESP_OK;
}

static esp_err_t get_string(suit_cbor_t *c, uint8_t major, const uint8_t **ptr, size_t *len)
{
    suit_cbor_head_t h;
    esp_err_t err = take_head(c, major, &h);
    if (err != ESP_OK) {
        return err;
    }
    if (h.val > (uint64_t)(c->end - c->p)) {
        return ESP_ERR_SUIT_OTA_FORMAT;
    }
    *ptr = c->p;
    *len = (size_t)h.val;
    c->p += h.val;
    return ESP_OK;
}

esp_err_t suit_cbor_get_bstr(suit_cbor_t *c, const uint8_t **ptr, size_t *len)
{
    return get_string(c, SUIT_CBOR_BSTR, ptr, len);
}

esp_err_t suit_cbor_get_tstr(suit_cbor_t *c, const uint8_t **ptr, size_t *len)
{
    return get_string(c, SUIT_CBOR_TSTR, ptr, len);
}

esp_err_t suit_cbor_get_bool(suit_cbor_t *c, bool *v)
{
    suit_cbor_head_t h;
    esp_err_t err = suit_cbor_peek(c, &h);
    if (err != ESP_OK) {
        return err;
    }
    if (h.major != SUIT_CBOR_SIMPLE || h.len != 1 || (h.val != 20 && h.val != 21)) {
        return ESP_ERR_SUIT_OTA_FORMAT;
    }
    *v = (h.val == 21);
    c->p += 1;
    return ESP_OK;
}

esp_err_t suit_cbor_get_nil(suit_cbor_t *c)
{
    suit_cbor_head_t h;
    esp_err_t err = suit_cbor_peek(c, &h);
    if (err != ESP_OK) {
        return err;
    }
    if (h.major != SUIT_CBOR_SIMPLE || h.len != 1 || h.val != 22) {
        return ESP_ERR_SUIT_OTA_FORMAT;
    }
    c->p += 1;
    return ESP_OK;
}

esp_err_t suit_cbor_get_array(suit_cbor_t *c, size_t *count)
{
    suit_cbor_head_t h;
    esp_err_t err = take_head(c, SUIT_CBOR_ARRAY, &h);
    if (err == ESP_OK) {
        if (h.val > (uint64_t)(c->end - c->p)) {
            return ESP_ERR_SUIT_OTA_FORMAT;   /* every item takes at least one byte */
        }
        *count = (size_t)h.val;
    }
    return err;
}

esp_err_t suit_cbor_get_map(suit_cbor_t *c, size_t *count)
{
    suit_cbor_head_t h;
    esp_err_t err = take_head(c, SUIT_CBOR_MAP, &h);
    if (err == ESP_OK) {
        if (h.val > (uint64_t)(c->end - c->p) / 2) {
            return ESP_ERR_SUIT_OTA_FORMAT;
        }
        *count = (size_t)h.val;
    }
    return err;
}

esp_err_t suit_cbor_get_tag(suit_cbor_t *c, uint64_t *tag)
{
    suit_cbor_head_t h;
    esp_err_t err = take_head(c, SUIT_CBOR_TAG, &h);
    if (err == ESP_OK) {
        *tag = h.val;
    }
    return err;
}

esp_err_t suit_cbor_skip(suit_cbor_t *c)
{
    uint64_t pending = 1;
    while (pending > 0) {
        suit_cbor_head_t h;
        esp_err_t err = suit_cbor_peek(c, &h);
        if (err != ESP_OK) {
            return err;
        }
        c->p += h.len;
        pending--;
        switch (h.major) {
        case SUIT_CBOR_BSTR:
        case SUIT_CBOR_TSTR:
            if (h.val > (uint64_t)(c->end - c->p)) {
                return ESP_ERR_SUIT_OTA_FORMAT;
            }
            c->p += h.val;
            break;
        case SUIT_CBOR_ARRAY:
            pending += h.val;
            break;
        case SUIT_CBOR_MAP:
            pending += 2 * h.val;
            break;
        case SUIT_CBOR_TAG:
            pending += 1;
            break;
        default:
            break;
        }
        if (pending > (uint64_t)(c->end - c->p) + 1) {
            return ESP_ERR_SUIT_OTA_FORMAT;
        }
    }
    return ESP_OK;
}

esp_err_t suit_cbor_get_raw(suit_cbor_t *c, const uint8_t **ptr, size_t *len)
{
    const uint8_t *start = c->p;
    esp_err_t err = suit_cbor_skip(c);
    if (err != ESP_OK) {
        return err;
    }
    *ptr = start;
    *len = (size_t)(c->p - start);
    return ESP_OK;
}
