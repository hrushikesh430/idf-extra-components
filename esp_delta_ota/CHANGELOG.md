## 1.1.0

### Enhancements:
- Added support to pass user data to write callback with new callback function: `merged_stream_write_cb_with_user_ctx_t`
- The older write callback function: `merged_stream_write_cb_t` has been deprecated and will be removed in the next major release.

## 1.1.1

### Enhancements:
- Refactored `esp_delta_ota_patch_gen.py` for improved readability and maintainability.
- Integrated `esptool` module for handling ESP chip-specific operations.
- Utilized `detools` module APIs for creating and applying patches efficiently.
