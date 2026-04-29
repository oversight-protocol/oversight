# Vendored third-party code

## noble-ciphers-chacha-1.3.0.js

Bundled ESM build of [@noble/ciphers](https://github.com/paulmillr/noble-ciphers) v1.3.0, `chacha.js` submodule. Obtained via jsDelivr's `+esm` bundler and pinned at:

- source: `https://cdn.jsdelivr.net/npm/@noble/ciphers@1.3.0/chacha.js/+esm`
- sha256: `b31ecc4f4dc4f5fcbfbd36d39bd9f15402040522232ab49181e5b36ad511fe07`

The viewer uses `xchacha20poly1305` from this module for AEAD because the
WebCrypto API does not expose XChaCha20-Poly1305.

@noble/ciphers is distributed under the MIT License by Paul Miller. See
<https://github.com/paulmillr/noble-ciphers/blob/main/LICENSE>.
