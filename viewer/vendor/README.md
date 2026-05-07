# Vendored third-party code

All files here are bundled ESM builds obtained from jsDelivr's `+esm` bundler
and pinned to specific versions. SHA-256 of each file at vendor time is recorded
below. (jsDelivr's `+esm` bundles are dynamically generated, so SRI is not
guaranteed across requests; the SHA-256s let a reviewer confirm the bytes we
shipped are the bytes we vouched for.)

## Classic suite

### noble-ciphers-chacha-1.3.0.js

Bundled ESM build of [@noble/ciphers](https://github.com/paulmillr/noble-ciphers)
v1.3.0, `chacha.js` submodule. Exports `xchacha20poly1305` for AEAD because the
WebCrypto API does not expose XChaCha20-Poly1305.

- source: `https://cdn.jsdelivr.net/npm/@noble/ciphers@1.3.0/chacha.js/+esm`
- sha256: `b31ecc4f4dc4f5fcbfbd36d39bd9f15402040522232ab49181e5b36ad511fe07`

## Hybrid (post-quantum) suite

The viewer's hybrid decrypt path uses ML-KEM-768 (NIST FIPS 203) for the
post-quantum half of the KEM. WebCrypto does not implement ML-KEM, so the
implementation comes from [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum).
The ML-KEM bundle imports from sibling `@noble/hashes` and `@noble/curves`
submodules; those are vendored alongside it and the imports in `ml-kem.js`
have been rewritten to relative file paths so the viewer is fully offline-
capable.

### noble-post-quantum-ml-kem-0.6.1.js

Exports `ml_kem512`, `ml_kem768`, `ml_kem1024`. The viewer uses `ml_kem768`.

- source: `https://cdn.jsdelivr.net/npm/@noble/post-quantum@0.6.1/ml-kem.js/+esm`
- sha256: `a91e5ea30e1c2cc65869c41e4de340306cfb7c143d5249fc14fd7c61dd776089`
  (after the three jsDelivr-style import paths were rewritten to relative
  paths pointing at the three files below)

### noble-hashes-sha3-2.2.0.js

Imported by `ml-kem.js` for SHA-3, SHAKE-128, SHAKE-256.

- source: `https://cdn.jsdelivr.net/npm/@noble/hashes@2.2.0/sha3.js/+esm`
- sha256: `1813e46811d7c7f7882def07b3c099eaafcf7042fce653425fad020fa4823349`

### noble-hashes-utils-2.2.0.js

Imported by `ml-kem.js` for `abytes`, `randomBytes`, `u32`, `swap32IfBE`.

- source: `https://cdn.jsdelivr.net/npm/@noble/hashes@2.2.0/utils.js/+esm`
- sha256: `e478e2f7bfd1eb829ccbf7239ff4353db9a3d092823638369ccd03232c482570`

### noble-curves-fft-2.2.0.js

Imported by `ml-kem.js` for the NTT primitives (`FFTCore`, `reverseBits`).

- source: `https://cdn.jsdelivr.net/npm/@noble/curves@2.2.0/abstract/fft.js/+esm`
- sha256: `4741238cc8180d5115fdde4238ff6eefa16db67e714d3855a508d95e4f1c8221`

## License

All packages (`@noble/ciphers`, `@noble/post-quantum`, `@noble/hashes`,
`@noble/curves`) are distributed under the MIT License by Paul Miller. See:

- <https://github.com/paulmillr/noble-ciphers/blob/main/LICENSE>
- <https://github.com/paulmillr/noble-post-quantum/blob/main/LICENSE>
- <https://github.com/paulmillr/noble-hashes/blob/main/LICENSE>
- <https://github.com/paulmillr/noble-curves/blob/main/LICENSE>
