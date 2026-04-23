# Wycheproof ECDSA test vectors (Brainpool)

These files are a redistribution of ECDSA test vectors from
[Project Wycheproof](https://github.com/C2SP/wycheproof), maintained
by the Crypto Community under the C2SP umbrella.

## Contents

| File                                        | Upstream path                                                        |
|---------------------------------------------|----------------------------------------------------------------------|
| `ecdsa_brainpoolP256r1_sha256.json.gz`      | `testvectors_v1/ecdsa_brainpoolP256r1_sha256_test.json`              |
| `ecdsa_brainpoolP384r1_sha384.json.gz`      | `testvectors_v1/ecdsa_brainpoolP384r1_sha384_test.json`              |
| `ecdsa_brainpoolP512r1_sha512.json.gz`      | `testvectors_v1/ecdsa_brainpoolP512r1_sha512_test.json`              |

## Modifications

- **gzip compression** — to keep the working-tree size down. The decompressed
  JSON is byte-identical to upstream.
- **`_test` suffix removed** from the filenames.

No test-vector content has been modified.

## License

Upstream is licensed under the Apache License 2.0. The full license text
is preserved at [`LICENSE`](LICENSE) in this directory and is identical
to the top-level [`LICENSE`](../../LICENSE) of this repository.

## Reproducing

To refresh these vectors from upstream:

```sh
for curve in 256r1_sha256 384r1_sha384 512r1_sha512; do
    curl -sL "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/ecdsa_brainpoolP${curve}_test.json" \
        | gzip -n > "testdata/wycheproof/ecdsa_brainpoolP${curve}.json.gz"
done
```

Record the upstream commit hash in the commit message when refreshing.
