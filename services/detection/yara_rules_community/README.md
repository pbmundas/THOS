# Managed community YARA corpus

Compose populates the `yara_community_rules` volume from the pinned
[`Yara-Rules/rules`](https://github.com/Yara-Rules/rules) revision configured by
`YARARULES_REF`. To operate fully offline, place a reviewed copy of that
repository's `.yar`/`.yara` files, `LICENSE`, `README.md`, and a `VERSION.txt`
containing the pinned commit in this directory before building.

The upstream corpus is licensed under GNU GPL v2. The initializer copies the
upstream `LICENSE` into the managed volume.
