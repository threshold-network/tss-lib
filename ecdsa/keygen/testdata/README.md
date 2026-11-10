The `save_data_legacy_btcec` files contain a synthetic `LocalPartySaveData`
value encoded at commit `86bd1a3` with the original btcec dependency
`github.com/btcsuite/btcd@v0.0.0-20190629003639-c26ffa870fd8`, using Go 1.26.0.
They contain no signing secrets. The value has `Ks = [1]`, `BigXj = [42*G]`,
and `ECDSAPub = 42*G`; all other fields have their zero values. The Gob file
is hex-encoded for reviewability.

These fixed fixtures check that the btcec/v2 migration can read previously
saved JSON and Gob data. The test also checks unchanged JSON output and a
new Gob round trip. Exact Gob stream bytes can depend on type registration
order, so only the point's custom Gob payload is compared byte for byte in
the crypto package.
