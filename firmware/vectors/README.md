# Independent-verifier vectors

`attest-v1.json` is packed by `firmware/attest.py`, not by a third-party
implementation. A coordinator that only round-trips its own `pack()` has
proven nothing.

Regenerate:

```
python firmware/attest.py --export-vectors firmware/vectors/attest-v1.json
```

`run_tests.py` fails if the file is missing or disagrees with a live
`export_vectors()`.
