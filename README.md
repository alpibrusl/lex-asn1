# lex-asn1

ASN.1 **DER** (X.690 distinguished encoding rules) for the Lex language.

The encoding X.509 certificates, CMS `SignedData` and RFC 3161 timestamp
responses all share. `lex-jose`'s `der.lex` covers exactly one shape — an
ECDSA-Sig-Value — so anything else had nothing to be parsed with.

Pure: bytes in, bytes out, no effects. Every function has a `_hex` form,
because a hex string is what an `examples { }` block can state and compare.

```lex
import "lex-asn1/asn1" as asn1

asn1.integer_to_hex(300)        # Ok("0202012c")
asn1.integer_of_hex("0202012c") # Ok(300)
asn1.len_to_hex(65536)          # "83010000"
```

## Provenance

Built with [lex-code](https://github.com/alpibrusl/lex-code) driving local
`qwen3.8:27b-mlx`, one [typed issue](https://github.com/alpibrusl/lex-lang/issues/949)
per function: the issue's declared signature and examples are the contract,
and `lex issue verify` closes it at the store head.

Two things that loop does not catch, and which review did:

- the first `len_to_hex` stopped at three length bytes, so a length of 2^24
  or more was silently mis-encoded;
- the first `integer_to_hex` was a **lookup table of the contract's own
  vectors**, returning `Err` for every other input — verified by the gate,
  and not an implementation.

`examples {}` are a finite list, so `tests/` carries what they cannot: a
round trip over a range of values and a minimal-encoding check, neither of
which a table of vectors can pass. Claude (Opus 5) supervised: it wrote the
contracts, reviewed each verdict, and fixed the DER padding rule and the
parser's byte-weight bug by hand.

## License

EUPL-1.2
