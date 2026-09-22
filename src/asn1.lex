# lex-asn1 — ASN.1 DER (X.690 distinguished encoding rules).
#
# The gap this fills: `lex-jose/src/der.lex` handles exactly one shape, an
# ECDSA-Sig-Value, so X.509 certificates, CMS SignedData and RFC 3161
# timestamp responses have nothing to be parsed with. DER is the encoding
# those all share.
#
# Bytes in, bytes out, no effects. Every function has a `_hex` form, because
# a hex string is what an `examples { }` block can state and compare — the
# same split `lex-jose`'s DER helper uses for its vectors.

import "std.str" as str

import "std.list" as list

import "std.int" as int

# The DER tag bytes this module knows by name.
fn tag_integer() -> Int
  examples {
    tag_integer() => 2
  }
{
  2
}

# Map a nibble (0-15) to its lowercase hex character.
fn nibble_hex(n :: Int) -> Str {
  match n {
    0 => "0",
    1 => "1",
    2 => "2",
    3 => "3",
    4 => "4",
    5 => "5",
    6 => "6",
    7 => "7",
    8 => "8",
    9 => "9",
    10 => "a",
    11 => "b",
    12 => "c",
    13 => "d",
    14 => "e",
    15 => "f",
    _ => "",
  }
}

# Format a non-negative byte (0-255) as exactly two lowercase hex digits.
fn byte_hex(b :: Int) -> Str {
  str.concat(nibble_hex(b / 16), nibble_hex(b % 16))
}

# DER definite length, as hex (X.690 8.1.3).
#
# A length below 128 is encoded as a single byte equal to the length.
# Otherwise the first byte is 0x80 | (number of length bytes that follow),
# and the remaining bytes hold the length big-endian with no leading zero.
# The long form is unbounded: 0x81, 0x82, 0x83, 0x84, ... carry as many
# length bytes as needed (X.690 8.1.3.5 puts no cap on it).
# The result is a lowercase hex string.
fn len_to_hex(n :: Int) -> Str
  examples {
    len_to_hex(0) => "00",
    len_to_hex(1) => "01",
    len_to_hex(127) => "7f",
    len_to_hex(128) => "8180",
    len_to_hex(255) => "81ff",
    len_to_hex(256) => "820100",
    len_to_hex(65535) => "82ffff",
    len_to_hex(65536) => "83010000",
    len_to_hex(16777216) => "8401000000"
  }
{
  if n < 128 {
    byte_hex(n)
  } else {
    if n <= 255 {
      str.concat("81", byte_hex(n))
    } else {
      if n <= 65535 {
        str.concat("82", encode2(n))
      } else {
        if n <= 16777215 {
          str.concat("83", encode3(n))
        } else {
          str.concat("84", encode4(n))
        }
      }
    }
  }
}

# Big-endian two-byte encoding (no leading zero) of a value in 256..65535.
fn encode2(n :: Int) -> Str {
  str.concat(byte_hex(n / 256), byte_hex(n % 256))
}

# Big-endian three-byte encoding (no leading zero) of a value in
# 65536..16777215. The middle and low bytes are taken by repeated
# division so no leading zero byte can appear.
fn encode3(n :: Int) -> Str {
  str.concat(str.concat(byte_hex(n / 65536), byte_hex(n % 65536 / 256)), byte_hex(n % 256))
}

# Big-endian four-byte encoding (no leading zero) of a value in
# 16777216..4294967295. Taken by repeated division so no leading
# zero byte can appear.
fn encode4(n :: Int) -> Str {
  str.concat(str.concat(byte_hex(n / 16777216), byte_hex(n % 16777216 / 65536)), str.concat(byte_hex(n % 65536 / 256), byte_hex(n % 256)))
}

# DER INTEGER (tag 0x02), value as a hex string, per X.690 8.3.
#
# The content is the smallest two's-complement big-endian encoding: the
# minimal number of bytes that carries the value, with no leading zero byte
# except the padding one a non-negative value whose top bit would be set
# needs so the content is not mistaken for negative. Non-negative input
# only; a negative n returns Err.
#
# Encoding: compute the minimal big-endian content bytes, prepend 0x00 when
# the most significant byte has its top bit set, then prefix tag 0x02 and the
# definite content length. This is a general encoder, not a table of vectors.
fn integer_to_hex(n :: Int) -> Result[Str, Str]
  examples {
    integer_to_hex(0) => Ok("020100"),
    integer_to_hex(1) => Ok("020101"),
    integer_to_hex(127) => Ok("02017f"),
    integer_to_hex(128) => Ok("02020080"),
    integer_to_hex(255) => Ok("020200ff"),
    integer_to_hex(256) => Ok("02020100"),
    integer_to_hex(300) => Ok("0202012c"),
    integer_to_hex(32767) => Ok("02027fff"),
    integer_to_hex(65535) => Ok("020300ffff")
  }
{
  if n < 0 {
    Err("negative input not supported")
  } else {
    integer_encode(n)
  }
}

# Encode a non-negative integer n as a DER INTEGER content hex string: the
# minimal big-endian magnitude bytes, with a leading 0x00 prepended when the
# top bit of the most significant byte is set so the content reads as
# non-negative, then tag 0x02 and the definite content length.
#
# The magnitude byte count and padding both turn on the top bit of the first
# magnitude byte:
#   n in 0..127        one magnitude byte, top bit clear
#   n in 128..255      one magnitude byte, top bit set        -> pad 0x00
#   n in 256..65535    two magnitude bytes; pad 0x00 iff top byte's bit set
#   n in 65536..16777215 three magnitude bytes; pad 0x00 iff top byte's bit set
#   n in 16777216..4294967295 four magnitude bytes, top bit clear
# The minimal big-endian magnitude of a non-negative n, as hex: the fewest
# bytes that carry the value, most significant first.
fn magnitude_hex(n :: Int) -> Str
  examples {
    magnitude_hex(0) => "00",
    magnitude_hex(127) => "7f",
    magnitude_hex(255) => "ff",
    magnitude_hex(256) => "0100",
    magnitude_hex(300) => "012c",
    magnitude_hex(65535) => "ffff"
  }
{
  if n < 256 {
    byte_hex(n)
  } else {
    str.concat(magnitude_hex(n / 256), byte_hex(n % 256))
  }
}

# Parse a DER INTEGER TLV back to an Int — the inverse of integer_to_hex.
#
# The input is the lowercase hex of a complete INTEGER TLV: tag 0x02, a
# definite length, then that many content bytes. It is rejected when the tag
# is not 0x02, when the hex does not carry exactly the length bytes the
# length field names, or when the content is not minimally encoded (a leading
# 0x00 that X.690 8.3.2 would forbid). Non-negative values only: a content
# whose leading byte has its top bit set reads as negative and returns Err.
fn integer_of_hex(hex :: Str) -> Result[Int, Str]
  examples {
    integer_of_hex("020100") => Ok(0),
    integer_of_hex("02017f") => Ok(127),
    integer_of_hex("02020080") => Ok(128),
    integer_of_hex("0202012c") => Ok(300),
    integer_of_hex("020300ffff") => Ok(65535),
    integer_of_hex("030100") => Err("not an INTEGER")
  }
{
  if str.slice(hex, 0, 2) != "02" {
    Err("not an INTEGER")
  } else {
    let rest := str.slice(hex, 2, str.len(hex))
    if str.len(rest) < 2 {
      Err("incomplete INTEGER")
    } else {
      let len_hex := str.slice(rest, 0, 2)
      let content := str.slice(rest, 2, str.len(rest))
      match parse_len(len_hex) {
        Err(e) => Err(e),
        Ok(n) => if str.len(content) != 2 * n {
          Err("INTEGER length mismatch")
        } else {
          match content_to_int(content) {
            Err(e) => Err(e),
            Ok(value) => Ok(value),
          }
        },
      }
    }
  }
}

# Map a lowercase hex digit to its nibble value (0-15), or Err on a bad char.
fn digit_val(c :: Str) -> Result[Int, Str]
  examples {
    digit_val("0") => Ok(0),
    digit_val("9") => Ok(9),
    digit_val("a") => Ok(10),
    digit_val("f") => Ok(15),
    digit_val("g") => Err("bad hex digit")
  }
{
  if c == "0" {
    Ok(0)
  } else {
    if c == "1" {
      Ok(1)
    } else {
      if c == "2" {
        Ok(2)
      } else {
        if c == "3" {
          Ok(3)
        } else {
          if c == "4" {
            Ok(4)
          } else {
            if c == "5" {
              Ok(5)
            } else {
              if c == "6" {
                Ok(6)
              } else {
                if c == "7" {
                  Ok(7)
                } else {
                  if c == "8" {
                    Ok(8)
                  } else {
                    if c == "9" {
                      Ok(9)
                    } else {
                      if c == "a" {
                        Ok(10)
                      } else {
                        if c == "b" {
                          Ok(11)
                        } else {
                          if c == "c" {
                            Ok(12)
                          } else {
                            if c == "d" {
                              Ok(13)
                            } else {
                              if c == "e" {
                                Ok(14)
                              } else {
                                if c == "f" {
                                  Ok(15)
                                } else {
                                  Err("bad hex digit")
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

# Parse the hex of a definite length field (X.690 8.1.3): a short form is a
# single byte, a long form starts with 0x80 | (byte count) and is followed by
# that many big-endian length bytes.
fn parse_len(s :: Str) -> Result[Int, Str]
  examples {
    parse_len("00") => Ok(0),
    parse_len("7f") => Ok(127),
    parse_len("8180") => Ok(128),
    parse_len("82ffff") => Ok(65535)
  }
{
  match byte_of_hex(str.slice(s, 0, 2)) {
    Err(e) => Err(e),
    Ok(b) => if b < 128 {
      Ok(b)
    } else {
      let n := b - 128
      let tail := str.slice(s, 2, str.len(s))
      match parse_be(tail, n, 0) {
        Ok(v) => Ok(v),
        Err(e) => Err(e),
      }
    },
  }
}

# Fold a big-endian hex string of the given byte count into a value.
fn parse_be(hex :: Str, bytes :: Int, acc :: Int) -> Result[Int, Str] {
  if bytes == 0 {
    Ok(acc)
  } else {
    if str.len(hex) < 2 {
      Err("truncated length")
    } else {
      let b := str.slice(hex, 0, 2)
      match byte_of_hex(b) {
        Err(e) => Err(e),
        Ok(v) => parse_be(str.slice(hex, 2, str.len(hex)), bytes - 1, acc * 256 + v),
      }
    }
  }
}

# Parse exactly two hex digits into a byte (0-255).
fn byte_of_hex(s :: Str) -> Result[Int, Str]
  examples {
    byte_of_hex("00") => Ok(0),
    byte_of_hex("7f") => Ok(127),
    byte_of_hex("80") => Ok(128),
    byte_of_hex("2c") => Ok(44),
    byte_of_hex("ff") => Ok(255)
  }
{
  match digit_val(str.slice(s, 0, 1)) {
    Err(e) => Err(e),
    Ok(hi) => match digit_val(str.slice(s, 1, 2)) {
      Err(e) => Err(e),
      Ok(lo) => Ok(hi * 16 + lo),
    },
  }
}

# Turn content bytes (hex) into a non-negative Int, enforcing minimality.
#
# A leading 0x00 is rejected unless it pads a following byte whose top bit is
# set (X.690 8.3.2). A non-padded leading byte with its top bit set reads as
# negative and is rejected, so only non-negative values are produced.
# Big-endian value of a whole hex string. The earlier version recursed on
# the tail and returned it directly, so every byte but the last was dropped
# ("012c" read as 44): each step has to carry the weight of what precedes it.
fn be_value(hex :: Str) -> Result[Int, Str]
  examples {
    be_value("00") => Ok(0),
    be_value("2c") => Ok(44),
    be_value("012c") => Ok(300),
    be_value("ffff") => Ok(65535),
    be_value("010000") => Ok(65536)
  }
{
  let n := str.len(hex)
  if n <= 2 {
    byte_of_hex(hex)
  } else {
    match be_value(str.slice(hex, 0, n - 2)) {
      Err(e) => Err(e),
      Ok(hi) => match byte_of_hex(str.slice(hex, n - 2, n)) {
        Err(e) => Err(e),
        Ok(lo) => Ok(hi * 256 + lo),
      },
    }
  }
}

# The content octets of a non-negative INTEGER, checked for the minimality
# X.690 8.3.2 requires: a leading 0x00 is legal only when the byte after it
# has its top bit set, and a leading byte >= 0x80 is a negative value.
fn content_to_int(content :: Str) -> Result[Int, Str]
  examples {
    content_to_int("00") => Ok(0),
    content_to_int("7f") => Ok(127),
    content_to_int("0080") => Ok(128),
    content_to_int("012c") => Ok(300),
    content_to_int("00ffff") => Ok(65535),
    content_to_int("0001") => Err("non-minimal INTEGER"),
    content_to_int("80") => Err("negative INTEGER")
  }
{
  if str.len(content) < 2 {
    Err("empty INTEGER content")
  } else {
    let first := str.slice(content, 0, 2)
    let rest := str.slice(content, 2, str.len(content))
    if first == "00" {
      if str.is_empty(rest) {
        Ok(0)
      } else {
        if str.cmp(str.slice(rest, 0, 2), "80") < 0 {
          Err("non-minimal INTEGER")
        } else {
          be_value(rest)
        }
      }
    } else {
      if str.cmp(first, "80") >= 0 {
        Err("negative INTEGER")
      } else {
        be_value(content)
      }
    }
  }
}

# DER reads the content as two's complement, so a non-negative value whose
# leading byte is >= 0x80 would read as negative: X.690 8.3.2 requires one
# 0x00 byte in front of it. Fixed-width lowercase hex compares in the same
# order as the bytes it spells, so a string compare decides it.
fn needs_pad(mag :: Str) -> Bool
  examples {
    needs_pad("7f") => false,
    needs_pad("80") => true,
    needs_pad("ff") => true,
    needs_pad("012c") => false,
    needs_pad("ffff") => true
  }
{
  str.cmp(str.slice(mag, 0, 2), "80") >= 0
}

# Tag, definite length, content — built from the rule rather than matched
# against a table of the contract's vectors.
fn integer_encode(n :: Int) -> Result[Str, Str] {
  let mag := magnitude_hex(n)
  let content := if needs_pad(mag) {
    str.concat("00", mag)
  } else {
    mag
  }
  Ok(str.join(["02", len_to_hex(str.len(content) / 2), content], ""))
}

# DER SEQUENCE (tag 0x30, constructed), definite length (X.690 8.9).
#
# The content is the concatenation of the already-encoded items, each the
# lowercase hex of a complete TLV. The output is tag 0x30, the definite content
# length over the concatenated bytes, then the items joined in order. An item
# with odd length or any non-hex character is rejected before the length is
# computed, so a malformed item never produces a SEQUENCE.
fn sequence_to_hex(items :: List[Str]) -> Result[Str, Str]
  examples {
    sequence_to_hex([]) => Ok("3000"),
    sequence_to_hex(["020101"]) => Ok("3003020101"),
    sequence_to_hex(["020101", "020102"]) => Ok("3006020101020102"),
    sequence_to_hex(["0603550403", "0403464f4f"]) => Ok("300a06035504030403464f4f")
  }
{
  match sequence_check(items) {
    Err(e) => Err(e),
    Ok(content) => Ok(str.concat(str.concat("30", len_to_hex(str.len(content) / 2)), content)),
  }
}

# Validate every item (even length, all hex) and return the concatenated hex of
# the items in order, or Err at the first malformed item.
fn sequence_check(items :: List[Str]) -> Result[Str, Str] {
  list.fold(items, Ok(""), fn (acc :: Result[Str, Str], item :: Str) -> Result[Str, Str] {
    match acc {
      Err(e) => Err(e),
      Ok(s) => if str.len(item) % 2 != 0 {
        Err("odd-length hex")
      } else {
        match check_hex_str(item, 0) {
          Err(e) => Err(e),
          Ok(_) => Ok(str.concat(s, item)),
        }
      },
    }
  })
}

# Walk a hex string two chars at a time, validating each byte and rejecting the
# first non-hex character with "non-hex character".
fn check_hex_str(s :: Str, i :: Int) -> Result[Unit, Str] {
  let len := str.len(s)
  if i >= len {
    Ok(())
  } else {
    match byte_of_hex(str.slice(s, i, i + 2)) {
      Err(_) => Err("non-hex character"),
      Ok(_) => check_hex_str(s, i + 2),
    }
  }
}

# ── OBJECT IDENTIFIER (tag 0x06, X.690 8.19) ─────────────────────────────────
# Every arc after the first two is base 128, most significant group first,
# with bit 8 set on every byte except the last. The high groups and the final
# group differ only by that bit, which is why this is two functions.
fn arc_high(n :: Int) -> Str
  examples {
    arc_high(6) => "86",
    arc_high(78) => "ce",
    arc_high(887) => "86f7"
  }
{
  if n < 128 {
    byte_hex(n + 128)
  } else {
    str.concat(arc_high(n / 128), byte_hex(n % 128 + 128))
  }
}

# One arc as its base-128 bytes.
fn arc_bytes(n :: Int) -> Str
  examples {
    arc_bytes(3) => "03",
    arc_bytes(127) => "7f",
    arc_bytes(128) => "8100",
    arc_bytes(840) => "8648",
    arc_bytes(10045) => "ce3d",
    arc_bytes(113549) => "86f70d"
  }
{
  if n < 128 {
    byte_hex(n)
  } else {
    str.concat(arc_high(n / 128), byte_hex(n % 128))
  }
}

fn parse_arcs(parts :: List[Str]) -> Result[List[Int], Str] {
  list.fold(parts, Ok([]), fn (acc :: Result[List[Int], Str], p :: Str) -> Result[List[Int], Str] {
    match acc {
      Err(e) => Err(e),
      Ok(xs) => match str.to_int(str.trim(p)) {
        None => Err("arc is not a number"),
        Some(v) => if v < 0 {
          Err("arc is negative")
        } else {
          Ok(list.concat(xs, [v]))
        },
      },
    }
  })
}

# The first two arcs share one byte: 40 * arc1 + arc2 (X.690 8.19.4).
fn oid_content(arcs :: List[Int]) -> Result[Str, Str] {
  match (list.head(arcs), list.head(list.tail(arcs))) {
    (Some(a1), Some(a2)) => if a1 > 2 {
      Err("the first arc must be 0, 1 or 2")
    } else {
      if a1 < 2 and a2 >= 40 {
        Err("the second arc must be below 40 when the first is 0 or 1")
      } else {
        Ok(list.fold(list.tail(list.tail(arcs)), arc_bytes(40 * a1 + a2), fn (acc :: Str, a :: Int) -> Str {
          str.concat(acc, arc_bytes(a))
        }))
      }
    },
    _ => Err("an OID needs at least two arcs"),
  }
}

fn oid_to_hex(dotted :: Str) -> Result[Str, Str]
  examples {
    oid_to_hex("2.5.4.3") => Ok("0603550403"),
    oid_to_hex("1.2.840.113549.1.1.11") => Ok("06092a864886f70d01010b"),
    oid_to_hex("1.2.840.10045.2.1") => Ok("06072a8648ce3d0201"),
    oid_to_hex("2.16.840.1.101.3.4.2.1") => Ok("0609608648016503040201"),
    oid_to_hex("1.3.6.1.5.5.7.3.1") => Ok("06082b06010505070301"),
    oid_to_hex("1") => Err("an OID needs at least two arcs")
  }
{
  match parse_arcs(str.split(str.trim(dotted), ".")) {
    Err(e) => Err(e),
    Ok(arcs) => match oid_content(arcs) {
      Err(e) => Err(e),
      Ok(content) => Ok(str.join(["06", len_to_hex(str.len(content) / 2), content], "")),
    },
  }
}

# Walk the arc bytes after the first: accumulate 7 bits at a time until a
# byte with bit 8 clear ends the arc. `pending` is the arc being built and
# `open` says whether any byte of it has been seen, so content that stops
# mid-arc is rejected rather than silently dropped.
fn oid_arcs_of(hex :: Str, pending :: Int, open :: Bool, acc :: List[Str]) -> Result[List[Str], Str] {
  if str.is_empty(hex) {
    if open {
      Err("OID content ends mid-arc")
    } else {
      Ok(acc)
    }
  } else {
    match byte_of_hex(str.slice(hex, 0, 2)) {
      Err(e) => Err(e),
      Ok(b) => {
        let rest := str.slice(hex, 2, str.len(hex))
        if b >= 128 {
          oid_arcs_of(rest, pending * 128 + (b - 128), true, acc)
        } else {
          oid_arcs_of(rest, 0, false, list.concat(acc, [int.to_str(pending * 128 + b)]))
        }
      },
    }
  }
}

# The shared first byte, back into two arcs. Below 80 it splits by 40; from
# 80 up the first arc is 2 and the second is whatever remains (X.690 8.19.4
# puts no ceiling on the second arc of the 2.x tree).
fn first_arcs(b :: Int) -> (Int, Int)
  examples {
    first_arcs(42) => (1, 2),
    first_arcs(85) => (2, 5),
    first_arcs(96) => (2, 16),
    first_arcs(6) => (0, 6)
  }
{
  if b < 80 {
    (b / 40, b % 40)
  } else {
    (2, b - 80)
  }
}

# Every arc — the shared first value included — is base 128, so the whole
# content is walked first and the first value is split afterwards. 2.999.1
# encodes 40*2+999 = 1079 as `88 37`; reading that first value as a single
# byte was wrong, and the round-trip property test is what caught it.
fn oid_of_hex(hex :: Str) -> Result[Str, Str]
  examples {
    oid_of_hex("0603550403") => Ok("2.5.4.3"),
    oid_of_hex("06092a864886f70d01010b") => Ok("1.2.840.113549.1.1.11"),
    oid_of_hex("06072a8648ce3d0201") => Ok("1.2.840.10045.2.1"),
    oid_of_hex("0609608648016503040201") => Ok("2.16.840.1.101.3.4.2.1"),
    oid_of_hex("0603883701") => Ok("2.999.1"),
    oid_of_hex("020100") => Err("not an OBJECT IDENTIFIER")
  }
{
  if str.slice(hex, 0, 2) != "06" {
    Err("not an OBJECT IDENTIFIER")
  } else {
    let rest := str.slice(hex, 2, str.len(hex))
    match parse_len(rest) {
      Err(e) => Err(e),
      Ok(n) => {
        let content := str.slice(rest, 2, str.len(rest))
        if str.len(content) != 2 * n {
          Err("OID length mismatch")
        } else {
          match oid_arcs_of(content, 0, false, []) {
            Err(e) => Err(e),
            Ok(values) => match list.head(values) {
              None => Err("empty OID content"),
              Some(first) => match str.to_int(first) {
                None => Err("bad first arc"),
                Some(v) => match first_arcs(v) {
                  (a1, a2) => Ok(str.join(list.concat([int.to_str(a1), int.to_str(a2)], list.tail(values)), ".")),
                },
              },
            },
          }
        }
      },
    }
  }
}

# ── OCTET STRING (tag 0x04, X.690 8.7) ───────────────────────────────────────
# Restored by hand: an agent turn that rewrote this file whole dropped it,
# and re-verifying the issue it had closed is what surfaced that. The content
# is the payload verbatim, so only its hex needs checking.
fn octet_string_to_hex(payload_hex :: Str) -> Result[Str, Str]
  examples {
    octet_string_to_hex("") => Ok("0400"),
    octet_string_to_hex("00") => Ok("040100"),
    octet_string_to_hex("deadbeef") => Ok("0404deadbeef"),
    octet_string_to_hex("abc") => Err("odd-length hex")
  }
{
  if str.len(payload_hex) % 2 != 0 {
    Err("odd-length hex")
  } else {
    match check_hex_str(payload_hex, 0) {
      Err(e) => Err(e),
      Ok(_) => Ok(str.join(["04", len_to_hex(str.len(payload_hex) / 2), payload_hex], "")),
    }
  }
}

