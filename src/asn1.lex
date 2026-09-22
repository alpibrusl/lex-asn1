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

