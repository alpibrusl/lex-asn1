# lex-asn1 — properties the contract's vectors cannot pin.
#
# Why this file exists: a typed issue's `examples {}` are a finite list, and
# an implementation can satisfy them by matching each one and refusing every
# other input — which is exactly what the first `integer_to_hex` did, and the
# gate still called the issue verified. A round trip over a range cannot be
# faked that way: the only way to pass is to encode and parse by the rule.

import "std.io" as io

import "std.str" as str

import "std.list" as list

import "std.int" as int

import "../src/asn1" as asn1

# 0..300 covers the short form, the 0x00 padding boundary at 128 and the
# two-byte values; the rest are boundaries and arbitrary middles.
fn sample_values() -> List[Int] {
  list.concat(list.range(0, 301), [511, 512, 4660, 32767, 32768, 65535, 65536, 1048576, 16777215, 16777216])
}

fn round_trips(n :: Int) -> Bool {
  match asn1.integer_to_hex(n) {
    Err(_) => false,
    Ok(hex) => match asn1.integer_of_hex(hex) {
      Err(_) => false,
      Ok(back) => back == n,
    },
  }
}

fn first_failure(vals :: List[Int]) -> Option[Int] {
  list.head(list.filter(vals, fn (n :: Int) -> Bool {
    not round_trips(n)
  }))
}

fn test_integer_round_trip() -> Result[Unit, Str] {
  match first_failure(sample_values()) {
    None => Ok(()),
    Some(n) => Err(str.concat("integer_to_hex/integer_of_hex do not round trip at n = ", int.to_str(n))),
  }
}

# Every encoding must be minimal: no leading 0x00 in the content unless the
# next byte has its top bit set. A table-driven encoder tends to get this
# wrong for values it never saw.
fn content_of(hex :: Str) -> Str {
  str.slice(hex, 4, str.len(hex))
}

# A leading 0x00 is allowed only when the byte after it has its top bit set.
fn minimal_ok(n :: Int) -> Bool {
  match asn1.integer_to_hex(n) {
    Err(_) => false,
    Ok(hex) => {
      let c := content_of(hex)
      if str.len(c) <= 2 {
        true
      } else {
        if str.slice(c, 0, 2) == "00" {
          str.cmp(str.slice(c, 2, 4), "80") >= 0
        } else {
          true
        }
      }
    },
  }
}

fn test_minimal_encoding() -> Result[Unit, Str] {
  match list.head(list.filter(sample_values(), fn (n :: Int) -> Bool {
    not minimal_ok(n)
  })) {
    None => Ok(()),
    Some(n) => Err(str.concat("integer_to_hex is not minimally encoded at n = ", int.to_str(n))),
  }
}

# OIDs the contract never mentioned, including long arcs (the base-128 case a
# table of vectors gets wrong) and both first-byte branches.
fn sample_oids() -> List[Str] {
  ["1.2.3", "0.9.2342.19200300.100.1.25", "1.3.6.1.4.1.311.21.20", "2.16.840.1.101.3.4.2.3", "1.2.840.113549.1.9.16.2.47", "2.999.1", "1.2.16383", "1.2.16384", "2.5.29.17"]
}

fn oid_round_trips(dotted :: Str) -> Bool {
  match asn1.oid_to_hex(dotted) {
    Err(_) => false,
    Ok(hex) => match asn1.oid_of_hex(hex) {
      Err(_) => false,
      Ok(back) => back == dotted,
    },
  }
}

fn test_oid_round_trip() -> Result[Unit, Str] {
  match list.head(list.filter(sample_oids(), fn (o :: Str) -> Bool {
    not oid_round_trips(o)
  })) {
    None => Ok(()),
    Some(o) => Err(str.concat("oid_to_hex/oid_of_hex do not round trip at ", o)),
  }
}

# A TLV's declared length must equal the content that follows it, whatever
# the payload size — the case where the short/long length forms meet.
fn payload_of(n :: Int) -> Str {
  str.join(list.map(list.range(0, n), fn (_i :: Int) -> Str {
    "ab"
  }), "")
}

fn octets_len_ok(n :: Int) -> Bool {
  match asn1.octet_string_to_hex(payload_of(n)) {
    Err(_) => false,
    Ok(hex) => {
      let expect := str.join(["04", asn1.len_to_hex(n), payload_of(n)], "")
      hex == expect
    },
  }
}

fn test_octet_string_lengths() -> Result[Unit, Str] {
  match list.head(list.filter([0, 1, 2, 126, 127, 128, 129, 255, 256], fn (n :: Int) -> Bool {
    not octets_len_ok(n)
  })) {
    None => Ok(()),
    Some(n) => Err(str.concat("octet_string_to_hex length is wrong at n = ", int.to_str(n))),
  }
}

# A SEQUENCE of k INTEGERs: its length must be the sum of the items', and the
# content their concatenation in order.
fn seq_of_ints_ok(k :: Int) -> Bool {
  let items := list.fold(list.range(0, k), [], fn (acc :: List[Str], i :: Int) -> List[Str] {
    match asn1.integer_to_hex(i) {
      Err(_) => acc,
      Ok(h) => list.concat(acc, [h]),
    }
  })
  let body := str.join(items, "")
  match asn1.sequence_to_hex(items) {
    Err(_) => false,
    Ok(hex) => hex == str.join(["30", asn1.len_to_hex(str.len(body) / 2), body], ""),
  }
}

fn test_sequence_lengths() -> Result[Unit, Str] {
  match list.head(list.filter([0, 1, 2, 5, 40, 43, 60], fn (k :: Int) -> Bool {
    not seq_of_ints_ok(k)
  })) {
    None => Ok(()),
    Some(k) => Err(str.concat("sequence_to_hex is wrong for k = ", int.to_str(k))),
  }
}

fn run_all() -> [io] Unit {
  let results := [test_integer_round_trip(), test_minimal_encoding(), test_oid_round_trip(), test_octet_string_lengths(), test_sequence_lengths()]
  let __p := list.map(results, fn (r :: Result[Unit, Str]) -> [io] Unit {
    match r {
      Ok(_) => (),
      Err(e) => io.print(str.concat("FAIL: ", e)),
    }
  })
  let failures := list.fold(results, 0, fn (n :: Int, r :: Result[Unit, Str]) -> Int {
    match r {
      Ok(_) => n,
      Err(_) => n + 1,
    }
  })
  if failures == 0 {
    io.print("ok   5 asn1 property tests")
  } else {
    io.print(str.concat(int.to_str(failures), " asn1 property test(s) failed"))
  }
}

