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

fn minimal_ok(n :: Int) -> Bool {
  match asn1.integer_to_hex(n) {
    Err(_) => false,
    Ok(hex) => {
      let c := content_of(hex)
      if str.len(c) <= 2 {
        true
      } else {
        if str.slice(c, 0, 2) == "00" {
          # the pad byte is allowed only when the next byte is >= 0x80
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

fn run_all() -> [io] Unit {
  let results := [test_integer_round_trip(), test_minimal_encoding()]
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
    io.print("ok   2 asn1 property tests")
  } else {
    io.print(str.concat(int.to_str(failures), " asn1 property test(s) failed"))
  }
}
