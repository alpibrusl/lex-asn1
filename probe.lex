import "std.str" as str

import "std.io" as io

fn main() -> [io] Unit {
  let c := content("ffff")
  io.print("c=")
  io.print(c)
  io.print(" neg?=")
  io.print(yn(c == "NEG"))
}

fn content(c :: Str) -> [io] Str {
  io.print("IN len=")
  io.print(int_str(str.len(c)))
  if str.len(c) <= 2 {
    c
  } else {
    let first := str.slice(c, 0, 2)
    let rest := str.slice(c, 2, str.len(c))
    io.print(" first=")
    io.print(first)
    if first == "00" {
      if str.cmp(rest, "80") < 0 {
        "NONMIN"
      } else {
        content(rest)
      }
    } else {
      if str.cmp(first, "80") >= 0 {
        "NEG"
      } else {
        content(rest)
      }
    }
  }
}

fn int_str(n :: Int) -> Str {
  match n {
    0 => "0",
    1 => "1",
    2 => "2",
    3 => "3",
    4 => "4",
    5 => "5",
    6 => "6",
    _ => "?",
  }
}

fn yn(b :: Bool) -> Str {
  if b {
    "y"
  } else {
    "n"
  }
}

