import gleam/bit_array
import gleam/int
import gleam/result
import gleam/string

pub fn int_to_bit_array(from: Int) -> BitArray {
  let hex_string = case from {
    0 -> ""
    _else -> from |> int.to_base16
  }
  case string.length(hex_string) {
    n if n % 2 == 0 -> hex_string
    n if n % 2 == 1 -> hex_string |> string.pad_start(n + 1, "0")
    _ -> panic as "length mod 2 should only be 0 or 1"
  }
  |> bit_array.base16_decode
  |> result.lazy_unwrap(fn() { panic as "Expected valid hex" })
}
