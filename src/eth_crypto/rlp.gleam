import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import gleam/string

const byte_size_limit = 18_446_744_073_709_552_000

const byte_length_prefix = 128

const byte_length_length_prefix = 183

const list_size_prefix = 192

const list_size_length_prefix = 247

//2^64

pub type RlpInput {
  RlpBytes(BitArray)
  RlpInt(Int)
  RlpList(List(RlpInput))
}

pub type RlpDecodeError {
  InvalidPrefix(BitArray)
}

pub fn encode(content: RlpInput) -> Result(BitArray, Nil) {
  case content {
    RlpBytes(<<bytes:size(8)>>) if bytes >= 0 && bytes < 128 -> Ok(<<bytes>>)
    RlpBytes(bytes) ->
      case bit_array.byte_size(bytes) {
        n if n <= 55 -> <<{ byte_length_prefix + n }, bytes:bits>> |> Ok
        n if n <= byte_size_limit -> {
          let length_bytes = int_to_bit_array(n)
          let length_bytes_length = bit_array.byte_size(length_bytes)
          <<
            { byte_length_length_prefix + length_bytes_length },
            length_bytes:bits,
            bytes:bits,
          >>
          |> Ok
        }
        _ -> Error(Nil)
      }
    RlpList(item_list) ->
      case list.length(item_list) {
        n if n <= 55 ->
          list.fold(
            item_list,
            Ok(<<{ list_size_prefix + n }>>),
            fn(acc, next_item) {
              use acc <- result.try(acc)
              use encoded_next_item <- result.map(encode(next_item))
              <<acc:bits, encoded_next_item:bits>>
            },
          )
        n if n <= byte_size_limit -> {
          let size_bytes = int_to_bit_array(n)
          let size_bytes_length = bit_array.byte_size(size_bytes)
          list.fold(
            item_list,
            Ok(<<
              { list_size_length_prefix + size_bytes_length },
              size_bytes:bits,
            >>),
            fn(acc, next_item) {
              use acc <- result.try(acc)
              use encoded_next_item <- result.map(encode(next_item))
              <<acc:bits, encoded_next_item:bits>>
            },
          )
        }
        //   todo as "list of items of size > 55. should be 0xf7 plus the length of the length of the list. then the length of the list. then the concatenated encodings of items in the list."
        _ -> Error(Nil)
      }
    RlpInt(value) ->
      value
      |> int_to_bit_array
      |> RlpBytes
      |> encode
  }
}

pub fn decode(from: BitArray) -> Result(RlpInput, Nil) {
  case from {
    <<n:size(8)>> if n < 128 -> RlpBytes(from)
    // <<n, rest:bits>> if n 
    _ -> todo
  }
  todo
}

fn int_to_bit_array(from: Int) -> BitArray {
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
  |> result.lazy_unwrap(fn() { panic as "RLP encoding, should be valid hex" })
}
