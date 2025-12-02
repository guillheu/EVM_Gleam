import gleam/bit_array
import gleam/bool
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
  InvalidLength(expected: Int, found: Int)
  ByteStringTooShort(found_size: Int)
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
    RlpList(item_list) -> {
      use list_encoded_content <- result.try(
        list.fold(item_list, Ok(<<>>), fn(acc, next_item) {
          use acc <- result.try(acc)
          use encoded_next_item <- result.map(encode(next_item))
          <<acc:bits, encoded_next_item:bits>>
        }),
      )

      case bit_array.byte_size(list_encoded_content) {
        n if n <= 55 ->
          <<{ list_size_prefix + n }, list_encoded_content:bits>> |> Ok
        n if n <= byte_size_limit -> {
          let size_bytes = int_to_bit_array(n)
          let size_bytes_length = bit_array.byte_size(size_bytes)
          <<
            { list_size_length_prefix + size_bytes_length },
            size_bytes:bits,
            list_encoded_content:bits,
          >>
          |> Ok
        }
        //   todo as "list of items of size > 55. should be 0xf7 plus the length of the length of the list. then the length of the list. then the concatenated encodings of items in the list."
        _ -> Error(Nil)
      }
    }
    RlpInt(value) ->
      value
      |> int_to_bit_array
      |> RlpBytes
      |> encode
  }
}

pub fn decode(from: BitArray) -> Result(RlpInput, RlpDecodeError) {
  case from {
    <<n:size(8)>> if n < 128 -> RlpBytes(from) |> Ok
    <<n:size(8), rest:bits>> -> {
      case n {
        n if n < byte_length_prefix -> Error(InvalidPrefix(<<n>>))
        n if n < byte_length_length_prefix -> {
          let i = n - byte_length_prefix
          bit_array.slice(rest, 0, i)
          |> result.lazy_unwrap(fn() {
            panic as {
              "slicing at index "
              <> int.to_string(i)
              <> " should work. input: "
              <> bit_array.base16_encode(from)
            }
          })
          |> RlpBytes
          |> Ok
        }
        //   todo as "short (less than 55 bytes) bytes string"
        n if n < list_size_prefix -> {
          let byte_length_length = {
            n - byte_length_length_prefix
          }
          let r = case rest {
            <<i:size(byte_length_length * 8), content:bits>> ->
              #(i, content) |> Ok
            _ ->
              Error(InvalidLength(byte_length_length, bit_array.byte_size(rest)))
          }
          use #(i, content) <- result.try(r)
          use <- bool.guard(i <= 55, Error(ByteStringTooShort(i)))
          bit_array.slice(content, 0, i)
          |> result.lazy_unwrap(fn() {
            panic as {
              "slicing at index "
              <> int.to_string(i)
              <> " should work. input: "
              <> bit_array.base16_encode(from)
            }
          })
          |> RlpBytes
          |> Ok
        }
        // todo as "long (over 55 bytes) bytes string"
        n if n < list_size_length_prefix -> {
          let i = n - byte_length_prefix
          list.repeat(Nil, i - 1)
          |> list.index_fold(#([], rest), fn(acc, _, index) {
            let #(built_list, remaining_bytes) = acc
            case remaining_bytes {
              <<first, rest:bits>> -> todo
              _ -> todo as "error"
            }
          })
          |> todo
          |> RlpList
          |> Ok
        }
        //   todo as "short (under 55 items) list"
        n -> todo as "long (over 55 items) list"
      }
    }
    _ -> todo as "else"
  }
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
