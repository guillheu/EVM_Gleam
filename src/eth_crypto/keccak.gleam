import gleam/bit_array

@external(erlang, "Elixir.ExKeccak", "hash_256")
pub fn hash(message: BitArray) -> BitArray {
  let assert Ok(message) = bit_array.to_string(message)
  hash_utf8_string(message)
}

@external(javascript, "../keccak_ffi.mjs", "hash")
pub fn hash_utf8_string(message: String) -> BitArray {
  hash(bit_array.from_string(message))
}
