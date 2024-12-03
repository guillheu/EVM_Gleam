import gleam/bit_array
import gleam/int
import gleam/string

import gleeunit/should

import eth_crypto/keccak
import eth_crypto/secp256k1

pub fn keccak_test() {
  let expected_result =
    "AE55CF31FE3EDBB5B8159DA3348B4C0565068AD0A4A81FEA6AF7DDD22950E98B"
  bit_array.from_string("A string")
  |> keccak.hash
  |> bit_array.base16_encode
  |> should.equal(expected_result)

  keccak.hash_utf8_string("A string")
  |> bit_array.base16_encode
  |> should.equal(expected_result)
}

pub fn secp256k1_test() {
  let message = <<"A string":utf8>>
  let ethereum_message_prefix = <<25, "Ethereum Signed Message:\n":utf8>>
  let assert Ok(signature_full) =
    bit_array.base16_decode(
      "58f00fea380eded3fbbd88e8ebaa7bf86a306a0ef725595555fba1e15fbefb48435cf2c9895254438fd1d3b16e2aa4176376967899fcf2a6a92ccf4563387a701c",
    )
  let message_length =
    bit_array.byte_size(message) |> int.to_string |> bit_array.from_string
  let message_hash =
    keccak.hash(
      [ethereum_message_prefix, message_length, <<"A string":utf8>>]
      |> bit_array.concat,
    )
  let assert Ok(signature) = bit_array.slice(signature_full, 0, 64)
  let assert Ok(recovery_id_byte) = bit_array.slice(signature_full, 64, 1)
  let assert Ok(recovery_id) =
    bit_array.base16_encode(recovery_id_byte) |> int.base_parse(16)
  let recovery_id = recovery_id - 27

  let pubkey =
    secp256k1.recover(message_hash, signature, recovery_id)
    |> should.be_ok
  pubkey
  |> bit_array.base16_encode
  pubkey
  |> bit_array.slice(1, 64)
  |> should.be_ok
  |> keccak.hash
  |> bit_array.base16_encode
  |> string.slice(24, 40)
  |> should.equal(string.uppercase("70997970C51812dc3A010C7d01b50e0d17dc79C8"))
  // |> bit_array.base16_encode
  // |> keccak.hash_string
  // |> string.slice()
}
