import gleam/bit_array
import gleam/int
import gleam/string
import gleeunit/should

import eth_crypto/keccak
import eth_crypto/secp256k1

pub fn keccak_test() {
  let expected_result =
    "AE55CF31FE3EDBB5B8159DA3348B4C0565068AD0A4A81FEA6AF7DDD22950E98B"
  assert bit_array.from_string("A string")
    |> keccak.hash
    |> bit_array.base16_encode
    == expected_result

  assert bit_array.base16_encode(keccak.hash_utf8_string("A string"))
    == expected_result
}

pub fn secp256k1_signature_test() {
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

  let assert Ok(value) = secp256k1.recover(message_hash, signature, recovery_id)
  let pubkey = value

  let assert Ok(sliced_pubkey) =
    pubkey
    |> bit_array.slice(1, 64)

  assert sliced_pubkey
    |> keccak.hash
    |> bit_array.base16_encode
    |> string.slice(24, 40)
    == string.uppercase("70997970C51812dc3A010C7d01b50e0d17dc79C8")
  // |> bit_array.base16_encode
  // |> keccak.hash_string
  // |> string.slice()
}

pub fn secp256k1_privkey_to_pubkey_test() {
  // Known Anvil address 1 private key
  let privkey =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    |> bit_array.base16_decode
    |> should.be_ok
  // Corresponding known public key
  let expected_pubkey = <<
    4, 131, 24, 83, 91, 84, 16, 93, 74, 122, 174, 96, 192, 143, 196, 95, 150,
    135, 24, 27, 79, 223, 198, 37, 189, 26, 117, 63, 167, 57, 127, 237, 117, 53,
    71, 241, 28, 168, 105, 102, 70, 242, 243, 172, 176, 142, 49, 1, 106, 250,
    194, 62, 99, 12, 93, 17, 245, 159, 97, 254, 245, 123, 13, 42, 165,
  >>

  secp256k1.privkey_to_pubkey(privkey)
  |> should.be_ok
  |> should.equal(expected_pubkey)
}
