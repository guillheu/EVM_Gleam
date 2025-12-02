import eth_crypto/eth
import gleam/bit_array
import gleam/option.{None, Some}

const anvil_account_1_private_key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

const uhhhh = <<
  112,
  153,
  121,
  112,
  197,
  24,
  18,
  220,
  58,
  1,
  12,
  125,
  1,
  181,
  14,
  13,
  23,
  220,
  121,
  200,
>>

pub fn main() {
  let assert Ok(account_private_key) =
    bit_array.base16_decode(anvil_account_1_private_key_hex)
  let assert Ok(priv) = eth.new_privkey(account_private_key)

  let assert Ok(to) =
    eth.address_from_string("0x70997970c51812dc3a010c7d01b50e0d17dc79c8")

  echo to |> eth.address_to_bit_array

  let tx = eth.LegacyTransaction(None, 0, 0, to, Some(0), 1, None)

  echo uhhhh |> bit_array.base16_encode

  eth.eth_send_raw_transaction(priv, tx)
}
