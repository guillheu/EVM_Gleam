import eth_crypto/eth
import gleam/bit_array
import gleam/option.{None, Some}
import gleam/uri

const anvil_account_1_private_key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

const rpc_url_string = "http://localhost:8545"

pub fn main() {
  let assert Ok(rpc_url) = uri.parse(rpc_url_string)
  let assert Ok(account_private_key) =
    bit_array.base16_decode(anvil_account_1_private_key_hex)
  let assert Ok(priv) = eth.new_privkey(account_private_key)

  let assert Ok(to) =
    eth.address_from_string("0x70997970c51812dc3a010c7d01b50e0d17dc79c8")

  let tx =
    eth.LegacyTransaction(
      Some(1),
      1_000_000_001,
      21_000,
      to,
      Some(1_000_000_000_000_000_000),
      31_337,
      None,
    )

  eth.eth_send_raw_transaction(priv, tx, rpc_url) |> echo
}
