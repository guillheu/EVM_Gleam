import eth_crypto/eth
import gleam/bit_array
import gleam/option.{None, Some}
import gleam/uri

const anvil_account_1_private_key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

const contract_address_string = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

const function_signature = "addCredits(uint256)"

const rpc_url_string = "http://localhost:8545"

pub fn main() {
  let assert Ok(rpc_url) = uri.parse(rpc_url_string)
  let assert Ok(account_private_key) =
    bit_array.base16_decode(anvil_account_1_private_key_hex)
  let assert Ok(priv) = eth.new_privkey(account_private_key)

  let assert Ok(to) = eth.address_from_string(contract_address_string)

  let assert Ok(contract_address) =
    eth.address_from_string(contract_address_string)

  let contract =
    eth.new_smart_contract(contract_address)
    |> eth.add_function("addCredits", function_signature)
  let assert Ok(contract_function) = eth.get_function(contract, "addCredits")
  let signature = eth.get_selector_hash(contract_function)

  let calldata =
    eth.generate_calldata(signature, [eth.CalldataUint256(200)]) |> echo

  let tx =
    eth.LegacyTransaction(
      Some(3),
      1_000_000_001,
      50_000,
      to,
      None,
      31_337,
      Some(calldata),
    )
  eth.eth_send_raw_transaction(priv, tx, rpc_url) |> echo
}
