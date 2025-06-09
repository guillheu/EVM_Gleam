import gleam/bit_array
import gleam/dynamic
import gleam/io
import gleam/list
import gleam/option.{Some}
import gleam/string
import gleam/uri

import eth_crypto/eth

const tests = [
  #(
    "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0x3F17F1962B36E491B30A40B2405849E597BA5FB5",
    "0x3f17f1962B36e491b30A40b2405849e597Ba5FB5",
  ),
  #(
    "0411111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
    "0xAD299C05A7BB4BFEBA5584FA760B4ABB12C65ABF",
    "0xaD299C05a7BB4bfEBa5584Fa760B4aBb12C65abf",
  ),
  #(
    "0422222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222",
    "0x78A00E3EEB90690E56ED3442FA8EC00063BC503D",
    "0x78a00e3eeB90690e56eD3442fa8Ec00063BC503D",
  ),
  #(
    "0433333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333",
    "0x183671CD69C7F9A760F9F1C59393DF69E893E557",
    "0x183671Cd69C7f9a760F9f1c59393Df69e893e557",
  ),
  #(
    "0444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "0xD6EF1B2305D825192572330EA9E3FF347BB5BBCC",
    "0xD6eF1b2305d825192572330Ea9e3fF347bb5BbCC",
  ),
  #(
    "0455555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555",
    "0xA0249DFA73690FAA1A5EEADF6BD6AD8C519C6BE7",
    "0xA0249DFA73690Faa1A5eeADF6BD6ad8c519c6Be7",
  ),
  #(
    "0466666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666",
    "0x14118B15F267D0E6024E81F135BE3F9DA3AC70B5",
    "0x14118B15F267d0e6024e81f135be3F9dA3aC70b5",
  ),
  #(
    "0477777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777",
    "0x183C480327F740E5E92918A7196A0783E9DFD715",
    "0x183c480327F740e5E92918a7196a0783E9DfD715",
  ),
  #(
    "0488888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888",
    "0x85E13D8681B90E2ED69E97A8C212555DBC2230E7",
    "0x85E13D8681b90e2eD69e97A8C212555DBc2230e7",
  ),
  #(
    "0499999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
    "0x271178BA2D235797BB5BBF47DA7315B33965B1C4",
    "0x271178bA2d235797Bb5bBF47Da7315B33965B1c4",
  ),
]

pub fn eth_address_test() {
  use #(test_pubkey, test_non_checksummed_address, test_checksummed_address) <- list.each(
    tests,
  )
  let assert Ok(pubkey_bits) = bit_array.base16_decode(test_pubkey)
  let assert Ok(pubkey) = eth.new_pubkey(pubkey_bits)
  let address = eth.pubkey_to_address(pubkey)

  assert eth.address_to_string(address) == test_non_checksummed_address
  assert eth.address_to_checksummed_address(address) == test_checksummed_address

  // Successful tests
  let assert Ok(value) =
    eth.address_from_string("0x0000000000000000000000000000000000000000")
  assert value
    |> eth.address_to_string
    == "0x0000000000000000000000000000000000000000"
  let assert Ok(value) =
    eth.address_from_string("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
  assert value
    |> eth.address_to_string
    == "0x" <> string.uppercase("70997970C51812dc3A010C7d01b50e0d17dc79C8")
  let assert Ok(value) =
    eth.address_from_string("0000000000000000000000000000000000000000")
  assert value
    |> eth.address_to_string
    == "0x0000000000000000000000000000000000000000"
  let assert Ok(value) =
    eth.address_from_string("70997970C51812dc3A010C7d01b50e0d17dc79C8")
  assert value
    |> eth.address_to_string
    == "0x" <> string.uppercase("70997970C51812dc3A010C7d01b50e0d17dc79C8")

  // Failing tests
  let assert Error(_) =
    eth.address_from_string("0x70997970C51812dc3A010C7d01b50e0d17dc79")
  let assert Error(_) =
    eth.address_from_string("0x70997970C51812dc3A010C7d01b50e0d17dc79C")
  let assert Error(_) =
    eth.address_from_string("70997970C51812dc3A010C7d01b50e0d17dc79")
  let assert Error(_) =
    eth.address_from_string("70997970C51812dc3A010C7d01b50e0d17dc79C")
  let assert Error(_) =
    eth.address_from_string("G0997970C51812dc3A010C7d01b50e0d17dc79C8")
  let assert Error(_) = eth.address_from_string("Should fail, obviously")
  let assert Error(_) = eth.address_from_string("")
}

pub fn signature_test() {
  let assert Ok(signature_full) =
    bit_array.base16_decode(
      "58f00fea380eded3fbbd88e8ebaa7bf86a306a0ef725595555fba1e15fbefb48435cf2c9895254438fd1d3b16e2aa4176376967899fcf2a6a92ccf4563387a701c",
    )
  let assert Ok(signature) = eth.signature_from(signature_full)
  let message_hash = eth.hash_string("A string")
  assert eth.recover_pubkey(signature, message_hash)
    |> eth.pubkey_to_address
    |> eth.address_to_checksummed_address
    == "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
}

pub fn eth_get_balance_test() {
  let assert Ok(address) =
    eth.address_from_string("0x0000000000000000000000000000000000000000")
  let assert Ok(rpc_url) = uri.parse("https://eth.llamarpc.com")
  let assert Ok(value) = eth.eth_get_balance(rpc_url, address)
  let balance = value

  // Current approximate balance of address 0
  assert balance > { 13_431_000_000_000_000_000_000 }
}

pub fn eth_get_block_miner_test() {
  let assert Ok(rpc_url) = uri.parse("https://eth.llamarpc.com")
  let block = Some(21_879_726)
  let assert Ok(miner) =
    eth.address_from_string("0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97")
  let assert Ok(value) = eth.eth_get_block_miner(rpc_url, block)
  assert value == miner
}

pub fn parse_eth_call_response_test() {
  let test_response =
    "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":\"0x0000000000000000000000000000000000000000000000000000000000000000\"}"
  let assert Ok(value) = eth.parse_eth_call_response(test_response)
  assert value
    == eth.RpcResult(
      jsonrpc: 2.0,
      id: 1,
      result: "0x0000000000000000000000000000000000000000000000000000000000000000",
    )
  let test_response =
    "{\"id\":1,\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"invalid argument 0: json: cannot unmarshal invalid hex string into Go struct field TransactionArgs.data of type hexutil.Bytes\"}}"
  let assert Ok(value) = eth.parse_eth_call_response(test_response)
  assert value
    == eth.RpcError(
      jsonrpc: 2.0,
      id: 1,
      error: eth.RpcErrorContent(
        code: -32_602,
        message: "invalid argument 0: json: cannot unmarshal invalid hex string into Go struct field TransactionArgs.data of type hexutil.Bytes",
      ),
    )
}
