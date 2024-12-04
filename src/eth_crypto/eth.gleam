import eth_crypto/secp256k1
import gleam/bit_array
import gleam/bool
import gleam/dict.{type Dict}
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/result
import gleam/string
import gleam/uri.{type Uri}
import gleam/yielder
import snag.{type Result}

import eth_crypto/keccak

pub opaque type PubKey {
  PubKey(key: BitArray)
}

pub opaque type Address {
  Address(addr: BitArray)
}

pub opaque type Signature {
  Signature(signature: BitArray, recovery_id: Int)
}

pub opaque type Hash {
  Hash(hash: BitArray)
}

pub opaque type SmartContract {
  SmartContract(addr: Address, selectors: Dict(String, Selector))
}

pub opaque type Selector {
  Function(signature: String, hash: String)
  Event(signature: String, hash: String)
}

pub fn new_smart_contract(at: Address) -> SmartContract {
  SmartContract(at, dict.new())
}

pub fn get_function(contract: SmartContract, id: String) -> Result(Selector) {
  case dict.get(contract.selectors, id) {
    Error(_) -> snag.error("selector id does not exist")
    Ok(selector) ->
      case selector {
        Function(_, _) -> Ok(selector)
        Event(_, _) -> snag.error("found selector is an event, not a function")
      }
  }
  |> snag.context("failed to get function " <> string.inspect(id))
}

pub fn get_event(contract: SmartContract, id: String) -> Result(Selector) {
  case dict.get(contract.selectors, id) {
    Error(_) -> snag.error("selector id does not exist")
    Ok(selector) ->
      case selector {
        Event(_, _) -> Ok(selector)
        Function(_, _) ->
          snag.error("found selector is a function, not an event")
      }
  }
  |> snag.context("failed to get function " <> string.inspect(id))
}

pub fn add_function(
  contract: SmartContract,
  id: String,
  signature: String,
) -> SmartContract {
  let signature_hash =
    "0x"
    <> signature
    |> keccak.hash_utf8_string
    |> bit_array.base16_encode
    |> string.lowercase
    |> string.slice(0, 8)
  SmartContract(
    ..contract,
    selectors: dict.insert(
      contract.selectors,
      id,
      Function(signature, signature_hash),
    ),
  )
}

pub fn add_event(
  contract: SmartContract,
  id: String,
  signature: String,
) -> SmartContract {
  let signature_hash =
    "0x"
    <> signature
    |> keccak.hash_utf8_string
    |> bit_array.base16_encode
    |> string.lowercase
    |> string.slice(0, 8)

  SmartContract(
    ..contract,
    selectors: dict.insert(
      contract.selectors,
      id,
      Event(signature, signature_hash),
    ),
  )
}

pub fn eth_call(
  contract: SmartContract,
  function_selector selector: Selector,
  data data: BitArray,
  rpc_uri rpc_uri: Uri,
) -> Result(String) {
  //TODO:
  // add decoder function as argument
  // and decode the response
  let data =
    case bit_array.byte_size(data) % 32 {
      0 -> data
      any -> {
        <<0:size({ 32 - any }), data:bits>>
      }
    }
    |> bit_array.base16_encode
  case selector {
    Function(_, hash) -> {
      let assert Ok(request) = request.from_uri(rpc_uri)
      let body = "{
  \"jsonrpc\": \"2.0\",
  \"id\": 1,
  \"method\": \"eth_call\",
  \"params\": [
    {
      \"to\": \"" <> address_to_string(contract.addr) <> "\",
      \"data\": \"" <> hash <> data <> "\"
    },
    \"latest\"
  ]
}"
      let response =
        request
        |> request.prepend_header("Content-Type", "application/json")
        |> request.prepend_header("Accept", "application/json")
        |> request.set_method(http.Post)
        |> request.set_body(body)
        |> httpc.send
      case response {
        Ok(res) -> {
          use <- bool.guard(
            res.status >= 300 && res.status < 200,
            snag.error("status error: " <> int.to_string(res.status)),
          )
          Ok(res.body)
        }
        Error(_e) -> snag.error("failed to fetch a response from the RPC")
      }
    }
    _ -> snag.error("selector is not a function")
  }
  |> snag.context("failed to use selector " <> selector.signature)
}

const message_prefix = <<25, "Ethereum Signed Message:\n":utf8>>

pub fn hash(message: BitArray) -> Hash {
  let msg_length =
    bit_array.byte_size(message) |> int.to_string |> bit_array.from_string
  // let msg_hex = bit_array.base16_encode(message) |> bit_array.from_string
  Hash(keccak.hash(bit_array.concat([message_prefix, msg_length, message])))
}

pub fn hash_string(from: String) -> Hash {
  hash(bit_array.from_string(from))
}

pub fn signature_from(from: BitArray) -> Result(Signature) {
  use <- bool.guard(
    bit_array.byte_size(from) != 65,
    snag.error("given signature is not 65 bytes long"),
  )
  let assert Ok(signature) = bit_array.slice(from, 0, 64)
  let assert <<_:512, recovery_id:8>> = from
  let recovery_id = case recovery_id >= 27 {
    True -> recovery_id - 27
    False -> recovery_id
  }
  Ok(Signature(signature, recovery_id))
}

pub fn recover_pubkey(signature: Signature, message_hash: Hash) -> PubKey {
  let assert Ok(result) =
    secp256k1.recover(
      message_hash.hash,
      signature.signature,
      signature.recovery_id,
    )
  let assert Ok(pubkey) = new_pubkey(result)
  pubkey
}

pub fn new_pubkey(key: BitArray) -> Result(PubKey) {
  use <- bool.guard(
    bit_array.byte_size(key) != 65,
    snag.error("given key is not 65 bytes long"),
  )
  let assert Ok(key_prefix) = bit_array.slice(key, 0, 1)
  use <- bool.guard(
    key_prefix |> bit_array.base16_encode != "04",
    snag.error("key prefix is not the expected 0x04"),
  )
  Ok(PubKey(key))
}

pub fn address_to_bit_array(address: Address) -> BitArray {
  address.addr
}

pub fn address_to_checksummed_address(address: Address) -> String {
  let address = address.addr
  let checksum =
    bit_array.base16_encode(address)
    |> string.lowercase
    |> keccak.hash_utf8_string
  use checksummed_address, index <- yielder.fold(yielder.range(0, 19), "0x")
  let assert Ok(address_byte) = bit_array.slice(address, index, 1)
  let assert Ok(checksum_byte) = bit_array.slice(checksum, index, 1)
  let assert <<address_byte_first_half:4, address_byte_second_half:4>> =
    address_byte
  let assert <<checksum_byte_first_half:4, checksum_byte_second_half:4>> =
    checksum_byte
  let address_first_hex = int.to_base16(address_byte_first_half)
  let address_second_hex = int.to_base16(address_byte_second_half)
  let checksummed_address_first_hex = case
    address_byte_first_half >= 10,
    checksum_byte_first_half >= 8
  {
    True, True -> address_first_hex
    _, _ -> string.lowercase(address_first_hex)
  }
  let checksummed_address_second_hex = case
    address_byte_second_half >= 10,
    checksum_byte_second_half >= 8
  {
    True, True -> address_second_hex
    _, _ -> string.lowercase(address_second_hex)
  }
  checksummed_address
  <> checksummed_address_first_hex
  <> checksummed_address_second_hex
}

pub fn address_to_string(address: Address) -> String {
  "0x" <> bit_array.base16_encode(address.addr)
}

pub fn address_from_string(from: String) -> Result(Address) {
  let no_leading_0x = case from {
    "0x" <> rest -> rest
    _ -> from
  }
  use decoded_address <- result.try(
    bit_array.base16_decode(no_leading_0x)
    |> result.try_recover(fn(_) { snag.error("not a valid hex string") }),
  )
  use <- bool.guard(
    bit_array.byte_size(decoded_address) != 20,
    snag.error("address is not 20 bytes long"),
  )

  Ok(Address(decoded_address))
}

pub fn pubkey_to_address(pubkey: PubKey) -> Address {
  let assert Ok(no_prefix) = bit_array.slice(pubkey.key, 1, 64)
  let assert Ok(address_bits) = bit_array.slice(keccak.hash(no_prefix), 12, 20)
  Address(address_bits)
}
