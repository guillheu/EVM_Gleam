import eth_crypto/secp256k1
import gleam/bit_array
import gleam/bool
import gleam/dict.{type Dict}
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/int
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri.{type Uri}
import gleam/yielder

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

pub type RpcResponse(result_type) {
  RpcResult(jsonrpc: String, id: Int, result: result_type)
  RpcError(jsonrpc: String, id: Int, error: RpcErrorContent)
  // Undefined
}

pub type EthError {
  MissingSelectorId(id: String)
  SelectorTypeMismatch(
    expected: fn(String, String) -> Selector,
    found: fn(String, String) -> Selector,
  )
  HttpError(httpc.HttpError)
  HttpStatusNon200(status: Int)
  JsonDecodeError(json.DecodeError)
  RpcResponseError(RpcErrorContent)
  RpcResponseFieldMissing(missing_field: String)
  RpcResponseDecodingFailed(details: String)
  InvalidSignatureByteSize(expected: Int, found: Int)
  InvalidKeyByteSize(expected: Int, found: Int)
  InvalidKeyPrefix(expected: String, found: String)
  InvalidAddressNotHex
  InvalidAddressLength(expected: Int, found: Int)
}

fn rpc_response_decoder(
  rpc_result_decoder: decode.Decoder(result_type),
) -> decode.Decoder(RpcResponse(result_type)) {
  use jsonrpc <- decode.field("jsonrpc", decode.string)
  use id <- decode.field("id", decode.int)
  // Either we have a "result" field which gets decoded by the rpc_result_decoder
  // (because RPC results differ based on the RPC function that was called)
  // OR we have a "error" field which always takes the same decoder.
  // In both cases, we then transfer (map) the decoded optional field into the appropriate final RpcResponse variant.
  // If neither "result" nor "error" is found, we get a decode failure with the `Undefined` variant instead.

  decode.one_of(
    decode.at(["result"], rpc_result_decoder)
      |> decode.map(fn(result) { RpcResult(jsonrpc:, id:, result:) }),
    [
      decode.at(["error"], rpc_error_content_decoder())
      |> decode.map(fn(error) { RpcError(jsonrpc:, id:, error:) }),
    ],
  )
}

pub type RpcErrorContent {
  RpcErrorContent(code: Int, message: String)
}

fn rpc_error_content_decoder() -> decode.Decoder(RpcErrorContent) {
  use code <- decode.field("code", decode.int)
  use message <- decode.field("message", decode.string)
  decode.success(RpcErrorContent(code:, message:))
}

pub fn new_smart_contract(at: Address) -> SmartContract {
  SmartContract(at, dict.new())
}

pub fn get_function(
  contract: SmartContract,
  id: String,
) -> Result(Selector, EthError) {
  case dict.get(contract.selectors, id) {
    Error(_) -> Error(MissingSelectorId(id))
    Ok(selector) ->
      case selector {
        Function(_, _) -> Ok(selector)
        Event(_, _) ->
          Error(SelectorTypeMismatch(expected: Function, found: Event))
      }
  }
}

pub fn get_event(
  contract: SmartContract,
  id: String,
) -> Result(Selector, EthError) {
  case dict.get(contract.selectors, id) {
    Error(_) -> Error(MissingSelectorId(id))
    Ok(selector) ->
      case selector {
        Event(_, _) -> Ok(selector)
        Function(_, _) ->
          Error(SelectorTypeMismatch(expected: Event, found: Function))
      }
  }
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

pub fn eth_get_block_miner(
  rpc_uri rpc_uri: Uri,
  block_number block_number: Option(Int),
) -> Result(Address, EthError) {
  let assert Ok(request) = request.from_uri(rpc_uri)
  let block_number = case block_number {
    Some(value) -> "0x" <> int.to_base16(value)
    None -> "latest"
  }
  let body = "{
  \"jsonrpc\": \"2.0\",
  \"id\": 1,
  \"method\": \"eth_getBlockByNumber\",
  \"params\": [
    \"" <> block_number <> "\",
    false
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
        Error(HttpStatusNon200(res.status)),
      )

      use rpc_response <- result.try(
        json.parse(res.body, rpc_response_decoder(get_block_result_decoder()))
        |> result.map_error(JsonDecodeError),
      )
      case rpc_response {
        RpcError(_, _, err) -> Error(RpcResponseError(err))
        RpcResult(_, _, GetBlockResult(miner_address_string)) ->
          address_from_string(miner_address_string)
      }
    }
    Error(e) -> Error(HttpError(e))
  }
}

pub fn eth_get_balance(
  rpc_uri rpc_uri: Uri,
  address address: Address,
) -> Result(Int, EthError) {
  let assert Ok(request) = request.from_uri(rpc_uri)
  let body = "{
  \"jsonrpc\": \"2.0\",
  \"id\": 1,
  \"method\": \"eth_getBalance\",
  \"params\": [
    \"" <> address_to_string(address) <> "\",
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
        Error(HttpStatusNon200(res.status)),
      )

      use get_balance <- result.try(
        json.parse(res.body, rpc_response_decoder(decode.string))
        |> result.map_error(JsonDecodeError),
      )
      case get_balance {
        RpcError(_, _, err) -> Error(RpcResponseError(err))
        RpcResult(_, _, res) ->
          {
            use #(_, balance_string) <- result.try(string.split_once(res, "x"))
            result.map(
              balance_string
                |> int.base_parse(16),
              fn(r) { r },
            )
          }
          |> result.replace_error(RpcResponseDecodingFailed(
            "balance field is not hexadecimal",
          ))
      }
    }
    Error(e) -> Error(HttpError(e))
  }
}

pub fn eth_call(
  contract: SmartContract,
  function_selector selector: Selector,
  data data: BitArray,
  rpc_uri rpc_uri: Uri,
) -> Result(RpcResponse(String), EthError) {
  //TODO:
  // add decoder function as argument
  // and decode the response
  let data =
    case bit_array.byte_size(data) % 32 {
      0 -> data
      any -> {
        let padding = { 32 - any } * 8
        <<0:size(padding), data:bits>>
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
            Error(HttpStatusNon200(res.status)),
          )
          res.body
          |> json.parse(rpc_response_decoder(decode.string))
          |> result.map_error(JsonDecodeError)
        }
        Error(e) -> Error(HttpError(e))
      }
    }
    _ -> Error(SelectorTypeMismatch(expected: Function, found: Event))
  }
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

pub fn signature_from(from: BitArray) -> Result(Signature, EthError) {
  let signature_byte_size = bit_array.byte_size(from)
  use <- bool.guard(
    signature_byte_size != 65,
    Error(InvalidSignatureByteSize(expected: 65, found: signature_byte_size)),
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

pub fn new_pubkey(key: BitArray) -> Result(PubKey, EthError) {
  let key_byte_size = bit_array.byte_size(key)
  use <- bool.guard(
    key_byte_size != 65,
    Error(InvalidKeyByteSize(expected: 65, found: key_byte_size)),
  )
  let assert Ok(key_prefix) = bit_array.slice(key, 0, 1)
  let key_prefix = key_prefix |> bit_array.base16_encode
  use <- bool.guard(
    key_prefix != "04",
    Error(InvalidKeyPrefix(expected: "04", found: key_prefix)),
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

pub fn address_from_string(from: String) -> Result(Address, EthError) {
  let no_leading_0x = case from {
    "0x" <> rest -> rest
    _ -> from
  }
  use decoded_address <- result.try(
    bit_array.base16_decode(no_leading_0x)
    |> result.replace_error(InvalidAddressNotHex),
  )
  let address_byte_size = bit_array.byte_size(decoded_address)
  use <- bool.guard(
    address_byte_size != 20,
    Error(InvalidAddressLength(expected: 20, found: address_byte_size)),
  )

  Ok(Address(decoded_address))
}

pub fn pubkey_to_address(pubkey: PubKey) -> Address {
  let assert Ok(no_prefix) = bit_array.slice(pubkey.key, 1, 64)
  let assert Ok(address_bits) = bit_array.slice(keccak.hash(no_prefix), 12, 20)
  Address(address_bits)
}

pub fn get_contract_address(smart_contract contract: SmartContract) -> Address {
  contract.addr
}

type GetBlockResult {
  GetBlockResult(miner: String)
}

fn get_block_result_decoder() -> decode.Decoder(GetBlockResult) {
  use miner <- decode.field("miner", decode.string)
  decode.success(GetBlockResult(miner:))
}
