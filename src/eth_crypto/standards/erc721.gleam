import eth_crypto/eth.{type Address, type SmartContract}
import gleam/list

const erc20_functions = [
  #("decimals", "decimals()"), #("totalSupply", "totalSupply()"),
  #("balanceOf", "balanceOf(address)"), #("ownerOf", "ownerOf(uint256)"),
  #("getApproved", "getApproved(uint256)"),
  #("isApprovedForAll", "isApprovedForAll(address,address)"),
]

const erc20_events = [
  #("transfer", "Transfer(address,address,uint256)"),
  #("approval", "Approval(address,address,uint256)"),
  #("approvalForAll", "ApprovalForAll(address,address,bool)"),
]

pub fn new(at: Address) -> SmartContract {
  eth.new_smart_contract(at)
  |> add_functions
  |> add_events
}

fn add_functions(contract: SmartContract) -> SmartContract {
  use contract, #(name, signature) <- list.fold(erc20_functions, contract)
  eth.add_function(contract, name, signature)
}

fn add_events(contract: SmartContract) -> SmartContract {
  use contract, #(name, signature) <- list.fold(erc20_events, contract)
  eth.add_event(contract, name, signature)
}
