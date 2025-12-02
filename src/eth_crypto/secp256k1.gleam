@external(erlang, "Elixir.ExSecp256k1", "create_public_key")
pub fn privkey_to_pubkey(privkey: BitArray) -> Result(BitArray, Nil)

@external(erlang, "Elixir.ExSecp256k1", "recover_compact")
pub fn recover(
  hash: BitArray,
  signature: BitArray,
  recovery_id: Int,
) -> Result(BitArray, Nil)

@external(erlang, "Elixir.ExSecp256k1", "sign_compact")
pub fn sign_compact(
  message: BitArray,
  private_key: BitArray,
) -> Result(#(BitArray, Int), Nil)

@external(erlang, "Elixir.ExSecp256k1", "sign")
pub fn sign(
  message: BitArray,
  private_key: BitArray,
) -> Result(#(BitArray, BitArray, Int), Nil)
