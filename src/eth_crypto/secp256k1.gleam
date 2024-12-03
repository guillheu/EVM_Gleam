@external(erlang, "Elixir.ExSecp256k1", "recover_compact")
pub fn recover(
  hash: BitArray,
  signature: BitArray,
  recovery_id: Int,
) -> Result(BitArray, Nil)
