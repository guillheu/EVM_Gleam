import createKeccakHash from "keccak";
import { BitArray } from "./gleam.mjs";

export function hash(message) {
    // if (message instanceof BitArray) {
    //     message = toBitArray(message)
    // }
  const hash = createKeccakHash("keccak256").update(message);
  const hex = hash.digest();
  return new BitArray(hex);
}