import eth_crypto/rlp
import gleam/bit_array
import gleam/list
import gleam/string
import gleeunit/should

type EncodeTestCase {
  EncodeTestCase(from: rlp.RlpInput, expected: Result(BitArray, Nil))
  KnownTestCase(from: rlp.RlpInput, expected: String)
}

const encoding_test_cases = [
  EncodeTestCase(rlp.RlpInt(69), Ok(<<69>>)),
  // single-byte integer values >127 are instead considered as a list with a single element.
  // 129 is 0x81, which is 0x80 + 1. 0x80 is the prefix for byte strings, and add to it the length of the string
  EncodeTestCase(rlp.RlpInt(255), Ok(<<129, 255>>)),
  EncodeTestCase(rlp.RlpInt(256), Ok(<<130, 1, 0>>)),
  EncodeTestCase(rlp.RlpBytes(<<127, 127, 127>>), Ok(<<131, 127, 127, 127>>)),
  EncodeTestCase(rlp.RlpBytes(<<128, 128, 128>>), Ok(<<131, 128, 128, 128>>)),
  EncodeTestCase(rlp.RlpBytes(<<0:size(448)>>), Ok(<<184, 56, 0:size(448)>>)),
  // This following test is for a byte "string" where the length must be encoded on 2 bytes
  // so 2048 bytes, length 256.
  // The length needs to be encoded over 2 bytes: [1, 0]
  EncodeTestCase(
    rlp.RlpBytes(<<0:size(2048)>>),
    Ok(<<185, 1, 0, 0:size(2048)>>),
  ),
  // We are not testing max length case because I just don't have enough RAM (by many orders of magnitude)
  EncodeTestCase(rlp.RlpList([rlp.RlpInt(69)]), Ok(<<193, 69>>)),
  EncodeTestCase(
    rlp.RlpList([rlp.RlpInt(69), rlp.RlpInt(69)]),
    Ok(<<194, 69, 69>>),
  ),
  EncodeTestCase(rlp.RlpList([rlp.RlpBytes(<<127>>)]), Ok(<<193, 127>>)),
  EncodeTestCase(rlp.RlpList([rlp.RlpBytes(<<255>>)]), Ok(<<193, 129, 255>>)),
  EncodeTestCase(
    rlp.RlpList([rlp.RlpBytes(<<127>>), rlp.RlpBytes(<<69>>)]),
    Ok(<<194, 127, 69>>),
  ),
  EncodeTestCase(
    rlp.RlpList([rlp.RlpBytes(<<255>>), rlp.RlpBytes(<<255>>)]),
    Ok(<<194, 129, 255, 129, 255>>),
  ),
  EncodeTestCase(
    rlp.RlpList([rlp.RlpBytes(<<255>>), rlp.RlpInt(255)]),
    Ok(<<194, 129, 255, 129, 255>>),
  ),
  // Known test cases were checked against results from npm's `rlp` package
  KnownTestCase(rlp.RlpList([]), "0xc0"),
  KnownTestCase(
    rlp.RlpList([rlp.RlpInt(1), rlp.RlpInt(2), rlp.RlpInt(3)]),
    "0xc3010203",
  ),
  KnownTestCase(rlp.RlpInt(256), "0x820100"),
  KnownTestCase(rlp.RlpInt(789_456_123), "0x842f0e24fb"),
  KnownTestCase(rlp.RlpInt(789_456_123), "0x842f0e24fb"),
  KnownTestCase(rlp.RlpInt(0), "0x80"),
  KnownTestCase(rlp.RlpBytes(<<>>), "0x80"),
  KnownTestCase(
    rlp.RlpList(
      [
        rlp.RlpInt(0),
        rlp.RlpInt(0),
        rlp.RlpInt(0),
        rlp.RlpInt(0),
        rlp.RlpInt(0),
        rlp.RlpInt(0),
      ],
    ),
    "0xc6808080808080",
  ),
]

pub fn rlp_encode_test() {
  list.each(encoding_test_cases, fn(test_case) {
    case test_case {
      EncodeTestCase(from:, expected:) -> {
        assert expected == rlp.encode(from)
        Nil
      }
      KnownTestCase(from:, expected:) -> {
        assert expected |> string.lowercase
          == "0x"
          <> {
            rlp.encode(from)
            |> should.be_ok
            |> bit_array.base16_encode
            |> string.lowercase
          }
        Nil
      }
    }
  })
}
