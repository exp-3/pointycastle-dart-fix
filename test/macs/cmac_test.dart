// See file LICENSE for more information.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';
import 'package:test/test.dart';

import '../test/runners/mac.dart';
import '../test/src/helpers.dart';

void main() {
  final mac = Mac('AES/CMAC');

  // Test vectors from AES-CMAC RFC, section 4.
  // https://tools.ietf.org/html/rfc4493
  final key = Uint8List.fromList([
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, //
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, //
  ]);
  final keyParam = KeyParameter(key);

  mac.init(keyParam);

  runMacTests(mac, [
    PlainTextDigestPair(
        Uint8List.fromList([]), 'bb1d6929e95937287fa37d129b756746'),
    PlainTextDigestPair(
        Uint8List.fromList([
          0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, //
          0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, //
        ]),
        '070a16b46b4d4144f79bdd9dd04a287c'),
    PlainTextDigestPair(
        Uint8List.fromList([
          0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, //
          0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, //
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, //
          0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, //
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, //
        ]),
        'dfa66747de9ae63030ca32611497c827'),
    PlainTextDigestPair(
        Uint8List.fromList([
          0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, //
          0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, //
          0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, //
          0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, //
          0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, //
          0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, //
          0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, //
          0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10, //
        ]),
        '51f0bebf7e3b9d92fc49741779363cfe'),
  ]);

  // AES-192/256 CMAC vectors from Bouncy Castle's CMacTest:
  // https://github.com/bcgit/bc-java/blob/main/core/src/test/java/org/bouncycastle/crypto/test/CMacTest.java
  _runCmacKeySizeTests(
    '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
    [
      'd17ddf46adaacde531cac483de7a9367',
      '9e99a7bf31e710900662f65e617c5184',
      '8a1de5be2eb31aad089a82e6ee908b0e',
      'a1d5df0eed790f794d77589659f39a11',
    ],
  );
  _runCmacKeySizeTests(
    '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
    [
      '028962f61b7bf89efc6b551f4667d983',
      '28a7023f452e8f82bd4bf28d8c37c35c',
      'aaf3d8f1de5640c232f5b169b9c911e6',
      'e1992190549f6ed5696a2c056c315410',
    ],
  );
}

void _runCmacKeySizeTests(String keyHex, List<String> expectedTags) {
  const lengths = [0, 16, 40, 64];
  final message = createUint8ListFromHexString(
    '6bc1bee22e409f96e93d7e117393172a'
    'ae2d8a571e03ac9c9eb76fac45af8e51'
    '30c81c46a35ce411e5fbc1191a0a52ef'
    'f69f2445df4f9b17ad2b417be66c3710',
  );

  group('AES-${keyHex.length * 4}', () {
    final mac = Mac('AES/CMAC')
      ..init(KeyParameter(createUint8ListFromHexString(keyHex)));
    runMacTests(mac, [
      for (var i = 0; i < lengths.length; i++)
        PlainTextDigestPair(message.sublist(0, lengths[i]), expectedTags[i]),
    ]);
  });
}
