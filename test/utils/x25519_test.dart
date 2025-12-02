import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:test/test.dart';

import 'package:tlslite/src/utils/x25519.dart';

Uint8List _hex(String value) => Uint8List.fromList(hex.decode(value));
String _hexStr(List<int> value) => hex.encode(value);

void main() {
  group('decodeUCoordinate', () {
    test('x25519 decode', () {
      final value = _hex('e6db6867583030db3594c1a424b15f7c7'
          '26624ec26b3353b10a903a6d0ab1c4c');
      final scalar = decodeUCoordinate(value, 255);
      expect(
        scalar,
        BigInt.parse('3442643403391959445115510778118882165131616721'
            '5306631574996226621102155684838'),
      );
    });

    test('invalid bit count throws', () {
      final value = _hex('e6db6867583030db3594c1a424b15f7c7'
          '26624ec26b3353b10a903a6d0ab1c4c');
      expect(() => decodeUCoordinate(value, 256), throwsArgumentError);
    });

    test('x448 decode', () {
      final value = _hex('06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f0'
          '20f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086');
      final scalar = decodeUCoordinate(value, 448);
      expect(
        scalar,
        BigInt.parse(
            '38223991081410733011622996123489937703141636524057132514834655'
            '5922438025162094455820962429142971339584360034337310079791515452463053830'),
      );
    });
  });

  test('decodeScalar22519', () {
    final value = _hex(
        'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4');
    final scalar = decodeScalar22519(value);
    expect(
      scalar,
      BigInt.parse(
          '3102984249211504090489556045186308965647277260467826026553122103'
          '6453811406496'),
    );
  });

  test('decodeScalar448', () {
    final value =
        _hex('3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c'
            '984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3');
    final scalar = decodeScalar448(value);
    expect(
      scalar,
      BigInt.parse(
          '5991891753738964027837560161452132561572308560850261299268914594'
          '68622403380588640249457727683869421921443004045221642549886377526240828'),
    );
  });

  group('x25519 uncommon inputs', () {
    test('all zero k', () {
      final k = Uint8List(32);
      final u = _hex(
          'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c');
      final ret = x25519(k, u);
      expect(
        _hexStr(ret),
        '030d7ba1a76719f96d5c39122f690e7856895ee9d24416279eb9182010287113',
      );
    });

    test('all zero u', () {
      final k = _hex(
          'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4');
      final u = Uint8List(32);
      final ret = x25519(k, u);
      expect(_hexStr(ret),
          '0000000000000000000000000000000000000000000000000000000000000000');
    });
  });

  group('x448 uncommon inputs', () {
    test('all zero k', () {
      final k = Uint8List(56);
      final u = _hex(
          '06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031'
          'ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086');
      final ret = x448(k, u);
      expect(
        _hexStr(ret),
        'f8d21fea4fe227fa556d27ec5317d8394db22217e27a96c8f7b47d36a4e15ba1'
        'bef872684ba18ee5ce72577b0aed87e98a3714ab32d9d169',
      );
    });

    test('all zero u', () {
      final k = _hex(
          '3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c'
          '984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3');
      final u = Uint8List(56);
      final ret = x448(k, u);
      expect(ret, equals(Uint8List(56)));
    });
  });

  group('known answer tests', () {
    test('x25519 vector 1', () {
      final k = _hex(
          'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4');
      final u = _hex(
          'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c');
      final ret = x25519(k, u);
      expect(
        _hexStr(ret),
        'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
      );
    });

    test('x25519 vector 2', () {
      final k = _hex(
          '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d');
      final u = _hex(
          'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493');
      final ret = x25519(k, u);
      expect(
        _hexStr(ret),
        '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957',
      );
    });

    test('x448 vector 1', () {
      final k = _hex(
          '3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c'
          '984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3');
      final u = _hex(
          '06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031'
          'ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086');
      final ret = x448(k, u);
      expect(
        _hexStr(ret),
        'ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaad'
            'eb445fc66a01b0779d98223961111e21766282f73dd96b6f',
      );
    });

    test('x448 vector 2', () {
      final k = _hex(
          '203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd7'
          '7c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f');
      final u = _hex(
          '0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d0158'
          '94e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db');
      final ret = x448(k, u);
      expect(
        _hexStr(ret),
        '884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3'
        'a5700df34321d62077e63633c575c1c954514e99da7c179d',
      );
    });
  });

  test('x25519 one iteration', () {
    final k = _hex(
        '0900000000000000000000000000000000000000000000000000000000000000');
    var u = Uint8List.fromList(k);
    final ret = x25519(k, u);
    expect(
      _hexStr(ret),
      '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079',
    );
  });

  test('x25519 thousand iterations', () {
    var k = _hex(
        '0900000000000000000000000000000000000000000000000000000000000000');
    var u = Uint8List.fromList(k);
    for (var i = 0; i < 1000; i++) {
      final nextU = Uint8List.fromList(k);
      final nextK = x25519(k, u);
      u = nextU;
      k = nextK;
    }
    expect(
      _hexStr(k),
      '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51',
    );
  }, skip: 'slow test case');

  test('x25519 million iterations', () {
    var k = _hex(
        '0900000000000000000000000000000000000000000000000000000000000000');
    var u = Uint8List.fromList(k);
    for (var i = 0; i < 1000000; i++) {
      final nextU = Uint8List.fromList(k);
      final nextK = x25519(k, u);
      u = nextU;
      k = nextK;
    }
    expect(
      _hexStr(k),
      '7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424',
    );
  }, skip: 'very slow test case');

  test('x448 one iteration', () {
    final k =
        _hex('0500000000000000000000000000000000000000000000000000000000000000'
            '000000000000000000000000000000000000000000000000');
    var u = Uint8List.fromList(k);
    final ret = x448(k, u);
    expect(
      _hexStr(ret),
      '3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd'
      '0db897086239492caf350b51f833868b9bc2b3bca9cf4113',
    );
  });

  test('x448 thousand iterations', () {
    var k =
        _hex('0500000000000000000000000000000000000000000000000000000000000000'
            '000000000000000000000000000000000000000000000000');
    var u = Uint8List.fromList(k);
    for (var i = 0; i < 1000; i++) {
      final nextU = Uint8List.fromList(k);
      final nextK = x448(k, u);
      u = nextU;
      k = nextK;
    }
    expect(
      _hexStr(k),
      'aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf'
      '10d087202db88286e2b79fceea3ec353ef54faa26e219f38',
    );
  }, skip: 'slow test case');

  test('x448 million iterations', () {
    var k =
        _hex('0500000000000000000000000000000000000000000000000000000000000000'
            '000000000000000000000000000000000000000000000000');
    var u = Uint8List.fromList(k);
    for (var i = 0; i < 1000000; i++) {
      final nextU = Uint8List.fromList(k);
      final nextK = x448(k, u);
      u = nextU;
      k = nextK;
    }
    expect(
      _hexStr(k),
      '077f453681caca3693198420bbe515cae0002472519b3e67661a7e89cab94695'
      'c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37',
    );
  }, skip: 'very slow test case');

  group('RFC 7748 ECDH', () {
    test('x25519 share A', () {
      final aRandom = _hex(
          '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
      final aPublic = x25519(aRandom, Uint8List.fromList(X25519_G));
      expect(
        _hexStr(aPublic),
        '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
      );
    });

    test('x25519 share B', () {
      final bRandom = _hex(
          '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
      final bPublic = x25519(bRandom, Uint8List.fromList(X25519_G));
      expect(
        _hexStr(bPublic),
        'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
      );
    });

    test('x25519 shared secret', () {
      final aRandom = _hex(
          '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
      final aPublic = x25519(aRandom, Uint8List.fromList(X25519_G));
      final bRandom = _hex(
          '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
      final bPublic = x25519(bRandom, Uint8List.fromList(X25519_G));
      final aShared = x25519(aRandom, bPublic);
      final bShared = x25519(bRandom, aPublic);
      expect(_hexStr(aShared), _hexStr(bShared));
      expect(
        _hexStr(aShared),
        '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
      );
    });

    test('x448 share A', () {
      final aRandom = _hex(
          '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf5'
          '74a9419744897391006382a6f127ab1d9ac2d8c0a598726b');
      final aPublic = x448(aRandom, Uint8List.fromList(X448_G));
      expect(
        _hexStr(aPublic),
        '9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bb'
        'c836647241d953d40c5b12da88120d53177f80e532c41fa0',
      );
    });

    test('x448 share B', () {
      final bRandom = _hex(
          '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120'
          'bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d');
      final bPublic = x448(bRandom, Uint8List.fromList(X448_G));
      expect(
        _hexStr(bPublic),
        '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972'
        'fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609',
      );
    });

    test('x448 shared secret', () {
      final aRandom = _hex(
          '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf5'
          '74a9419744897391006382a6f127ab1d9ac2d8c0a598726b');
      final aPublic = x448(aRandom, Uint8List.fromList(X448_G));
      final bRandom = _hex(
          '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120'
          'bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d');
      final bPublic = x448(bRandom, Uint8List.fromList(X448_G));
      final aShared = x448(aRandom, bPublic);
      final bShared = x448(bRandom, aPublic);
      expect(_hexStr(aShared), _hexStr(bShared));
      expect(
        _hexStr(aShared),
        '07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56'
        'fd2464c335543936521c24403085d59a449a5037514a879d',
      );
    });
  });
}
