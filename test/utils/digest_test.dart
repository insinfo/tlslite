import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:pointycastle/digests/sha3.dart' as pc;
import 'package:pointycastle/digests/shake.dart' as pc;
import 'package:test/test.dart';
import 'package:tlslite/src/utils/digest/digest.dart';

// Official vectors: FIPS 180-4 / NIST examples (SHA-1/SHA-2), RFC 1321 (MD5),
// FIPS 202 examples (SHA-3, SHAKE with 1600-bit message and 4096-bit output),
// RFC 4231 (HMAC-SHA-2) and RFC 2202 (HMAC-MD5/SHA-1). The SHA-256 fingerprints
// of long SHAKE outputs were cross-checked against Python hashlib (OpenSSL).

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List _rand(Random r, int n) {
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) {
    out[i] = r.nextInt(256);
  }
  return out;
}

final _messages = <String, List<int>>{
  'empty': <int>[],
  'abc': ascii.encode('abc'),
  '448':
      ascii.encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
  '896': ascii.encode('abcdefghbcdefghicdefghijdefghijkefghijklfghijklm'
      'ghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu'),
  'million': Uint8List(1000000)..fillRange(0, 1000000, 0x61),
  'a3x200': Uint8List(200)..fillRange(0, 200, 0xa3),
};

final _cryptoRef = <String, crypto.Hash>{
  'md5': crypto.md5,
  'sha1': crypto.sha1,
  'sha224': crypto.sha224,
  'sha256': crypto.sha256,
  'sha384': crypto.sha384,
  'sha512': crypto.sha512,
};

/// Lengths 0..300 plus a few large ones (block-boundary heavy).
final _lengths = [
  for (var i = 0; i <= 300; i++) i,
  511, 512, 1000, 4095, 4096, 65537, (1 << 20) + 3, //
];

/// Feeds [data] to [d] in random-sized chunks.
void _feedChunked(
    Random r, void Function(List<int>, int, int) update, Uint8List data) {
  var pos = 0;
  while (pos < data.length) {
    final step = r.nextInt(4) == 0
        ? r.nextInt(400) + 1
        : r.nextInt(r.nextBool() ? 8 : 150) + 1;
    final end = min(pos + step, data.length);
    update(data, pos, end);
    pos = end;
  }
}

const _rfc4231 = <String, Map<String, String>>{
  'TC1': {
    'sha224': '896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22',
    'sha256':
        'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    'sha384':
        'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6',
    'sha512':
        '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
  },
  'TC2': {
    'sha224': 'a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44',
    'sha256':
        '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    'sha384':
        'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649',
    'sha512':
        '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
  },
  'TC3': {
    'sha224': '7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea',
    'sha256':
        '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
    'sha384':
        '88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27',
    'sha512':
        'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
  },
  'TC4': {
    'sha224': '6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a',
    'sha256':
        '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
    'sha384':
        '3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb',
    'sha512':
        'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
  },
  'TC5': {
    'sha224': '0e2aea68a90c8d37c988bcdb9fca6fa8',
    'sha256': 'a3b6167473100ee06e0c796c2955552b',
    'sha384': '3abf34c3503b2a23a46efc619baef897',
    'sha512': '415fad6271580a531d4179bc891d87a6',
  },
  'TC6': {
    'sha224': '95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e',
    'sha256':
        '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
    'sha384':
        '4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952',
    'sha512':
        '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
  },
  'TC7': {
    'sha224': '3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1',
    'sha256':
        '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
    'sha384':
        '6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e',
    'sha512':
        'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58',
  },
};
const _rfc2202 = <String, List<String>>{
  'md5': [
    '9294727a3638bb1c13f48ef8158bfc9d',
    '750c783e6ab0b503eaa86e310a5db738',
    '56be34521d144c88dbb8c733f0e8b3f6',
    '697eaf0aca3a3aea3a75164746ffaa79',
    '56461ef2342edc00f9bab995690efd4c',
    '6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd',
    '6f630fad67cda0ee1fb1f562db3aa53e'
  ],
  'sha1': [
    'b617318655057264e28bc0b6fb378c8ef146be00',
    'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79',
    '125d7342b9ac11cd91a39af48aa17b4f63f175d3',
    '4c9007f4026250c6bc8414f9bf50c86c2d7235da',
    '4c1a03424b55e07fe7f27be1d58bb9324a9a5a04',
    'aa4ae5e15272d00e95705637ce8a3b55ed402112',
    'e8e99d0f45237d786d6bbaa7965c7808bbff1a91'
  ],
};
const _sha2Vectors = <String, Map<String, String>>{
  'sha1': {
    'abc': 'a9993e364706816aba3e25717850c26c9cd0d89d',
    '448': '84983e441c3bd26ebaae4aa1f95129e5e54670f1',
    '896': 'a49b2446a02c645bf419f995b67091253a04a259',
    'million': '34aa973cd4c4daa4f61eeb2bdbad27316534016f',
    'empty': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
  },
  'sha224': {
    'abc': '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7',
    '448': '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525',
    '896': 'c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3',
    'million': '20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67',
    'empty': 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
  },
  'sha256': {
    'abc': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    '448': '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    '896': 'cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1',
    'million':
        'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
    'empty': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  },
  'sha384': {
    'abc':
        'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
    '448':
        '3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b',
    '896':
        '09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039',
    'million':
        '9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985',
    'empty':
        '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
  },
  'sha512': {
    'abc':
        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    '448':
        '204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445',
    '896':
        '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909',
    'million':
        'e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b',
    'empty':
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
  },
};
const _sha3Vectors = <String, Map<String, String>>{
  'sha3_224': {
    'empty': '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7',
    'abc': 'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf',
    '448': '8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33',
    'a3x200': '9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0',
    'million': 'd69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c',
  },
  'sha3_256': {
    'empty': 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
    'abc': '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
    '448': '41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376',
    'a3x200':
        '79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787',
    'million':
        '5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1',
  },
  'sha3_384': {
    'empty':
        '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004',
    'abc':
        'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25',
    '448':
        '991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22',
    'a3x200':
        '1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd76197a31fd55ee989f2d7050dd473e8f',
    'million':
        'eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340',
  },
  'sha3_512': {
    'empty':
        'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
    'abc':
        'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
    '448':
        '04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e',
    'a3x200':
        'e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca81b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00',
    'million':
        '3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87',
  },
};
const _shake128A3x200 =
    '131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037cf232ef7164a6d1eb448c8908186ad852d3f85a5cf28da1ab6fe3438171978467f1c05d58c7ef38c284c41f6c2221a76f12ab1c04082660250802294fb87180213fdef5b0ecb7df50ca1f8555be14d32e10f6edcde892c09424b29f597afc270c904556bfcb47a7d40778d390923642b3cbd0579e60908d5a000c1d08b98ef933f806445bf87f8b009ba9e94f7266122ed7ac24e5e266c42a82fa1bbefb7b8db0066e16a85e0493f07df4809aec084a593748ac3dde5a6d7aae1e8b6e5352b2d71efbb47d4caeed5e6d633805d2d323e6fd81b4684b93a2677d45e7421c2c6aea259b855a698fd7d13477a1fe53e5a4a6197dbec5ce95f505b520bcd9570c4a8265a7e01f89c0c002c59bfec6cd4a5c109258953ee5ee70cd577ee217af21fa70178f0946c9bf6ca8751793479f6b537737e40b6ed28511d8a2d7e73eb75f8daac912ff906e0ab955b083bac45a8e5e9b744c8506f37e9b4e749a184b30f43eb188d855f1b70d71ff3e50c537ac1b0f8974f0fe1a6ad295ba42f6aec74d123a7abedde6e2c0711cab36be5acb1a5a11a4b1db08ba6982efccd716929a7741cfc63aa4435e0b69a9063e880795c3dc5ef3272e11c497a91acf699fefee206227a44c9fb359fd56ac0a9a75a743cff6862f17d7259ab075216c0699511643b6439';
const _shake256A3x200 =
    'cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b1048a7f64e1074cd629e85ad7566048efc4fb500b486a3309a8f26724c0ed628001a1099422468de726f1061d99eb9e93604d5aa7467d4b1bd6484582a384317d7f47d750b8f5499512bb85a226c4243556e696f6bd072c5aa2d9b69730244b56853d16970ad817e213e470618178001c9fb56c54fefa5fee67d2da524bb3b0b61ef0e9114a92cdbb6cccb98615cfe76e3510dd88d1cc28ff99287512f24bfafa1a76877b6f37198e3a641c68a7c42d45fa7acc10dae5f3cefb7b735f12d4e589f7a456e78c0f5e4c4471fffa5e4fa0514ae974d8c2648513b5db494cea847156d277ad0e141c24c7839064cd08851bc2e7ca109fd4e251c35bb0a04fb05b364ff8c4d8b59bc303e25328c09a882e952518e1a8ae0ff265d61c465896973d7490499dc639fb8502b39456791b1b6ec5bcc5d9ac36a6df622a070d43fed781f5f149f7b62675e7d1a4d6dec48c1c7164586eae06a51208c0b791244d307726505c3ad4b26b6822377257aa152037560a739714a3ca79bd605547c9b78dd1f596f2d4f1791bc689a0e9b799a37339c04275733740143ef5d2b58b96a363d4e08076a1a9d7846436e4dca5728b6f760eef0ca92bf0be5615e96959d767197a0beeb';
const _shake128EmptySha256 = <int, String>{
  1: '620bfdaa346b088fb49998d92f19a7eaf6bfc2fb0aee015753966da1028cb731',
  135: '2501aabbbcd9387a13869842a4f3fc3c81af80ed6c6a89bd33d31984de31f243',
  136: '8605d5d064f9728f76b21c8c740c7d2fa6265bdea8ddf78072310b57c455ac38',
  137: 'b0a9908cab9074d4efa8249753c72f07c322d35247a0441421f0d61091b5e59a',
  167: '8837410d1dea9b1a958889260a0b47a294cd8b327dca762a072b4f671f4afacf',
  168: 'b162b569f72ca793ef913527809c6f13cae99b3430c6c134a69248b9237aed0f',
  169: '83b9e2d383537895a587d8a7bcf78de9d5eab8f9889e9e840a70cd0d82a2c4c8',
  1000: '218ae7a5107911c8702edb40ec361ebbe57b6b6288287889361baabdb4d5cc9c',
  10000: '4da827b680bc13a6a42695ddd6ababa66a81806aa9a6e7fb218ad99bd52e2f25',
};
const _shake128Abc4096Sha256 =
    '014aff4bcdb67991c63d96a7486072e07c5479b5f1861fe9495ff52e0692c95c';
const _shake256Abc4096Sha256 =
    '3caa96e461376be0bdec7acdb4d2a4f40d7acd9c8124a5ac0c140860b06de980';

void main() {
  group('official vectors', () {
    test('MD5 (RFC 1321)', () {
      const v = {
        '': 'd41d8cd98f00b204e9800998ecf8427e',
        'a': '0cc175b9c0f1b6a831c399e269772661',
        'abc': '900150983cd24fb0d6963f7d28e17f72',
        'message digest': 'f96b697d7cb7938d525a2f31aaf161d0',
        'abcdefghijklmnopqrstuvwxyz': 'c3fcd3d76192e4007dfb496cca67e13b',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789':
            'd174ab98d277d9f5a5611c2c9f419d9f',
        '1234567890123456789012345678901234567890'
                '1234567890123456789012345678901234567890':
            '57edf4a22be3c955ac49da2e2107b67a',
      };
      v.forEach((msg, h) {
        expect(_hex(md5Hash(ascii.encode(msg))), h, reason: msg);
      });
    });

    test('SHA-1/SHA-2 (FIPS 180-4)', () {
      _sha2Vectors.forEach((alg, vs) {
        vs.forEach((name, h) {
          expect(_hex(hashBytes(alg, _messages[name]!)), h,
              reason: '$alg $name');
        });
      });
    });

    test('SHA-3 (FIPS 202)', () {
      _sha3Vectors.forEach((alg, vs) {
        vs.forEach((name, h) {
          expect(_hex(hashBytes(alg, _messages[name]!)), h,
              reason: '$alg $name');
        });
      });
      expect(
          _hex(sha3_256(_messages['abc']!)), _sha3Vectors['sha3_256']!['abc']);
      expect(
          _hex(sha3_512(_messages['abc']!)), _sha3Vectors['sha3_512']!['abc']);
    });

    test('SHAKE (FIPS 202) including long outputs', () {
      expect(_hex(shake128(const [], 32)),
          '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26');
      expect(
          _hex(shake256(const [], 64)),
          '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f'
          'd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be');
      final m = _messages['a3x200']!;
      expect(_hex(shake128(m, 512)), _shake128A3x200);
      expect(_hex(shake256(m, 512)), _shake256A3x200);
      _shake128EmptySha256.forEach((n, h) {
        expect(_hex(sha256Hash(shake128(const [], n))), h, reason: 'n=$n');
      });
      expect(_hex(sha256Hash(shake128(ascii.encode('abc'), 4096))),
          _shake128Abc4096Sha256);
      expect(_hex(sha256Hash(shake256(ascii.encode('abc'), 4096))),
          _shake256Abc4096Sha256);
    });

    test('HMAC-SHA-2 (RFC 4231)', () {
      final cases = <String, (List<int>, List<int>)>{
        'TC1': (List.filled(20, 0x0b), ascii.encode('Hi There')),
        'TC2': (
          ascii.encode('Jefe'),
          ascii.encode('what do ya want for nothing?')
        ),
        'TC3': (List.filled(20, 0xaa), List.filled(50, 0xdd)),
        'TC4': (List.generate(25, (i) => i + 1), List.filled(50, 0xcd)),
        'TC5': (List.filled(20, 0x0c), ascii.encode('Test With Truncation')),
        'TC6': (
          List.filled(131, 0xaa),
          ascii.encode('Test Using Larger Than Block-Size Key - Hash Key First')
        ),
        'TC7': (
          List.filled(131, 0xaa),
          ascii.encode('This is a test using a larger than block-size key '
              'and a larger than block-size data. The key needs to be hashed '
              'before being used by the HMAC algorithm.')
        ),
      };
      cases.forEach((tc, kd) {
        _rfc4231[tc]!.forEach((alg, expected) {
          final mac = _hex(hmac(alg, kd.$1, kd.$2));
          expect(mac.substring(0, expected.length), expected,
              reason: '$tc $alg');
        });
      });
    });

    test('HMAC-MD5 / HMAC-SHA1 (RFC 2202)', () {
      final big = 'Test Using Larger Than Block-Size Key - Hash Key First';
      final big2 = 'Test Using Larger Than Block-Size Key and Larger Than One '
          'Block-Size Data';
      final common = <(List<int>, List<int>)>[
        (ascii.encode('Jefe'), ascii.encode('what do ya want for nothing?')),
        (List.generate(25, (i) => i + 1), List.filled(50, 0xcd)),
        (List.filled(80, 0xaa), ascii.encode(big)),
        (List.filled(80, 0xaa), ascii.encode(big2)),
      ];
      List<(List<int>, List<int>)> casesFor(int keyLen) => [
            (List.filled(keyLen, 0x0b), ascii.encode('Hi There')),
            common[0],
            (List.filled(keyLen, 0xaa), List.filled(50, 0xdd)),
            common[1],
            (List.filled(keyLen, 0x0c), ascii.encode('Test With Truncation')),
            common[2],
            common[3],
          ];
      final md5Cases = casesFor(16);
      final sha1Cases = casesFor(20);
      for (var i = 0; i < 7; i++) {
        expect(_hex(hmac('md5', md5Cases[i].$1, md5Cases[i].$2)),
            _rfc2202['md5']![i],
            reason: 'md5 TC${i + 1}');
        expect(_hex(hmac('sha1', sha1Cases[i].$1, sha1Cases[i].$2)),
            _rfc2202['sha1']![i],
            reason: 'sha1 TC${i + 1}');
      }
    });
  });

  group('vs package:crypto', () {
    for (final alg in _cryptoRef.keys) {
      test('$alg one-shot, lengths 0..300 + large', () {
        final r = Random(alg.hashCode);
        for (final n in _lengths) {
          final data = _rand(r, n);
          expect(hashBytes(alg, data), _cryptoRef[alg]!.convert(data).bytes,
              reason: '$alg len=$n');
        }
      });

      test('$alg incremental with random splits and peeking', () {
        final r = Random(alg.hashCode + 1);
        for (var iter = 0; iter < 120; iter++) {
          final n = iter < 100 ? r.nextInt(1200) : r.nextInt(70000);
          final data = _rand(r, n);
          final d = createDigest(alg);
          var fed = 0;
          _feedChunked(r, (b, s, e) {
            d.update(b, s, e);
            fed = e;
            if (r.nextInt(10) == 0) {
              // Peek must not disturb the running state.
              expect(d.digest(),
                  _cryptoRef[alg]!.convert(data.sublist(0, fed)).bytes);
            }
          }, data);
          final ref = _cryptoRef[alg]!.convert(data).bytes;
          final c = d.clone();
          expect(d.digest(), ref);
          expect(d.finish(), ref);
          // After finish() the object is reset.
          expect(d.finish(), _cryptoRef[alg]!.convert(const []).bytes);
          expect(c.finish(), ref);
        }
      });

      test('$alg accepts plain List<int> and sub-ranges', () {
        final r = Random(7);
        final data = _rand(r, 333);
        final d = createDigest(alg)..update(data.toList(), 10, 300);
        expect(
            d.finish(), _cryptoRef[alg]!.convert(data.sublist(10, 300)).bytes);
      });
    }

    test('HMAC all algorithms, random keys and data', () {
      final r = Random(42);
      for (final alg in _cryptoRef.keys) {
        for (var iter = 0; iter < 150; iter++) {
          final key = _rand(r, r.nextInt(300));
          final data = _rand(r, iter < 140 ? r.nextInt(600) : r.nextInt(20000));
          final ref = crypto.Hmac(_cryptoRef[alg]!, key).convert(data).bytes;
          expect(hmac(alg, key, data), ref, reason: '$alg iter=$iter');
          final m = createHmac(alg, key);
          _feedChunked(r, m.update, data);
          final c = m.clone();
          expect(m.digest(), ref);
          expect(m.finish(), ref);
          // finish() resets to the keyed state.
          m.update(data);
          expect(m.finish(), ref);
          m.update([1, 2, 3]);
          m.reset();
          m.update(data);
          expect(m.digest(), ref);
          expect(c.digest(), ref);
        }
      }
    });
  });

  group('vs pointycastle (SHA-3 / SHAKE)', () {
    Uint8List pcSha3(int bits, Uint8List data) {
      final d = pc.SHA3Digest(bits);
      final out = Uint8List(d.digestSize);
      d.update(data, 0, data.length);
      d.doFinal(out, 0);
      return out;
    }

    Uint8List pcShake(int bits, Uint8List data, int outLen) {
      final d = pc.SHAKEDigest(bits);
      d.update(data, 0, data.length);
      final out = Uint8List(outLen);
      d.doFinalRange(out, 0, outLen);
      return out;
    }

    for (final bits in [224, 256, 384, 512]) {
      test('SHA3-$bits one-shot and incremental', () {
        final r = Random(bits);
        for (final n in _lengths) {
          final data = _rand(r, n);
          final ref = pcSha3(bits, data);
          expect(hashBytes('sha3_$bits', data), ref, reason: 'len=$n');
          if (n % 7 == 0) {
            final d = Sha3(bits);
            _feedChunked(r, d.update, data);
            expect(d.digest(), ref);
            expect(d.clone().finish(), ref);
            expect(d.finish(), ref);
          }
        }
      });
    }

    for (final bits in [128, 256]) {
      test('SHAKE$bits one-shot, many input/output lengths', () {
        final r = Random(bits + 1);
        for (final n in _lengths) {
          final data = _rand(r, n);
          final outLen = r.nextInt(700);
          final ref = pcShake(bits, data, outLen);
          final got =
              bits == 128 ? shake128(data, outLen) : shake256(data, outLen);
          expect(got, ref, reason: 'len=$n out=$outLen');
        }
      });

      test('SHAKE$bits incremental absorb and squeeze in pieces', () {
        final r = Random(bits + 2);
        for (var iter = 0; iter < 80; iter++) {
          final data = _rand(r, r.nextInt(2000));
          final outLen = r.nextInt(3000) + 1;
          final ref = pcShake(bits, data, outLen);
          final x = Shake(bits);
          _feedChunked(r, x.update, data);
          final snapshot = x.clone();
          final out = Uint8List(outLen);
          var pos = 0;
          while (pos < outLen) {
            final end = min(outLen, pos + r.nextInt(200) + 1);
            if (r.nextBool()) {
              x.readInto(out, pos, end);
            } else {
              out.setRange(pos, end, x.read(end - pos));
            }
            pos = end;
          }
          expect(out, ref, reason: 'iter=$iter');
          expect(snapshot.read(outLen), ref);
          expect(() => x.update([1]), throwsStateError);
        }
      });
    }
  });

  group('API', () {
    test('createDigest metadata', () {
      const meta = {
        'md5': (16, 64),
        'sha1': (20, 64),
        'sha224': (28, 64),
        'sha256': (32, 64),
        'sha384': (48, 128),
        'sha512': (64, 128),
        'sha3_224': (28, 144),
        'sha3_256': (32, 136),
        'sha3_384': (48, 104),
        'sha3_512': (64, 72),
      };
      meta.forEach((alg, m) {
        final d = createDigest(alg.toUpperCase());
        expect(d.algorithm, alg);
        expect(d.digestSize, m.$1);
        expect(d.blockSize, m.$2);
      });
      expect(() => createDigest('ripemd160'), throwsArgumentError);
      expect(tryCreateDigest('nope'), isNull);
    });

    test('HMAC-SHA3 matches generic construction', () {
      // No package:crypto reference; check RFC 2104 structure manually.
      final r = Random(3);
      final key = _rand(r, 200); // longer than the SHA3-256 rate (136)
      final data = _rand(r, 77);
      final k0 = Uint8List(136)..setAll(0, sha3_256(key));
      final ipad = Uint8List.fromList([for (final b in k0) b ^ 0x36]);
      final opad = Uint8List.fromList([for (final b in k0) b ^ 0x5c]);
      final inner = sha3_256([...ipad, ...data]);
      expect(hmac('sha3_256', key, data), sha3_256([...opad, ...inner]));
    });
  });
}
