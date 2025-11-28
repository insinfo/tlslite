import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:tlslite/src/utils/cryptomath.dart';
import 'package:tlslite/src/utils/rsakey.dart';

void main() {
	late PythonRSAKey key;

	setUp(() {
		key = _buildSampleKey();
		resetRsaRandomBytes();
	});

	tearDown(resetRsaRandomBytes);

	test('MGF1 matches python vector', () {
		final mask = key.MGF1(_hexBytes(_mgfSeedHex), 107, 'sha1');
		expect(mask, _hexBytes(_mgfExpectedHex));
	});

	test('EMSA_PSS_encode matches python vector with patched RNG', () {
		final salt = _hexBytes(_pssSaltHex);
		var randomCalled = false;
		overrideRsaRandomBytes((length) {
			randomCalled = true;
			expect(length, salt.length);
			return Uint8List.fromList(salt);
		});
		final mHash = secureHash(_pythonMessageForPss(), 'sha1');
		final em = key.EMSA_PSS_encode(mHash, 1023, 'sha1', saltLen: 10);
		expect(randomCalled, isTrue, reason: 'salt RNG override not used');
		expect(em, _hexBytes(_pssEncodedHex));
	});

	test('EMSA_PSS_verify accepts known vector', () {
		final mHash = secureHash(_pythonMessageForPss(), 'sha1');
		expect(
			key.EMSA_PSS_verify(mHash, _hexBytes(_pssEncodedHex), 1023, 'sha1',
					saltLen: 10),
			isTrue,
		);
	});

	test('hashAndSign PKCS1 SHA1 matches vector', () {
		final signature = key.hashAndSign(
			_pythonMessage(),
			rsaScheme: 'PKCS1',
			hAlg: 'sha1',
		);
		expect(signature, _hexBytes(_pkcs1Sha1Hex));
	});

	test('hashAndVerify PKCS1 SHA512 succeeds', () {
		final message = _pythonMessage();
		final signature = _hexBytes(_pkcs1Sha512Hex);
		expect(
			key.hashAndVerify(signature, message, rsaScheme: 'PKCS1', hAlg: 'sha512'),
			isTrue,
		);
	});

	test('encrypt/decrypt roundtrip', () {
		final plaintext = Uint8List.fromList('tlslite dart'.codeUnits);
		final ciphertext = key.encrypt(plaintext);
		expect(ciphertext.length, numBytes(key.n));
		final decrypted = key.decrypt(ciphertext);
		expect(decrypted, plaintext);
	});
}

PythonRSAKey _buildSampleKey() {
	final n = _hexBigInt(_nHex);
	final e = _hexBigInt(_eHex);
	final d = _hexBigInt(_dHex);
	final p = _hexBigInt(_pHex);
	final q = _hexBigInt(_qHex);
	return PythonRSAKey(n: n, e: e, d: d, p: p, q: q);
}

Uint8List _pythonMessage() => _hexBytes(_pkcs1MessageHex);

Uint8List _pythonMessageForPss() => _hexBytes(_pssMessageHex);

Uint8List _hexBytes(String hex) {
	final cleaned = hex.replaceAll(RegExp(r'\s+'), '');
	if (cleaned.length.isOdd) {
		throw FormatException('hex string must have even length');
	}
	final result = Uint8List(cleaned.length ~/ 2);
	for (var i = 0; i < cleaned.length; i += 2) {
		result[i ~/ 2] = int.parse(cleaned.substring(i, i + 2), radix: 16);
	}
	return result;
}

BigInt _hexBigInt(String source) {
	final normalized = source.replaceAll(RegExp(r'\s+'), '');
	return BigInt.parse(normalized, radix: 16);
}

const _nHex =
		'a8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802aafbadbf2564dd55095'
		'6abb54f8b1c917844e5f36195d1088c600e07cada5c080ede679f50b3de32cf4026e514542495c54b19'
		'03768791aae9e36f082cd38e941ada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301'
		'd45176b5';

const _eHex =
		'000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
		'000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
		'000000000000000000000000000000000000000000000000000000000000000000000000000000000003';

const _dHex =
		'1c23c1cce034ba598f8fd2b7af37f1d30b090f7362aee68e5187adae49b9955c729f24a863b7a38d6e3c'
		'748e2972f6d940b7ba89043a2d6c2100256a1cf0f56a8cd35fc6ee205244876642f6f9c3820a3d9d2c89'
		'21df7d82aaadcaf2d7334d398931ddbba553190b3a416099f3aa07fd5b26214645a828419e122cfb857a'
		'd73b';

const _pHex =
		'c107a2fe924b76e206cb9bc4af2ab7008547c00846bf6d0680b3eac3ebcbd0c7fd7a54c2b9899b08f80cd'
		'e1d3691eaaa2816b1eb11822d6be7beaf4e30977c49';

const _qHex =
		'dfea984ce4307eafc0d140c2bb82861e5dbac4f8567cbc981d70440dd639492079031486315e305eb83e5'
		'91c4a2e96064966f7c894c3ca351925b5ce82d8ef0d';

const _mgfSeedHex = 'ad8fd1f7f97f67725253ce7d189835b3';

const _mgfExpectedHex =
		'b8301273bbd96ace26550814b20730c7c8a8a0c1c3f3d431adbee81d4e94f6737802edfb0b0b85c54eff04'
		'7aec13864f15e87caec61c0dcdecf4b1b524f217fff6c2f5d28ad298a8b7e03babe0e950d9ea86b3eb29a3'
		'98b465b5500714f13fa869b7c6941c391f583e40e3';

const _pssMessageHex =
		'c7f5270fca72725f9bd19f519a8d7cca3cc5c079024029f3bae510f9b02140fe238908e4f6c18f07a89c687c8684'
		'669b1f1db2baf9251a3c829faccb493084e16ec9e28d58868074a5d6221667dd6e528d16fe2c9f3db4cfaf6c4dce8'
		'c8439af38ceaaaa9ce2ecae7bc8f4a5a55e3bf96df9cd575c4f9cb327951b8cdfe4087168';

const _pssSaltHex = '11223344555432167890';

const _pssEncodedHex =
		'48e1169c28ca5c9ee0b75d46fc4aa3976e43eb99dd7ad1c769bdc7f8439241e97e5f6bf83cf66c791f53e'
		'c516189ff2a6a94a5a52b1a40941ff7151a129eb6b881324f7b0910591012684751d7ceb04cf91a59123d97f0cfde97'
		'85c74b77857240d294a0e03915ac7e63767082ce7297c8d326b57c6ec1257b05669f4fb9edbc';

const _pkcs1MessageHex =
		'd73829497cddbe41b705faac50e7899fdb5a38bf3a459e536357029e64f8796ba47f4fe96ba5a8b9a4396746e2164f5'
		'5a25368ddd0b9a5188c7ac3da2d1f742286c3bdee697f9d546a25efcfe53191d743fcc6b47833d993d08804daeca78'
		'fb9076c3c017f53e33a90305af06220974d46bf19ed3c9b84edbae98b45a8771258';

const _pkcs1Sha1Hex =
		'175015bda50abe0fa7d39a8353885ca01be3a7e7fcc55045744111362ee1914473a48dc537d956294b9e20a1ef661d'
		'58537acdc8de908fa050630fcc272e6d001045e6fdeed2d10531c8603334c2e8db39e73e6d9665ee1343f9e4198302'
		'd2201b44e8e8d06b3ef49cee6197582163a8490089ca654c0012fce1ba6511089750';

const _pkcs1Sha512Hex =
		'8b57a6f91606ba4813b83536581eb15d72875dcbb0a514b4c03b6df8f202fa8556e4002122bedaf26eaa107ece4860'
		'752379ec8baa64f40098be92a4214b69e98b24ae1cc4d2f457cff4f405a82ef94c5f8dfaadd3078d7a9224887db86c'
		'3218bf53c9779ed09895b2cfb84f1fad2e5b1f8e4b209c5785b9ce332cd41356c171';
