import 'package:test/test.dart';
import 'package:tlslite/src/utils/keyfactory.dart';
import 'package:tlslite/src/utils/rsakey.dart';

void main() {
  group('parsePEMKey (python impl)', () {
    test('parses PKCS#8 without newlines', () {
      final key = parsePEMKey(
        _pkcs8WithNewlines.replaceAll('\n', ''),
        private: true,
        implementations: const ['python'],
      );
      final rsaKey = _expectRsaKey(key);
      expect(rsaKey.bitLength, equals(1024));
      expect(rsaKey.hasPrivateKey(), isTrue);
    });

    test('parses PKCS#8 with newlines', () {
      final key = parsePEMKey(
        _pkcs8WithNewlines,
        private: true,
        implementations: const ['python'],
      );
      final rsaKey = _expectRsaKey(key);
      expect(rsaKey.bitLength, equals(1024));
      expect(rsaKey.hasPrivateKey(), isTrue);
    });

    test('parses PKCS#1 without newlines', () {
      final key = parsePEMKey(
        _pkcs1WithNewlines.replaceAll('\n', ''),
        private: true,
        implementations: const ['python'],
      );
      final rsaKey = _expectRsaKey(key);
      expect(rsaKey.bitLength, equals(1024));
      expect(rsaKey.hasPrivateKey(), isTrue);
    });

    test('parses PKCS#1 with newlines', () {
      final key = parsePEMKey(
        _pkcs1WithNewlines,
        private: true,
        implementations: const ['python'],
      );
      final rsaKey = _expectRsaKey(key);
      expect(rsaKey.bitLength, equals(1024));
      expect(rsaKey.hasPrivateKey(), isTrue);
    });

    test('parses RSA-PSS private key', () {
      final key = parsePEMKey(
        _rsaPssPrivateKey,
        private: true,
        implementations: const ['python'],
      );
      final rsaKey = _expectRsaKey(key);
      expect(rsaKey.keyType, equals('rsa-pss'));
      expect(rsaKey.bitLength, equals(1024));
      expect(rsaKey.hasPrivateKey(), isTrue);
    });

    test('public flag strips private component', () {
      final publicKey = parsePEMKey(
        _pkcs8WithNewlines,
        public: true,
        implementations: const ['python'],
      );
      final rsaKey = _expectRsaKey(publicKey);
      expect(rsaKey.hasPrivateKey(), isFalse);
      expect(rsaKey.bitLength, equals(1024));
    });

    test('parses encrypted PKCS#8 when password callback provided', () {
      final key = _expectRsaKey(parsePrivateKey(_pkcs8WithNewlines));
      final encryptedPem = key.write(password: 'hunter2');
      final parsed = parsePEMKey(
        encryptedPem,
        private: true,
        passwordCallback: () => 'hunter2',
      );
      final rsaKey = _expectRsaKey(parsed);
      expect(rsaKey.hasPrivateKey(), isTrue);
      expect(rsaKey.privateExponent, equals(key.privateExponent));
    });

    test('throws without password callback for encrypted PKCS#8', () {
      final key = _expectRsaKey(parsePrivateKey(_pkcs8WithNewlines));
      final encryptedPem = key.write(password: 'hunter2');
      expect(
        () => parsePEMKey(encryptedPem, private: true),
        throwsStateError,
      );
    });

    test('throws when password callback returns wrong password', () {
      final key = _expectRsaKey(parsePrivateKey(_pkcs8WithNewlines));
      final encryptedPem = key.write(password: 'hunter2');
      expect(
        () => parsePEMKey(
          encryptedPem,
          private: true,
          passwordCallback: () => 'wrong',
        ),
        throwsA(isA<FormatException>()),
      );
    });
  });
}

RSAKey _expectRsaKey(Object? key) {
  expect(key, isA<RSAKey>());
  return key as RSAKey;
}

const _pkcs8WithNewlines = '-----BEGIN PRIVATE KEY-----\n'
    'MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANEJBHmpEslfyzLU\n'
    '3gEXUbV+aXW81blLqjiHc95YO2DskSf6Mi0z81l6Ssa//7eBT0L2LEiYlTpT5PPe\n'
    'RTburDRf7iUMkBnxVmCpBOn8xYn0OrPZLLLJBZS9Q1SP3Q/2Z+7IM7mtj9UsiyR0\n'
    'E07NTLTG9e9P319hAT5A8/tpGCjdAgMBAAECgYBVItsTwezI358fANu6jgjVZrsF\n'
    'HPffFBYsF971O/JTM4abRaeSCYqfctNpx2EbGCt0FldK6fo9W1XwjSKbkPHJVo12\n'
    'Lfeyn48iRlTfzp/VVSpydieaCyexRAQElC59RmaA0z5t9H5F+WLgx7DyVDSyitn5\n'
    '3b/l+wzSDzRCGLkzcQJBAO9d4LKtzLS78dkU2MiWjJdoAi9q9notzqB/OcJJ8dzl\n'
    'jCmU5jt0hanwVFElzJeQDfvSXl0nQRePkbG51X1BDjcCQQDfj5HGNGTgNPtmj61s\n'
    'z8WSiLuOHX/SEWRTk0MfB4l4f+Ymx6Ie2wco5w8a0QYEGpPYo09ZXPgWPX0uJSaa\n'
    'NZeLAkEAgGzj07n/7LAx0ACpVuW/RLSfB4Xh/Cd7hwz7lkxKIfRewSiMZjXcSRMS\n'
    'if83x9GYTxXNXzliaRu0VaCY9Hzk/QJBAKx6VZs3XQRlm/f6rXAftGxjNWBlffIS\n'
    'HPclzEkqRXNEKcqNhpSLozB5Y3vq+9s6rgobpOJrCbQO6H8rhma/JhUCQGmkTlFF\n'
    'CpeK/UoX1sCtwAke8ubS+cc+l/XIhCvltbqeMG4vipzGVoolUZFdPvIW2PZ+PSC/\n'
    'f3XiNjay5aqnxck=\n'
    '-----END PRIVATE KEY-----\n';

const _pkcs1WithNewlines = '-----BEGIN RSA PRIVATE KEY-----\n'
    'MIICXAIBAAKBgQCnBW08FYymHDwA+Vug5QWH2g0nX2EnTnzdyvaZ/mE1pCTxV+Fp\n'
    'j0glrRIoPJPP+rZTcl/cqm7FSD+n2QDWHrg4h8xFPC7uPyfrbd/u6hTO3edu0los\n'
    'tKkq93ZiM/kmfHIS57/nOiG9ETySx4TP4ca6dhNoIAU5uMQDHjhgSXSU4wIDAQAB\n'
    'AoGAOB2PpOdMmSbVVjJxga5Q3GL7lmXqW214cIBXuEeKW55ptxiiqHe2csoiVph7\n'
    'xR3kEkdUQ+yTSP9MO9Wh/U7W78RTKM21tRn2uwzVD4p0whVK/WCa0zsSu41VQ23l\n'
    'wxN3Byrxw6jTTKD3gSLJc/4kGaduXgc/1IHCtmVaD9L2XJkCQQDVjqaDuQhPqzGI\n'
    'kHZ77PARFLf3q+nVIFSIf1m/wxLQEj1HZ9PuyHNm0USQYswwDnh9g7F25YylWex+\n'
    'yiefS0/fAkEAyDcekKtYudtgOhyN7tgSlUiHEyLCRo5IeazKQ0wNCDWfok9HYpEo\n'
    'mOuE+NIQEcCJu+sRXK6rykJQGkHgYsALfQJAN5aJK3Jngm1aWGTaIonbN2cAN/zM\n'
    'wghHWLxlfS/m3rhQsRyKovYUa+f/A+JjqgKqRGmaMQuxX30XvS0bwTAWWwJAQl3j\n'
    'B9mEg7cwYpLsiWueXVW5UKKI+5JWe97G/R/MghgkXk0hQI8VgfswDLq1EO1duqjl\n'
    'DG/qChWJL+r+Uj2OkQJBAK22WDZnIa52dm6G2dC+pM7TC10p7pwOS+G4YsA92Jd2\n'
    'rBjtgPGNR6tCjWMh0+2AUF5lTbXAPqECeV6MIvJXGpg=\n'
    '-----END RSA PRIVATE KEY-----\n';

const _rsaPssPrivateKey = '-----BEGIN PRIVATE KEY-----'
    'MIICdQIBADALBgkqhkiG9w0BAQoEggJhMIICXQIBAAKBgQCn8gxBHPCDZIWDXOuJ'
    'jDv2/sLFrtnrwrHVaHRKvJQ4La5X6juRb6SoStMmhgfBiQHqLN7CphcjqhU5G5u1'
    '3GRWd8PsauSQWfAVeT7AO99PwlTsR3oigN4HfaBkEXpDcUdxw0CapjQFEeVD14Ds'
    'ylqGxuX63FZAoY7fSNW9xInqOQIDAQABAoGAEk1YdIgY1djQi/5GVNkJd+NPioeB'
    'jCXNh3o4oiRm6rBfvYjzMOg/w29UD3Cvy7GImeKF7CR5hRN1+KE/mNQJww1cPe2X'
    'DZ7VlWqg4zuXFxOjL4qA+crk4Th7KQhOWmjbB4dtRAa/YJSpQR0a0NMvKPXhvwxy'
    'Mj+lLgCycy14lzkCQQDRQlseMlc3VudfNo2ei2PkuOG+za4PoBEumsC7dg2+Sxvv'
    'JkXEGdJ9DZGxqZTI4Q4OtFZ7PTwAvHgmvyyI03E3AkEAzXVVlsl6hOl2Wy+hpKDk'
    'GOL4er9eubHzP70bSkgSvlUkxvSSP4ixnLv14XPqCRLzoMxQEQxymq1aO87iGc/4'
    'DwJBAIM2fngSzMlwfqgfRvHxKXQT0cmYoto9XkjA1LU3MyrtYdi1QO3T2z56sa6b'
    'TSYgqHXj8o5YOTWk+BojqcMqAkUCQBSg1zsQd5CosA1vttcEoGIvR6trU2Npjnaz'
    '0e2fVuJtQggHvjdKzipiZMmCDdljYbqfSNqtWURWa1zd5K2ax9kCQQC7Eg+ktzi3'
    '1wAXDgXMdW+TsDPBHrRqRGzFXKe83e05/nVc8EwiS0mYdkpblm+uzUqiSsa20Guo'
    'Xf3/znMC6LAS'
    '-----END PRIVATE KEY-----';
