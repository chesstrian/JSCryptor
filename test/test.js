(function () {
  const crypto = require('crypto');
  const fs = require('fs');
  const expect = require('chai').expect;
  const RNCryptor = require('../index');

  const specs = require('./spec');
  require('./title');

  const getSha1Sum = function (file) {
    const hashSum = crypto.createHash('sha1');
    hashSum.update(file);
    return hashSum.digest('hex');
  };

  const password = 'סיסמא';
  const plain_text = 'Some plain text';

  describe('RNCryptor: Supported version', function () {
    it('Decrypt encrypted text for version 3, expect be the same than plain text', function () {
      const encrypted = RNCryptor.Encrypt(plain_text, password);
      const decrypted = RNCryptor.Decrypt(encrypted, password);

      expect(plain_text).to.equal(decrypted.toString());
    });

    it('Decrypt encrypted image for version 3, expect be the same than plain text', function () {
      const image = fs.readFileSync('test/fixtures/Octocat.png');
      const encrypted = RNCryptor.Encrypt(image, password);
      const decrypted = RNCryptor.Decrypt(encrypted, password);

      expect(getSha1Sum(image)).to.equal(getSha1Sum(decrypted));
    });
  });

  for (const key in specs) {
    if (!specs.hasOwnProperty(key)) {
      continue;
    }

    describe('RNCryptor: ' + key.title() + ' spec', function (key) {
      return function () {
        if (key === 'kdf') {
          specs[key].forEach(function (spec) {
            it(spec.title, function () {
              const generated_key = RNCryptor.GenerateKey(Buffer.from(spec.password), Buffer.from(spec.salt_hex, 'hex'));

              expect(spec.key_hex).to.equal(generated_key.toString('hex'));
            });
          });
        } else if (key === 'key') {
          specs[key].forEach(function (spec) {
            it(spec.title, function () {
              const cipher_text = RNCryptor.EncryptWithArbitraryKeys(
                Buffer.from(spec.plaintext_hex, 'hex'),
                Buffer.from(spec.enc_key_hex, 'hex'),
                Buffer.from(spec.hmac_key_hex, 'hex'),
                Buffer.from(spec.iv_hex, 'hex'),
                parseInt(spec.version)
              );

              expect(spec.ciphertext_hex).to.equal(Buffer.from(cipher_text, 'base64').toString('hex'));
            });
          });
        } else if (key === 'password') {
          specs[key].forEach(function (spec) {
            it(spec.title, function () {
              const cipher_text = RNCryptor.EncryptWithArbitrarySalts(
                Buffer.from(spec.plaintext_hex, 'hex'),
                Buffer.from(spec.password),
                Buffer.from(spec.enc_salt_hex, 'hex'),
                Buffer.from(spec.hmac_salt_hex, 'hex'),
                Buffer.from(spec.iv_hex, 'hex'),
                parseInt(spec.version)
              );

              expect(spec.ciphertext_hex).to.equal(Buffer.from(cipher_text, 'base64').toString('hex'));
            });
          });
        }
      };
    }(key));
  }
}).call(undefined, undefined);
