(function() {
  var expect = require('chai').expect;
  var RNCryptor = require('../index');

  var password = 'סיסמא';
  var plain_text = 'Some plain text';

  var specs = require('./spec');
  var title = require('./title');

  describe('RNCryptor: Supported version', function() {
    it('Decrypt encrypted text for version 3, expect be the same than plain text', function() {
      var encrypted = RNCryptor.Encrypt(plain_text, password);
      var decrypted = RNCryptor.Decrypt(encrypted, password);

      expect(plain_text).to.equal(decrypted.toString());
    });
  });

  for(var key in specs) {
    if (!specs.hasOwnProperty(key)) {
      continue;
    }

    describe('RNCryptor: ' + key.title() + ' spec', function(key) {
      return function() {
        if (key === 'kdf') {
          specs[key].forEach(function(spec) {
            it(spec.title, function() {
              var generated_key = RNCryptor.GenerateKey(Buffer.from(spec.password), Buffer.from(spec.salt_hex, 'hex'));

              expect(spec.key_hex).to.equal(generated_key.toString('hex'));
            });
          });
        } else if (key === 'key') {
          specs[key].forEach(function(spec) {
            it(spec.title, function() {
              var cipher_text = RNCryptor.EncryptWithArbitraryKeys(
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
          specs[key].forEach(function(spec) {
            it(spec.title, function() {
              var cipher_text = RNCryptor.EncryptWithArbitrarySalts(
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
}).call();
