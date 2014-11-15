(function() {
  var expect = require('chai').expect;
  var RNCryptor = require('../index');

  var password = 'סיסמא';
  var plain_text = 'Some plain text';

  describe('RNCryptor: Supported versions', function() {
    RNCryptor.supported_versions.forEach(function(version) {
      it('Decrypt encrypted text for version ' + version + ', expect be the same than plain text', function() {
        var encrypted = RNCryptor.Encrypt(plain_text, password, version);
        var decrypted = RNCryptor.Decrypt(encrypted, password);

        expect(plain_text).to.equal(decrypted);
      });
    });
  });
}).call();
