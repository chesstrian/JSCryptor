(function() {
  var crypto = require('crypto');
  var pbkdf2 = require('./pbkdf2_sha1');
  var base64_decode = require('./base64_decode');

  var MCrypt = require('mcrypt').MCrypt;

  var RNCryptor = {};

  var _settings = {};

  var _configureSettings = function(version) {
    var settings = {
      algorithm: 'rijndael-128',
      salt_length: 8,
      iv_length: 16,
      hmac: {
        length: 32
      }
    };

    switch(version) {
      case 3:
        settings.mode = 'cbc';
        settings.options = 1;
        settings.hmac.includes_header = true;
        settings.hmac.algorithm = 'sha256';
        settings.hmac.includes_padding = false;
        settings.truncatesMultibytePasswords = false;
        break;
      default:
        throw "Unsupported schema version " + version
    }

    _settings = settings;
  };

  var _unpackEncryptedBase64Data = function(b64str) {
    var binary_data = base64_decode(b64str);

    var components = {
      headers: _parseHeaders(binary_data),
      hmac: binary_data.substr(-_settings.hmac.length)
    };

    var header_length = components.headers.length;
    var cipher_text_length = binary_data.length - header_length - components.hmac.length;

    components.cipher_text = binary_data.substr(header_length, cipher_text_length);

    return components;
  };

  var _parseHeaders = function(bin_data) {
    var offset = 0;

    var version_char = bin_data[0];
    offset += version_char.length;

    _configureSettings(version_char.charCodeAt());

    var options_char = bin_data[1];
    offset += options_char.length;

    var encryption_salt = bin_data.substr(offset, _settings.salt_length);
    offset += encryption_salt.length;

    var hmac_salt = bin_data.substr(offset, _settings.salt_length);
    offset += hmac_salt.length;

    var iv = bin_data.substr(offset, _settings.iv_length);
    offset += iv.length;

    return {
      version: version_char,
      options: options_char,
      encryption_salt: encryption_salt,
      hmac_salt: hmac_salt,
      iv: iv,
      length: offset
    };
  };

  var _hmac_is_valid = function(components, password) {
    var hmac_key = _generate_key(components.headers.hmac_salt, password);
    return components.hmac == _generate_hmac(components, hmac_key);
  };

  var _generate_key = function (salt, password) {
    return pbkdf2(password, salt, 10000, 32);
  };

  var _generate_hmac = function(components, hmac_key) {
    var hmac_message = '';

    if (_settings.hmac.includes_header) {
      hmac_message += components.headers.version;
      hmac_message += components.headers.options;
      hmac_message += components.headers.encryption_salt != null ? components.headers.encryption_salt : '';
      hmac_message += components.headers.hmac_salt != null ? components.headers.hmac_salt : '';
      hmac_message += components.headers.iv;
    }

    hmac_message += components.cipher_text;

    return _hmac_sha256(hmac_key, hmac_message);
  };

  var _hmac_sha256 = function(password, salt) {
    return crypto.createHmac("sha256", password).update(salt).digest('binary');
  };

  var _strip_pkcs7_padding = function(plain_text) {
    var pad_length = plain_text.charCodeAt(plain_text.length - 1);
    return plain_text.substr(0, plain_text.length - pad_length);
  };

  RNCryptor.Decrypt = function(b64str, password) {
    var components = _unpackEncryptedBase64Data(b64str);

    if (!_hmac_is_valid(components, password)) {
      return;
    }

    var key = _generate_key(components.headers.encryption_salt, password);
    var decrypter = new MCrypt(_settings.algorithm, _settings.mode);
    decrypter.open(key, components.headers.iv);

    var padded_plain_text = decrypter.decrypt(new Buffer(components.cipher_text, 'binary')).toString();
    return _strip_pkcs7_padding(padded_plain_text);
  };

  module.exports = RNCryptor;
})();
