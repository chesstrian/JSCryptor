(function() {
  var crypto = require('crypto');
  var MCrypt = require('mcrypt').MCrypt;

  var RNCryptor = {
    supported_versions: [2, 3]
  };

  var _settings = {};

  var _configureSettings = function(version) {
    var settings = {
      algorithm: 'rijndael-128',
      salt_length: 8,
      iv_length: 16,
      pbkdf2: {
        prf: 'sha1',
        iterations: 10000,
        key_length: 32
      },
      hmac: {
        length: 32
      }
    };

    switch(version) {
      case 2:
        settings.mode = 'cbc';
        settings.options = 1;
        settings.hmac.includes_header = true;
        settings.hmac.algorithm = 'sha256';
        settings.hmac.includes_padding = false;
        settings.truncates_multibyte_passwords = true;
        break;
      case 3:
        settings.mode = 'cbc';
        settings.options = 1;
        settings.hmac.includes_header = true;
        settings.hmac.algorithm = 'sha256';
        settings.hmac.includes_padding = false;
        settings.truncates_multibyte_passwords = false;
        break;
      default:
        var err = "Unsupported schema version " + version;
        throw err
    }

    _settings = settings;
  };

  var _unpackEncryptedBase64Data = function(b64str) {
    var binary_data = new Buffer(b64str, 'base64').toString('binary');

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
    var hmac_key = _generate_key(password, components.headers.hmac_salt);
    return components.hmac == _generate_hmac(components, hmac_key);
  };

  var _generate_key = function (password, salt) {
    if (_settings.truncates_multibyte_passwords) {
      password = new Buffer(new Buffer(password, 'utf-8').toString('hex', 0, password.length), 'hex');
    }
    // Applies pseudorandom function HMAC-SHA1 by default
    var pbkdf2_key = crypto.pbkdf2Sync(password, salt, _settings.pbkdf2.iterations, _settings.pbkdf2.key_length);
    return pbkdf2_key.toString('binary');
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

    return crypto.createHmac(_settings.hmac.algorithm, hmac_key).update(hmac_message).digest('binary');
  };

  var _strip_pkcs7_padding = function(plain_text) {
    var pad_length = plain_text.charCodeAt(plain_text.length - 1);
    return plain_text.substr(0, plain_text.length - pad_length);
  };

  var _generate_initialized_components = function(version) {
    return {
      headers: {
        version: String.fromCharCode(version),
        options: String.fromCharCode(_settings.options)
      }
    };
  };

  var _generate_salt = function() {
    return _generate_iv(_settings.salt_length);
  };

  var _generate_iv = function (block_size) {
    var mcrypt = new MCrypt(_settings.algorithm, _settings.mode);
    var iv = mcrypt.generateIv();
    return iv.toString('binary', 0, block_size);
  };

  var _encrypt = function(plain_text, components, encryption_key, hmac_key) {
    var padded_plain_text = _add_pkcs7_padding(plain_text, components.headers.iv.length);
    var mcrypt = new MCrypt(_settings.algorithm, _settings.mode);
    mcrypt.open(encryption_key, components.headers.iv);
    components.cipher_text = mcrypt.encrypt(padded_plain_text).toString('binary');

    var binary_data = '';
    binary_data += components.headers.version;
    binary_data += components.headers.options;
    binary_data += components.headers.encryption_salt != null ? components.headers.encryption_salt : '';
    binary_data += components.headers.hmac_salt != null ? components.headers.hmac_salt : '';
    binary_data += components.headers.iv;
    binary_data += components.cipher_text;

    var hmac = _generate_hmac(components, hmac_key);

    return new Buffer(binary_data + hmac, 'binary').toString('base64');
  };

  var _add_pkcs7_padding = function (plain_text, block_size) {
    var pad_size = block_size - (plain_text.length % block_size);
    return plain_text + new Array(pad_size + 1).join(String.fromCharCode(pad_size));
  };

  RNCryptor.Encrypt = function(plain_text, password, version) {
    version = version || 3;

    _configureSettings(version);

    var components = _generate_initialized_components(version);
    components.headers.encryption_salt = _generate_salt();
    components.headers.hmac_salt = _generate_salt();
    components.headers.iv = _generate_iv(_settings.iv_length);

    var encryption_key = _generate_key(password, components.headers.encryption_salt);
    var hmac_key = _generate_key(password, components.headers.hmac_salt);

    return _encrypt(plain_text, components, encryption_key, hmac_key);
  };

  RNCryptor.Decrypt = function(b64str, password) {
    var components = _unpackEncryptedBase64Data(b64str);

    if (!_hmac_is_valid(components, password)) {
      return;
    }

    var key = _generate_key(password, components.headers.encryption_salt);
    var mcrypt = new MCrypt(_settings.algorithm, _settings.mode);
    mcrypt.open(key, components.headers.iv);

    var padded_plain_text = mcrypt.decrypt(new Buffer(components.cipher_text, 'binary')).toString();
    return _strip_pkcs7_padding(padded_plain_text);
  };

  module.exports = RNCryptor;
})();
