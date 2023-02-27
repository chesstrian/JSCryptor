(function () {
  const crypto = require('crypto');

  let _settings = {};

  const _configure_settings = function (version) {
    const settings = {
      algorithm: 'aes-256-cbc',
      salt_length: 8,
      iv_length: 16,
      pbkdf2: {
        iterations: 10000,
        key_length: 32
      },
      hmac: {
        length: 32
      }
    };

    switch (version) {
      case 3:
        settings.options = 1;
        settings.hmac.includes_header = true;
        settings.hmac.algorithm = 'sha256';
        break;
      default:
        throw `Unsupported schema version ${version}`
    }

    _settings = settings;
  };

  const _unpack_encrypted_base64_data = function (b64str) {
    const data = Buffer.from(b64str, 'base64');

    const components = {
      headers: _parseHeaders(data),
      hmac: data.slice(data.length - _settings.hmac.length)
    };

    const header_length = components.headers.length;
    const cipher_text_length = data.length - header_length - components.hmac.length;

    components.cipher_text = data.slice(header_length, header_length + cipher_text_length);

    return components;
  };

  const _parseHeaders = function (buffer_data) {
    let offset = 0;

    const version_char = buffer_data.slice(offset, offset + 1);
    offset += version_char.length;

    _configure_settings(version_char.toString('binary').charCodeAt());

    const options_char = buffer_data.slice(offset, offset + 1);
    offset += options_char.length;

    const encryption_salt = buffer_data.slice(offset, offset + _settings.salt_length);
    offset += encryption_salt.length;

    const hmac_salt = buffer_data.slice(offset, offset + _settings.salt_length);
    offset += hmac_salt.length;

    const iv = buffer_data.slice(offset, offset + _settings.iv_length);
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

  const _hmac_is_valid = function (components, password) {
    const hmac_key = _generate_key(password, components.headers.hmac_salt);

    // For 0.11+ we can use Buffer.compare
    return components.hmac.toString('hex') === _generate_hmac(components, hmac_key).toString('hex');
  };

  const _generate_key = function (password, salt) {
    return crypto.pbkdf2Sync(password, salt, _settings.pbkdf2.iterations, _settings.pbkdf2.key_length, 'SHA1');
  };

  const _generate_hmac = function (components, hmac_key) {
    let hmac_message = Buffer.from('');

    if (_settings.hmac.includes_header) {
      hmac_message = Buffer.concat([
        hmac_message,
        components.headers.version,
        components.headers.options,
        components.headers.encryption_salt || Buffer.from(''),
        components.headers.hmac_salt || Buffer.from(''),
        components.headers.iv
      ]);
    }

    hmac_message = Buffer.concat([hmac_message, components.cipher_text]);

    return crypto.createHmac(_settings.hmac.algorithm, hmac_key).update(hmac_message).digest();
  };

  const _generate_initialized_components = function (version) {
    return {
      headers: {
        version: Buffer.from(String.fromCharCode(version)),
        options: Buffer.from(String.fromCharCode(_settings.options))
      }
    };
  };

  const _generate_salt = function () {
    return _generate_iv(_settings.salt_length);
  };

  const _generate_iv = function (block_size) {
    return crypto.randomBytes(block_size)
  };

  const _encrypt = function (plain_text, components, encryption_key, hmac_key) {
    const cipher = crypto.createCipheriv(_settings.algorithm, encryption_key, components.headers.iv)
    components.cipher_text = Buffer.concat([cipher.update(plain_text), cipher.final()])

    const data = Buffer.concat([
      components.headers.version,
      components.headers.options,
      components.headers.encryption_salt || Buffer.from(''),
      components.headers.hmac_salt || Buffer.from(''),
      components.headers.iv,
      components.cipher_text
    ]);

    const hmac = _generate_hmac(components, hmac_key);

    return Buffer.concat([data, hmac]).toString('base64');
  };

  const RNCryptor = {};

  RNCryptor.GenerateKey = _generate_key;

  RNCryptor.Encrypt = function (plain_text, password, version = 3) {
    Buffer.isBuffer(plain_text) || (plain_text = Buffer.from(plain_text, 'binary'));
    Buffer.isBuffer(password) || (password = Buffer.from(password, 'binary'));

    _configure_settings(version);

    const components = _generate_initialized_components(version);
    components.headers.encryption_salt = _generate_salt();
    components.headers.hmac_salt = _generate_salt();
    components.headers.iv = _generate_iv(_settings.iv_length);

    const encryption_key = _generate_key(password, components.headers.encryption_salt);
    const hmac_key = _generate_key(password, components.headers.hmac_salt);

    return _encrypt(plain_text, components, encryption_key, hmac_key);
  };

  RNCryptor.EncryptWithArbitrarySalts = function (plain_text, password, encryption_salt, hmac_salt, iv, version = 3) {
    Buffer.isBuffer(plain_text) || (plain_text = Buffer.from(plain_text, 'binary'));
    Buffer.isBuffer(password) || (password = Buffer.from(password));
    Buffer.isBuffer(encryption_salt) || (encryption_salt = Buffer.from(encryption_salt, 'binary'));
    Buffer.isBuffer(hmac_salt) || (hmac_salt = Buffer.from(hmac_salt, 'binary'));
    Buffer.isBuffer(iv) || (iv = Buffer.from(iv, 'binary'));

    _configure_settings(version);

    const components = _generate_initialized_components(version);
    components.headers.encryption_salt = encryption_salt;
    components.headers.hmac_salt = hmac_salt;
    components.headers.iv = iv;

    const encryption_key = _generate_key(password, encryption_salt);
    const hmac_key = _generate_key(password, hmac_salt);

    return _encrypt(plain_text, components, encryption_key, hmac_key);
  };

  RNCryptor.EncryptWithArbitraryKeys = function (plain_text, encryption_key, hmac_key, iv, version = 3) {
    Buffer.isBuffer(plain_text) || (plain_text = Buffer.from(plain_text, 'binary'));
    Buffer.isBuffer(encryption_key) || (encryption_key = Buffer.from(encryption_key, 'binary'));
    Buffer.isBuffer(hmac_key) || (hmac_key = Buffer.from(hmac_key, 'binary'));
    Buffer.isBuffer(iv) || (iv = Buffer.from(iv, 'binary'));

    _settings.options = 0;

    const components = _generate_initialized_components(version);
    components.headers.iv = iv;

    return _encrypt(plain_text, components, encryption_key, hmac_key);
  };

  RNCryptor.Decrypt = function (b64str, password) {
    const components = _unpack_encrypted_base64_data(b64str);

    Buffer.isBuffer(password) || (password = Buffer.from(password, 'binary'));

    if (!_hmac_is_valid(components, password)) {
      return;
    }

    const key = _generate_key(password, components.headers.encryption_salt);
    const decipher = crypto.createDecipheriv(_settings.algorithm, key, components.headers.iv)
    return Buffer.concat([decipher.update(components.cipher_text), decipher.final()]).toString()
  };

  module.exports = RNCryptor;
})();
