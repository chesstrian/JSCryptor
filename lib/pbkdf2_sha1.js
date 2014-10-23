(function() {
  var pack = require('./pack');
  var crypto = require('crypto');

  var hmac_sha1 = function(password, salt) {
    return crypto.createHmac("sha1", password).update(salt).digest('binary');
  };

  String.prototype.xor = function(other) {
    var xor = "";
    for (var i = 0; i < this.length && i < other.length; ++i) {
      xor += String.fromCharCode(this.charCodeAt(i) ^ other.charCodeAt(i));
    }
    return xor;
  };

  var pbkdf2 = function(password, salt, count, key_length) {
    var last, xorsum;

    var block_count = Math.ceil(key_length / 20);

    var output = '';
    for(var i = 1; i <= block_count; i++) {
      last = salt + pack('N', i);
      last = xorsum = hmac_sha1(password, last);

      for(var j = 1; j < count; j++) {
        xorsum = xorsum.xor(last = hmac_sha1(password, last));
      }

      output += xorsum;
    }

    return output.substr(0, key_length);
  };

  module.exports = pbkdf2;
})();
