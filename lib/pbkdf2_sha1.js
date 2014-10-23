(function() {
  var pack = require('./pack');
  var crypto = require('crypto');

  var hmac_sha1 = function(password, salt) {
    var hmac = crypto.createHmac('sha1', password);
    hmac.setEncoding('binary');
    hmac.write(salt);
    hmac.end();

    return hmac.read();
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
        last = hmac_sha1(password, last);
        xorsum = xorsum.xor(last);
      }

      output += xorsum;
    }

    return output.substr(0, key_length);
  };

  module.exports = pbkdf2;
})();
