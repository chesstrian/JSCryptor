(function() {
  var crypto = require('crypto');

  module.exports = function(password, salt, iterations, key_length) {
    var last, xor_sum;

    var algorithm = 'sha1';

    if (!Buffer.isBuffer(password)) password = new Buffer(password, 'binary');
    if (!Buffer.isBuffer(salt)) salt = new Buffer(salt, 'binary');

    var block_count = Math.ceil(key_length / 20);

    var output = '';
    for (var i = 1; i <= block_count; i++) {
      last = new Buffer(salt.length + 4);
      salt.copy(last, 0, 0, salt.length);
      last.writeUInt32BE(i, salt.length);

      last = xor_sum = crypto.createHmac(algorithm, password).update(last).digest();


      for (var j = 1; j < iterations; j++) {
        last = crypto.createHmac(algorithm, password).update(last).digest();
        for (var k = 0; k < last.length; k++) {
          xor_sum[k] ^= last[k];
        }
      }

      output += xor_sum.toString('binary');
    }

    return output.substr(0, key_length);
  };
})();
