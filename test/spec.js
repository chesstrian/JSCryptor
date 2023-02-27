(function () {
  const fs = require('fs');
  const path = require('path');

  const spec_dir = path.join(__dirname, '../spec/vectors/v3/');

  fs.readdirSync(spec_dir).forEach(function (file) {
    let aux_object;
    exports[file] = [];

    const file_content = fs.readFileSync(spec_dir + file);
    file_content.toString().split('\n').forEach(function (line) {
      if (line === '' || line[0] === '#') return;

      const key_value = line.split(':');
      if (key_value[0] === 'title') aux_object = {};

      if (['key_hex', 'ciphertext_hex', 'plaintext_hex'].indexOf(key_value[0]) >= 0)
        key_value[1] = key_value[1].replace(/\s+/g, '');

      aux_object[key_value[0]] = key_value[1].trim() || '';

      if (['key_hex', 'ciphertext_hex'].indexOf(key_value[0]) >= 0) exports[file].push(aux_object);
    });
  });
})();
