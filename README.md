# JSCryptor

[![Build Status](https://travis-ci.org/chesstrian/JSCryptor.svg?branch=master)](https://travis-ci.org/chesstrian/JSCryptor)

*Javascript implementation of RNCryptor*

This implementation try to be compatible with Rob Napier's Objective-C implementation of RNCryptor, It supports schema version 3.
This code is based on the [PHP implementation of RNCryptor](https://github.com/RNCryptor/RNCryptor-php).

## Install
```bash
sudo apt-get install libmcrypt4 libmcrypt-dev
npm install jscryptor
```

## Test
```bash
npm test
```

## Example
```js
// Example taken from https://github.com/RNCryptor/RNCryptor-php/blob/master/examples/decrypt.php

var password = 'myPassword';
var b64string = "AwHsr+ZD87myaoHm51kZX96u4hhaTuLkEsHwpCRpDywMO1Moz35wdS6OuDgq+SIAK6BOSVKQFSbX/GiFSKhWNy1q94JidKc8hs581JwVJBrEEoxDaMwYE+a+sZeirThbfpup9WZQgp3XuZsGuZPGvy6CvHWt08vsxFAn9tiHW9EFVtdSK7kAGzpnx53OUSt451Jpy6lXl1TKek8m64RT4XPr";

var RNCryptor = require('jscryptor');

console.time('Decrypting example');
var decrypted = RNCryptor.Decrypt(b64string, password);
console.timeEnd('Decrypting example');
console.log("Result:", decrypted);
```

## API
### RNCryptor()
Object exposed by `require('jscryptor')`;

### RNCryptor.Encrypt
* **plain_text**: *String* or *Buffer*
* **password**: *String* or *Buffer*
* **version**: *Number* (3 by default, not mandatory)

### RNCryptor.Decrypt
* **b64_str**: *String* or *Buffer*
* **password**: *String* or *Buffer*

### RNCryptor.EncryptWithArbitrarySalts
* **plain_text**: *String* or *Buffer*
* **password**: *String* or *Buffer*
* **encryption_salt**: *String* or *Buffer*
* **hmac_salt**: *String* or *Buffer*
* **iv**: *String* or *Buffer*
* **version**: *Number* (3 by default, not mandatory)

### RNCryptor.EncryptWithArbitraryKeys
* **plain_text**: *String* or *Buffer*
* **encryption_key**: *String* or *Buffer*
* **hmac_key**: *String* or *Buffer*
* **iv**: *String* or *Buffer*
* **version**: *Number* (3 by default, not mandatory)
