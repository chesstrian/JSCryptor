# JSCryptor

*Javascript implementation of [RNCryptor](https://github.com/RNCryptor/RNCryptor-Spec)*

This implementation tries to be compatible with [Rob Napier's Objective-C implementation of RNCryptor](https://github.com/RNCryptor/RNCryptor), It supports schema version 3.
This code is based on the [PHP implementation of RNCryptor](https://github.com/RNCryptor/RNCryptor-php).

## Important Recent Changes
* Now a `Buffer` is returned, use `.toString()` to convert the result to whatever format you need.
* `mcrypt` library not used anymore. Thanks to @b00tsy.
* Support dropped for Nodejs 12 and below.

## Install
```bash
npm install jscryptor
```

## Install on Windows
### Thanks to @jimmitaker and @black-snow for pointing this

VS2015+ (Community Edition works fine) is required.

## Test
```bash
npm test
```

## Example
```js
// Example taken from https://github.com/RNCryptor/RNCryptor-php/blob/master/examples/decrypt.php

const password = 'myPassword';
const b64string = "AwHsr+ZD87myaoHm51kZX96u4hhaTuLkEsHwpCRpDywMO1Moz35wdS6OuDgq+SIAK6BOSVKQFSbX/GiFSKhWNy1q94JidKc8hs581JwVJBrEEoxDaMwYE+a+sZeirThbfpup9WZQgp3XuZsGuZPGvy6CvHWt08vsxFAn9tiHW9EFVtdSK7kAGzpnx53OUSt451Jpy6lXl1TKek8m64RT4XPr";

const RNCryptor = require('jscryptor');

console.time('Decrypting example');
const decrypted = RNCryptor.Decrypt(b64string, password);
console.timeEnd('Decrypting example');
console.log("Result:", decrypted.toString());
```

### A very good example, provided by @enricodeleo
```js
const fs = require('fs');
const RNCryptor = require('jscryptor');

const password = 'myPassword';

const img = fs.readFileSync('./Octocat.jpg');
const enc = RNCryptor.Encrypt(img, password);

// Save encrypted image to a file, for sending to anywhere
fs.writeFileSync('./Octocat.enc', enc);

// Now, to decrypt the image:
const b64 = Buffer.from(fs.readFileSync('./Octocat.enc').toString(), 'base64');
const dec = RNCryptor.Decrypt(b64, password);

fs.writeFileSync('./Octocat2.jpg', dec);  // Image should open.
```

## API
### RNCryptor()
Object exposed by `require('jscryptor')`;

### RNCryptor.Encrypt
* plain_text: *String* or *Buffer*
* password: *String* or *Buffer*
* version: *Number* (3 by default, not mandatory)

### RNCryptor.Decrypt
* b64_str: *String* or *Buffer*
* password: *String* or *Buffer*

### RNCryptor.EncryptWithArbitrarySalts
* plain_text: *String* or *Buffer*
* password: *String* or *Buffer*
* encryption_salt: *String* or *Buffer*
* hmac_salt: *String* or *Buffer*
* iv: *String* or *Buffer*
* version: *Number* (3 by default, not mandatory)

### RNCryptor.EncryptWithArbitraryKeys
* plain_text: *String* or *Buffer*
* encryption_key: *String* or *Buffer*
* hmac_key: *String* or *Buffer*
* iv: *String* or *Buffer*
* version: *Number* (3 by default, not mandatory)
