var RNCryptor = require('./index');

// Example taken from https://github.com/RNCryptor/RNCryptor-php/blob/master/examples/decrypt.php

var password = 'myPassword';
var b64string = "AwHsr+ZD87myaoHm51kZX96u4hhaTuLkEsHwpCRpDywMO1Moz35wdS6OuDgq+SIAK6BOSVKQFSbX/GiFSKhWNy1q94JidKc8hs581JwVJBrEEoxDaMwYE+a+sZeirThbfpup9WZQgp3XuZsGuZPGvy6CvHWt08vsxFAn9tiHW9EFVtdSK7kAGzpnx53OUSt451Jpy6lXl1TKek8m64RT4XPr";
var plain_text = 'There is no place like home';

console.time('Encrypting');
var encrypted = RNCryptor.Encrypt(plain_text, password);
console.timeEnd('Encrypting');
console.log("Result:", encrypted);

console.time('Decrypting');
var decrypted1 = RNCryptor.Decrypt(encrypted, password);
console.timeEnd('Decrypting');
console.log("Result:", decrypted1);

console.time('Decrypting other');
var decrypted2 = RNCryptor.Decrypt(b64string, password);
console.timeEnd('Decrypting other');
console.log("Result:", decrypted2);
