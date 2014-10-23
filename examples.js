var RNCryptor = require('./index');

// Example taken from https://github.com/RNCryptor/RNCryptor-php/blob/master/examples/decrypt.php

var password = 'myPassword';
var b64string = "AwHsr+ZD87myaoHm51kZX96u4hhaTuLkEsHwpCRpDywMO1Moz35wdS6OuDgq+SIAK6BOSVKQFSbX/GiFSKhWNy1q94JidKc8hs581JwVJBrEEoxDaMwYE+a+sZeirThbfpup9WZQgp3XuZsGuZPGvy6CvHWt08vsxFAn9tiHW9EFVtdSK7kAGzpnx53OUSt451Jpy6lXl1TKek8m64RT4XPr";

console.time('Decrypting');
var result = RNCryptor.Decrypt(b64string, password);
console.timeEnd('Decrypting');
console.log("Result:", result);
