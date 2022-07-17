<?php

$sensitiveData = "hola mundo";
$privateKeyPassphrase = '';

// Get keys from a string so that this example can be run without the need for extra files
$privateKeyString = file_get_contents('privatekey.pem');

$publicKeyString = file_get_contents('publickey.pem');

// Load private key
$privateKey = openssl_pkey_get_private(array($privateKeyString, $privateKeyPassphrase));

// Load public key
$publicKey = openssl_pkey_get_public(array($publicKeyString, $privateKeyPassphrase));

if (!$privateKey) {
    echo "Private key NOT OK\n";
}

if (!$publicKey) {
    echo "Public key NOT OK\n";
}

if (!openssl_private_encrypt($sensitiveData, $encryptedWithPrivate, $privateKey)) {
    echo "Error encrypting with private key\n";
}

if (!openssl_public_encrypt($sensitiveData, $encryptedWithPublic, $publicKey)) {
    echo "Error encrypting with public key\n";
}

if (!openssl_private_decrypt($encryptedWithPublic, $decryptedWithPrivateFromPublic, $privateKey)) {
    echo "Error decrypting with private key what was encrypted with public key\n";
}

if (!openssl_public_decrypt($encryptedWithPrivate, $decryptedWithPublicFromPrivate, $publicKey)) {
    echo "Error decrypting with public key what was encrypted with private key\n";
}

echo "Encrypted with public key: " . base64_encode($encryptedWithPublic) . "\n"; // This is different every time
echo "Encrypted with private key: " . base64_encode($encryptedWithPrivate) . "\n";
echo "Decrypted with private key what was encrypted with public key: " . $decryptedWithPrivateFromPublic . "\n";
echo "Decrypted with public key what was encrypted with private key: " . $decryptedWithPublicFromPrivate . "\n";



/*

openssl genrsa -out privatekey.pem 512
openssl rsa -in privatekey.pem -outform PEM -pubout -out publickey.pem

*/

