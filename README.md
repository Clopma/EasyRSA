# EasyRSA
All the information you'll need to use this class can be found here:
https://carloslopezmari.com/encriptacion-asimetrica-en-java-hecho-tan-sencillo-que-te-hara-llorar


# Use your own keys:
```
try {
    RSAUtils rsa = new RSAUtils(publicKeyStr, privateKeyStr);
    String encryptedText = rsa.encrypt("Test 123");
    String decryptedText = rsa.decrypt(encryptedText);
    System.out.println(decryptedText); //Prints: Test 123
} catch (InvalidKeySpecException e) {
     //Check your keys
} catch (IllegalBlockSizeException e) {
     //String too long for the granted key
}
```

# Use autogenerated keys:

```
try {
    RSAUtils rsa = new RSAUtils(3072); //key length min: 512 recommended: 3072 / 4096
    String encryptedText = rsa.encrypt("Test 123");
    String decryptedText = rsa.decrypt(encryptedText);
    System.out.println(decryptedText); //Prints: Test 123
} catch (IllegalBlockSizeException e) {
     //String too long for the granted key
}
```

# Only encrypt (client side):

```
try {
    RSAUtils rsa = new RSAUtils(publicKeyStr);
    String encryptedText = rsa.encrypt("Test 123");
    String decryptedText = rsa.decrypt(encryptedText);
    System.out.println(decryptedText); //Prints: Test 123
} catch (InvalidKeySpecException e) {
     //Check your key
} catch (IllegalBlockSizeException e) {
     //String too long for the granted key
}
```
