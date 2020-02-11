# EasyRSA
All the information you'll need to use this class can be found here:
https://carloslopezmari.com/encriptacion-asimetrica-en-java-hecho-tan-sencillo-que-te-hara-llorar

Generate temporal keys:
```
openssl genpkey -out private.pem -algorithm RSA -pkeyopt rsa_keygen_bits:3072

openssl rsa -in private.pem -out public.pem -pubout -outform PEM
```

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
            String encryptedText = rsa.encrypt("Test 234");
            String decryptedText = rsa.decrypt(encryptedText);
            System.out.println(decryptedText); //Prints: Test 234
        } catch (IllegalBlockSizeException e) {
            //String too long for the granted key
        }
```

# Only encrypt (client side):

```
        try {
            RSAUtils rsa = new RSAUtils(publicKeyStr);
            String encryptedText = rsa.encrypt("Test 456");
            //Send it to the server, he will decrypt it with:
            //new RSAUtils(publicKeyStr, privateKeyStr).decode(encryptedText);
        } catch (InvalidKeySpecException e) {
            //Check your key
        } catch (IllegalBlockSizeException e) {
            //String too long for the granted key
        }
```
