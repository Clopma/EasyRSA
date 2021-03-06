package EasyRSA;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAUtils {

    private Cipher encrypter;
    private Cipher decrypter;
    private Key pubKey;
    private Key privKey;
    public RSAUtils(int keyLength) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); // NoSuchAlgorithmException
            kpg.initialize(keyLength);
            KeyPair kp = kpg.generateKeyPair();
            pubKey = kp.getPublic();
            privKey = kp.getPrivate();
            initEncrypter();
            initDecrypter();
        } catch (NoSuchAlgorithmException e) {
            //Nunca ocurrirá ya que "RSA" es un algoritmo existente
        }
    }

    public RSAUtils(String publicKeyStr, String privateKeyStr) throws InvalidKeySpecException {
        pubKey = loadPublicKey(publicKeyStr);
        privKey = loadPrivateKey(privateKeyStr);

        initEncrypter();
        initDecrypter();
    }

    public RSAUtils(String publicKeyStr) throws InvalidKeySpecException {
        pubKey = loadPublicKey(publicKeyStr);
        initEncrypter();
    }

    private void initEncrypter() {
        try {
            encrypter = Cipher.getInstance("RSA");
            encrypter.init(Cipher.ENCRYPT_MODE, pubKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private void initDecrypter() {
        try {
            decrypter = Cipher.getInstance("RSA");
            decrypter.init(Cipher.DECRYPT_MODE, privKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private Key loadPublicKey(String publicKeyStr) throws InvalidKeySpecException {
        byte[] publicKeyBytes = Base64.getDecoder().decode(formatKey(publicKeyStr).getBytes());
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        } catch (NoSuchAlgorithmException e) {
            return null; //Nunca ocurrirá ya que "RSA" es un algoritmo existente
        }
    }

    private Key loadPrivateKey(String privateKeyStr) throws InvalidKeySpecException {
        byte[] privateKeyBytes = Base64.getDecoder().decode(formatKey(privateKeyStr).getBytes());
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        } catch (NoSuchAlgorithmException e) {
            return null; //Nunca ocurrirá ya que "RSA" es un algoritmo existente
        }
    }

    public String encrypt(String textoPlano) throws IllegalBlockSizeException {
        try {
            return new String(Base64.getEncoder().encode(encrypter.doFinal(textoPlano.getBytes())), StandardCharsets.ISO_8859_1);
        } catch (IllegalBlockSizeException e) {
            initEncrypter();
            throw e;
        } catch (BadPaddingException e) {
            e.printStackTrace();
            return null; //No debería ocurrir nunca.
        }
    }

    public String decrypt(String encryptedData) throws IllegalBlockSizeException {
        if(decrypter == null){
           new Exception("You didn't provide a private key so you can't decrypt.").printStackTrace();
           return null;
        }
        try {
            return new String(decrypter.doFinal(Base64.getDecoder().decode(encryptedData.getBytes(StandardCharsets.ISO_8859_1))), StandardCharsets.ISO_8859_1);
        } catch (IllegalBlockSizeException e) {
            initDecrypter();
            throw e;
        } catch (BadPaddingException e) {
            e.printStackTrace();
            return null; //No debería ocurrir nunca.
        }
    }

    public String formatKey(String unformattedKey){
       return unformattedKey
                .replaceAll("-----(.)*-----", "")
                .replace("\n", "");
    }


}
