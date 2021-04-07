import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.*;


public class DigitalSignatureSolution {

    public static void main(String[] args) throws Exception {
//Read the text file and save to String data
        String fileName = "EncryptionLab/longtext.txt";
        String data = "";
        String line;
        BufferedReader bufferedReader = new BufferedReader( new FileReader(fileName));
        while((line= bufferedReader.readLine())!=null){
            data = data +"\n" + line;
        }
        //System.out.println("Original content: "+ data);

//TODO: generate a RSA keypair, initialize as 1024 bits, get public key and private key from this keypair.
        KeyPair RSAKeyPair = generateRSAKeyPair();
        Key publicKey = RSAKeyPair.getPublic();
        Key privateKey = RSAKeyPair.getPrivate();

//TODO: Calculate message digest, using MD5 hash function
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(data.getBytes());
        byte[] digest = md.digest();
        System.out.println("Original digest: " + Base64.getEncoder().encodeToString(digest));

//TODO: print the length of output digest byte[], compare the length of file shorttext.txt and longtext.txt
        System.out.println("Length of original digest: " + digest.length);

//TODO: Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as encrypt mode, use PRIVATE key.
        Cipher encrypt_cipher = getCipher(Cipher.ENCRYPT_MODE, privateKey);

//TODO: encrypt digest message
        byte[] encrypt_bytearray = encrypt_cipher.doFinal(digest);

//TODO: print the encrypted message (in base64format String using Base64) 
        System.out.println("Encrypted digest: " + Base64.getEncoder().encodeToString(encrypt_bytearray));

//TODO: Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as decrypt mode, use PUBLIC key.           
        Cipher decrypt_cipher = getCipher(Cipher.DECRYPT_MODE, publicKey);

//TODO: decrypt message
        byte[] decrypt_digest = decrypt_cipher.doFinal(encrypt_bytearray);


//TODO: print the decrypted message (in base64format String using Base64), compare with origin digest
        System.out.println("Decrypted digest: " + Base64.getEncoder().encodeToString(decrypt_digest));
        System.out.println("Length of decrypted digest: " + decrypt_digest   .length);





    }

    private static KeyPair generateRSAKeyPair () throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();
        return keyPair;
    }

    private static Cipher getCipher (int mode, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher desCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        desCipher.init(mode, key);
        return desCipher;
    }


}