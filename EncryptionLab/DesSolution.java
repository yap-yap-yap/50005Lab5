import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import javax.crypto.*;
import java.security.*;
import java.util.Base64;


public class DesSolution {
    public static void main(String[] args) throws Exception {
        String fileName = "EncryptionLab/shorttext.txt";
        String data = "";
        String line;
        BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName));
        while ((line = bufferedReader.readLine()) != null) {
            data = data + "\n" + line;
        }
        //System.out.println("Original content: " + data);

//TODO: generate secret key using DES algorithm
        SecretKey deskey = getSecretKey();

//TODO: create cipher object, initialize the ciphers with the given key, choose encryption mode as DES
        Cipher encrypt_cipher = getCipher(Cipher.ENCRYPT_MODE, deskey);

//TODO: do encryption, by calling method Cipher.doFinal().
        byte[] encrypt_bytearray = encrypt_cipher.doFinal(data.getBytes());

//TODO: print the length of output encrypted byte[], compare the length of file shorttext.txt and longtext.txt
        System.out.println("length of encrypted data: " + encrypt_bytearray.length);
        //System.out.println(new String(encrypt_bytearray));

//TODO: do format conversion. Turn the encrypted byte[] format into base64format String using Base64
//TODO: print the encrypted message (in base64format String format)
        //System.out.println("Encrypted data: " + Base64.getEncoder().encodeToString(encrypt_bytearray));

//TODO: create cipher object, initialize the ciphers with the given key, choose decryption mode as DES
        Cipher decrypt_cipher = getCipher(Cipher.DECRYPT_MODE, deskey);

//TODO: do decryption, by calling method Cipher.doFinal().
        byte[] decrypt_bytearray = decrypt_cipher.doFinal(encrypt_bytearray);

//TODO: do format conversion. Convert the decrypted byte[] to String, using "String a = new String(byte_array);"
        String decrypt_data = new String(decrypt_bytearray);

//TODO: print the decrypted String text and compare it with original text
        //System.out.println(decrypt_data);
        System.out.println(data.equals(decrypt_data));


    }

    private static SecretKey getSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance("DES");
        keygen.init(new SecureRandom());
        return keygen.generateKey();

    }
        
    private static Cipher getCipher (int mode, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        desCipher.init(mode, key);
        return desCipher;
    }









}