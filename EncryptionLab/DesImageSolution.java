import java.lang.Object;
import javax.imageio.ImageIO;
import java.io.*;
import java.awt.image.BufferedImage;
import java.nio.*;
import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;


public class DesImageSolution {
    public static void main(String[] args) throws Exception {
        int image_width = 200;
        int image_length = 200;
        String DES_encryption_mode = "CBC";
        // read image file and save pixel value into int[][] imageArray
        BufferedImage img = ImageIO.read(new File("EncryptionLab/SUTD.bmp"));
        image_width = img.getWidth();
        image_length = img.getHeight();
        // byte[][] imageArray = new byte[image_width][image_length];
        int[][] imageArray = new int[image_width][image_length];
        for (int idx = 0; idx < image_width; idx++) {
            for (int idy = 0; idy < image_length; idy++) {
                int color = img.getRGB(idx, idy);
                imageArray[idx][idy] = color;
            }
        }
// TODO: generate secret key using DES algorithm
        SecretKey deskey = getSecretKey();


// TODO: Create cipher object, initialize the ciphers with the given key, choose encryption algorithm/mode/padding,
//you need to try both ECB and CBC mode, use PKCS5Padding padding method
        Cipher encrypt_cipher = getCipher(Cipher.ENCRYPT_MODE, deskey, DES_encryption_mode);


        // define output BufferedImage, set size and format
        BufferedImage outImage = new BufferedImage(image_width, image_length, BufferedImage.TYPE_3BYTE_BGR);

        for (int idx = 0; idx < image_width; idx++) {
            // convert each column int[] into a byte[] (each_width_pixel)
            byte[] each_width_pixel = new byte[4 * image_length];
            for (int idy = 0; idy < image_length; idy++) {
                ByteBuffer dbuf = ByteBuffer.allocate(4);
                dbuf.putInt(imageArray[idx][idy]);
                byte[] bytes = dbuf.array();
                System.arraycopy(bytes, 0, each_width_pixel, idy * 4, 4);
            }
// TODO: encrypt each column or row bytes 
            byte[] encrypt_each_width_pixel = encrypt_cipher.doFinal(each_width_pixel);

// TODO: convert the encrypted byte[] back into int[] and write to outImage (use setRGB)
            /*for (int idy = 0; idy < image_length; idy++){
                int rgbint = ByteBuffer.wrap(Arrays.copyOfRange(encrypt_each_width_pixel, idy*4, (idy*4)+3)).getInt();
                outImage.setRGB(idx, idy, rgbint);
            }*/

            //top to bottom
            /*ByteBuffer encrypt_byte_buffer = ByteBuffer.wrap(encrypt_each_width_pixel);
            for(int idy = 0; idy < image_length; idy++){
                int encrypt_rgbint =encrypt_byte_buffer.getInt();
                outImage.setRGB(idx, idy, encrypt_rgbint);
            }*/

            //bottom to top
            ByteBuffer encrypt_byte_buffer = ByteBuffer.wrap(encrypt_each_width_pixel);
            for(int idy = image_length-1; idy > 0; idy--){
                int encrypt_rgbint =encrypt_byte_buffer.getInt();
                outImage.setRGB(idx, idy, encrypt_rgbint);
            }

        }
//write outImage into file
        ImageIO.write(outImage, "BMP", new File("EncryptionLab/" + "test" + ".bmp"));
    }

    private static SecretKey getSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance("DES");
        keygen.init(new SecureRandom());
        return keygen.generateKey();
    }

    private static Cipher getCipher (int mode, SecretKey key, String encryption_mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher desCipher = Cipher.getInstance("DES/" + encryption_mode + "/PKCS5Padding");
        desCipher.init(mode, key);
        return desCipher;
    }
}