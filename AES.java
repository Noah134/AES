import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class AES {

    public static int iterations = 1000;
    private static String seperator = ";";
    private static int key_length = 256;
    private static int salt_length = 64;

    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String KEY_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    public static void setSaltLength(int length) throws Exception {
        if((length > 0) && ((length & (length - 1)) == 0))
            salt_length = length;
        else
            throw new Exception("Invalid Salt Length");

    }

    public static void setKeyLength(int length) throws Exception {
        if(length == 128 || length == 192 || length == 256)
            key_length = length;
        else
            throw new Exception("Invalid Length");
    }

    public static void setSeperator(String s) throws Exception {
        if(seperator.matches("[^+=/\\w]"))
            seperator = s;
        else
            throw new Exception("Invalid Seperator");
    }

    public static void setDurationOnCurrentComputer(int milliseconds){
        char[] password = {'t', 'e', 's', 't'};
        int i = 1;
        long duration = 0;
        while(duration < milliseconds) {
            i*=2;
            long t = System.currentTimeMillis();
            byte[] salt = new byte[64];
            new SecureRandom().nextBytes(salt);
            try {
                createKey(password, salt, i);
            } catch (Exception e) {
                e.printStackTrace();
            }
            duration = System.currentTimeMillis() - t;
            System.out.println("i: " + i + " duration: " + duration);
        }
        iterations = i;
    }

    private static SecretKey createKey(char[] password, byte[] salt, int iterations) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password, salt, iterations, key_length);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), KEY_ALGORITHM);
    }

    public static String encrypt(char[] password, byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidParameterSpecException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        byte[] salt = new byte[salt_length];
        new SecureRandom().nextBytes(salt);
        cipher.init(Cipher.ENCRYPT_MODE, createKey(password, salt, iterations));
        AlgorithmParameters params = cipher.getParameters();
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] ciphertext = cipher.doFinal(data);
        Base64.Encoder e = Base64.getEncoder();
        return e.encodeToString(iv) + seperator + e.encodeToString(ciphertext) + seperator + e.encodeToString(salt);
    }

    public static String decrypt(char[] password, String ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        String[] data = ciphertext.split(seperator);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        Base64.Decoder d = Base64.getDecoder();
        cipher.init(Cipher.DECRYPT_MODE, createKey(password, d.decode(data[2]), iterations), new IvParameterSpec(d.decode(data[0])));
        return new String(cipher.doFinal(d.decode(data[1])));
    }
}
