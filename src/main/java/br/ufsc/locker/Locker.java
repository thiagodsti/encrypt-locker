package br.ufsc.locker;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class Locker {

    private static final int MAC_SIZE = 128;
    public static final int GCM_NONCE_LENGTH = 12; // in bytes
    public static final byte[] SALT = "FaculdadeUniversity".getBytes();

    private static final ObjectMapper mapper = new ObjectMapper();


    private File file;
    private String password;
    private File lockerKey;
    private File lockerFile;
    private List<Content> contents;


    public Locker(String fileName, String password, File lockerKey, File lockerFile) {
        File file = new File(fileName);

        if (!file.exists()) {
            System.err.println("File: " + file.getAbsolutePath() + " couldn't be found.");
            System.exit(1);
        }


        this.file = file;
        this.password = password;
        this.lockerKey = lockerKey;
        this.lockerFile = lockerFile;
        this.contents = new ArrayList<>();

        //Ler arquivo e popular array.
        try {

            if (lockerFile.length() > 0) {
                byte[] inputBytes = Files.readAllBytes(lockerFile.toPath());

                byte[] keyFile = Files.readAllBytes(lockerKey.toPath());
                String keyPlain = new String(keyFile, Charset.forName("UTF-8"));
                System.out.println(keyPlain);
                String input = new String(inputBytes, Charset.forName("UTF-8"));
                String decrypt = this.decrypt(keyPlain, input);

                List<Content> contentsAux = Arrays.asList(mapper.readValue(decrypt, Content[].class));
                contents.addAll(contentsAux);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void add() {
        System.out.println("Add " + file.getName() + " " + password);
        Content c = new Content(file.getName(), password);
        contents.add(encryptContent(c));
        writeToLocker();

        close();
    }

    public void del() {
        System.out.println("Del " + file.getName() + " " + password);
        Content c = new Content(file.getName(), password);
        contents.remove(encryptContent(c));
        writeToLocker();

        close();
    }

    public void check() {
        System.out.println("Check " + file.getName() + " " + password);
        Content c = new Content(file.getName(), password);
        if (contents.indexOf(this.encryptContent(c)) >= 0) {
            System.out.println("Exists");
        } else {
            System.out.println("Doesn't exist");
        }

        writeToLocker();
        close();
    }

    public void update(String newPassword) {
        System.out.println("Update " + file.getName() + " " + password + " " + newPassword );
        Content c = new Content(file.getName(), password);
        int index = contents.indexOf(this.encryptContent(c));
        Content content = contents.get(index);
        content.setFileName(file.getName());
        content.setKey(newPassword);
        contents.set(index, encryptContent(content));
        writeToLocker();
        close();
    }


    private Content encryptContent(Content c) {


        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(c.getKey().toCharArray(), SALT, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

            byte[] K = secret.getEncoded();

            //  texto plano (P)
            byte[] P;

            /**
             * String pP; pP = "d9313225f88406e5a55909c5aff5269a" +
             * "86a7a9531534f7da2e4c303d8a318a72" +
             * "1c3c0c95956809532fcf0e2449a6b525" +
             * "b16aedf5aa0de657ba637b391aafd255";
             */
            //= org.apache.commons.codec.binary.Hex.decodeHex(pP.toCharArray());
            //  nonce (IV)
            String pN;
            pN = "cafebabefacedbaddecaf888";
            byte[] N = org.apache.commons.codec.binary.Hex.decodeHex(pN.toCharArray());

            //  tag (T)
            String T;
            //= "b094dac5d93471bdec1a502270e3cc6c";

            //  texto cifrado (C)
            byte[] C;

            /**
             * String pC; pC = "522dc1f099567d07f47f37a32a84427d" +
             * "643a8cdcbfe5c0c97598a2bd2555d1aa" +
             * "8cb08e48590dbb3da7b08b1056828838" +
             * "c5f61e6393ba7a0abcc9f662898015ad" + T;
             */
            //= org.apache.commons.codec.binary.Hex.decodeHex(pC.toCharArray());
            // Mensagem de entrada
            P = c.getFileName().getBytes();

            System.out.println("Msg = " + c.getFileName());

            // CIFRAR criando GCMBlockCipher
            // Instancia um GCM com AES usando o formato da BouncyCastle
            GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());

            // Parametros a serem passados para o GCM: chave, tamanho do mac, o nonce
            KeyParameter key2 = new KeyParameter(K);
            AEADParameters params = new AEADParameters(key2, MAC_SIZE, N);

            // true para cifrar
            gcm.init(true, params);
            int outsize = gcm.getOutputSize(P.length);
            byte[] outc = new byte[outsize];
            //processa os bytes calculando o offset para cifrar
            int lengthOutc = gcm.processBytes(P, 0, P.length, outc, 0);

            try {
                //cifra os bytes
                gcm.doFinal(outc, lengthOutc);
            } catch (InvalidCipherTextException e) {
                e.printStackTrace();
            }

            System.out.println("Msg cifrada = " + org.bouncycastle.util.encoders.Hex.toHexString(outc));

            //Salvar a key como GCM
            c.setKey(Hex.toHexString(outc));

            // Recupera tag do GCM
            byte[] encT1 = gcm.getMac();

            String gcmFileName = Hex.toHexString(encT1);

            //Salvar o fileName como HMAC
            c.setFileName(gcmFileName);

            return c;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return c;

        //System.out.println("Tag msg cifrada = " + Hex.toHexString(encT1));

        // tampering step - mudando o texto cifrado para ver se eh detectado!
        // A msg cifrada FOI MODIFICADA
        //outc[11] ^= '0' ^ '9';

        // DECIFRAR usando GCMBlockCipher
        // false para decifrar


        /**    gcm.init(false, params);

         int outsize2 = gcm.getOutputSize(outc.length);
         byte[] out2 = new byte[outsize2];
         int offOut2 = gcm.processBytes(outc, 0, outc.length, out2, 0);

         try {
         gcm.doFinal(out2, offOut2);
         String decifrado = new String(out2);
         System.out.println("Msg decifrada = \t\t" + decifrado);
         byte[] encT2 = gcm.getMac();
         System.out.println("Tag msg cifrada modificada = \t" + org.bouncycastle.util.encoders.Hex.toHexString(encT2));

         } catch (InvalidCipherTextException e) {
         System.err.println("Erro de decifragem: " + e.getMessage());
         //e.printStackTrace();
         } */
    }

    public static String encrypt(String key, String toEncrypt) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        PBEKeySpec keySpec = new PBEKeySpec(key.toCharArray(), SALT, 65536, MAC_SIZE);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", "BC");
        SecretKey passwordKey = secretKeyFactory.generateSecret(keySpec);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, passwordKey);
        byte[] encrypted = cipher.doFinal(toEncrypt.getBytes());
        byte[] encryptedValue = Base64.getEncoder().encode(encrypted);
        return new String(encryptedValue);
    }

    public static String decrypt(String key, String encrypted) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        PBEKeySpec keySpec = new PBEKeySpec(key.toCharArray(), SALT, 65536, MAC_SIZE);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", "BC");
        SecretKey passwordKey = secretKeyFactory.generateSecret(keySpec);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, passwordKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encrypted.getBytes());
        byte[] original = cipher.doFinal(decodedBytes);
        return new String(original);
    }

    private void close() {
        try {
            byte[] inputBytes = Files.readAllBytes(lockerFile.toPath());
            byte[] keyFile = Files.readAllBytes(lockerKey.toPath());
            String keyPlain = new String(keyFile, Charset.forName("UTF-8"));
            System.out.println(keyPlain);
            String input = new String(inputBytes, Charset.forName("UTF-8"));

            String encrypt = this.encrypt(keyPlain, input);
            FileOutputStream fileOutputStream = new FileOutputStream(lockerFile, false);
            fileOutputStream.write(encrypt.getBytes());
            fileOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void writeToLocker() {
        try {
            FileUtils.write(lockerFile, mapper.writeValueAsString(contents.toArray()), Charset.defaultCharset());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


}
