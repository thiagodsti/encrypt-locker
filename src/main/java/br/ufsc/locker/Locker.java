package br.ufsc.locker;

import com.fasterxml.jackson.databind.ObjectMapper;
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
    public static final byte[] SALT = "FaculdadeUniversity".getBytes();
    public static final byte[] NONCE = "SegurancaRedes".getBytes();
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
                String input = new String(inputBytes, Charset.forName("UTF-8"));
                String decrypt = this.decryptLocker(keyPlain, input);

                List<Content> contentsAux = Arrays.asList(mapper.readValue(decrypt, Content[].class));
                contents.addAll(contentsAux);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void add() {
        System.out.println("Add " + file.getAbsolutePath() + " " + password);
        Content c = new Content(file.getAbsolutePath(), password);
        contents.add(encryptContent(c));
        close();
    }

    public void del() {
        System.out.println("Del " + file.getAbsolutePath() + " " + password);
        Content c = new Content(file.getAbsolutePath(), password);
        contents.remove(encryptContent(c));
        close();
    }

    public void check() {
        System.out.println("Check " + file.getAbsolutePath() + " " + password);
        Content c = new Content(file.getAbsolutePath(), password);
        if (contents.indexOf(this.encryptContent(c)) >= 0) {
            System.out.println("Exists");
        } else {
            System.out.println("Doesn't exist");
        }
        close();
    }

    public void update(String newPassword) {
        System.out.println("Update " + file.getAbsolutePath() + " " + password + " " + newPassword );
        Content c = new Content(file.getAbsolutePath(), password);
        int index = contents.indexOf(this.encryptContent(c));
        Content content = contents.get(index);
        content.setFileName(file.getAbsolutePath());
        content.setKey(newPassword);
        contents.set(index, encryptContent(content));
        close();
    }


    private Content encryptContent(Content c) {


        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(c.getKey().toCharArray(), SALT, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

            byte[] key = secret.getEncoded();

            //  texto plano (P)
            byte[] input;

            String pN = Hex.toHexString(NONCE);
            byte[] nonce = org.apache.commons.codec.binary.Hex.decodeHex(pN.toCharArray());

            // Mensagem de entrada
            input = c.getFileName().getBytes();

            System.out.println("Msg = " + c.getFileName());

            // CIFRAR criando GCMBlockCipher
            // Instancia um GCM com AES usando o formato da BouncyCastle
            GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());

            // Parametros a serem passados para o GCM: chave, tamanho do mac, o nonce
            KeyParameter key2 = new KeyParameter(key);
            AEADParameters params = new AEADParameters(key2, MAC_SIZE, nonce);

            // true para cifrar
            gcm.init(true, params);
            int outsize = gcm.getOutputSize(input.length);
            byte[] outc = new byte[outsize];
            //processa os bytes calculando o offset para cifrar
            int lengthOutc = gcm.processBytes(input, 0, input.length, outc, 0);

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
    }

    public static String encryptLocker(String key, String toEncrypt) throws Exception {
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

    public static String decryptLocker(String key, String encrypted) throws Exception {
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
            String content = mapper.writeValueAsString(contents.toArray());
            byte[] keyFile = Files.readAllBytes(lockerKey.toPath());
            String keyPlain = new String(keyFile, Charset.forName("UTF-8"));
            System.out.println(keyPlain);

            String encrypt = this.encryptLocker(keyPlain, content);
            FileOutputStream fileOutputStream = new FileOutputStream(lockerFile, false);
            fileOutputStream.write(encrypt.getBytes());
            fileOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}
