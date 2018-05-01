package br.ufsc.locker;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Helper;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Scanner;

public class Main {

    public static final String LOCKER_KEY = ".locker.key";
    public static final String LOCKER = ".locker";
    public static final int PARALLELISM = 4;
    public static final int MEMORY = 65536;

    public static void main(String[] args) {
        if (args.length != 3 && args.length != 4) {
            System.out.println("Wrong args");
            System.out.println("Usage: COMMAND FILE PASSWORD [NEW_PASSWORD]");
            System.exit(1);
            return;
        }


        File userDirectory = FileUtils.getUserDirectory();
        File lockerKey = new File(userDirectory.getPath() + "/" + LOCKER_KEY);
        File lockerFile = new File(userDirectory.getPath() + "/" + LOCKER);
        if (lockerFile.exists() && !lockerKey.exists()) {
            System.out.println("Theres a locker without a key");
            System.out.println("Your locker will be erased and another one empty will be create");
            lockerFile.delete();
        }
        if (!lockerKey.exists()) {
            criarChaveMestre(lockerKey);
        }

        if (!lockerFile.exists()) {
            try {
                lockerFile.createNewFile();
            } catch (IOException e) {
                System.err.println("Couldn't create locker file");
                e.printStackTrace();
                System.exit(1);
            }
        }

        Locker locker = new Locker(args[1], args[2], lockerKey, lockerFile);

        switch (args[0].toUpperCase()) {
            case "ADD":
                locker.add();
                break;
            case "DEL":
                locker.del();
                break;
            case "CHECK":
                locker.check();
                break;
            case "UPDATE":
                if (args.length != 4) {
                    System.out.println("Wrong args");
                    System.out.println("Usage: COMMAND FILE OLD_PASSWORD NEW_PASSWORD");
                    System.exit(1);
                    return;
                }
                locker.update(args[3]);
                break;
            default:
                System.err.println("Comand not recognized");
                System.exit(1);
        }

    }

    private static void criarChaveMestre(File chaveiroKey) {
        Scanner sc = new Scanner(System.in);

        System.out.println("Insert a master password:");
        String secret = sc.nextLine();

        System.out.println("Please wait, generating a new key");

        Argon2 argon2 = Argon2Factory.create();
        int iterations = Argon2Helper.findIterations(argon2, 1000, MEMORY, PARALLELISM);

        char[] password = secret.toCharArray();
        String hash = "";

        try {
            // Hash password
            hash = argon2.hash(iterations, MEMORY, PARALLELISM, password);
            password = hash.toCharArray();
        } finally {
            // Wipe confidential data
            argon2.wipeArray(password);
        }


        try {
            FileUtils.write(chaveiroKey, hash, Charset.defaultCharset());
        } catch (IOException e) {
            System.err.println("Couldn't create locker.key");
            e.printStackTrace();
            System.exit(1);
        }
    }
}
