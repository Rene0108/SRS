package hr.fer.srs.labosi.lab1;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordManager {

	  private static final int SIZE = 256;          // adresa i zaporka se sastoje od najviše 256 znakova
	  private static final int ITERATIONS = 1000;
	  private static Cipher cipher;
	  private static byte[] salt;
	  private static byte[] iv;
	  private static byte[] encryptedContent;
	  private static HashMap<String, String> map = new HashMap<>();
	  private static Mac mac = null;
	  private static File file = new File("safe.txt");
	
	  public static void main(String[] args) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchPaddingException, InvalidKeySpecException {
		
		      // Provjera valjanosti argumenata naredbe
		      if (args.length == 2) {
			          if (args[0].equals("init")) {
				              initialization(args[1]);
			          } else {
				              throw new IllegalArgumentException("Only command 'init' has 2 arguments!");
			          }
		      } else if (args.length == 3) {
			          if (args[0].equals("get")) {
				              masterCheck(args[1]);
				              getPassword(args[1], args[2]);
			          } else {
				              throw new IllegalArgumentException("Only command 'get' has 3 arguments!");
			          }
		      } else if (args.length == 4)  {
			          if (args[0].equals("put")) {
				              masterCheck(args[1]);
				              putPassword(args[1], args[2], args[3]);
			          } else {
				              throw new IllegalArgumentException("Only command 'put' has 4 arguments!");
			          }
		      } else {
			          throw new IllegalArgumentException("There must be 2, 3 or 4 arguments in command!");
		      }
	  }
	
	
	  /**
	   * Inicijalizacija password managera, odnosno stvaranje prazne baze za pohrana parova [adresa, zaporka].
       * @param masterPassword Master password se koristi za inicijalizaciju baze.
       * @throws InvalidKeyException
       * @throws InvalidAlgorithmException
       * @throws NoSuchAlgorithmException
       * @throws IOException
       * @throws IllegalBlockSizeException
       * @throws BadPaddingException
       * @throws NoSuchPaddingException
       * @throws InvalidKeySpecException
       */
	  public static void initialization(String masterPassword) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeySpecException {
		
		      // PRIPREMA KRIPTIRANJA
		
		      // Definiranje algoritma za kriptiranje (algoritam/način/podstava)
		      cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		      // Kriptiranje praznog skupa
		      encryption(masterPassword);
		
		      // Ispisna potvrda kreirane baze odnosno password managera
		      System.out.println("Password manager initialized.");
	  }
	
	  /**
	  * Provjera integriteta master passworda i diska.
      * @param masterPassword 
	    * @throws IOException 
	    * @throws NoSuchAlgorithmException 
	    * @throws InvalidKeyException 
	    * @throws InvalidKeySpecException 
	    * @throws NoSuchPaddingException 
      */
	  public static void masterCheck(String masterPassword) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException {
		
		      // Provjera napravljene inicijalizacije i postojanja password managera
		      if(!file.exists()) {
			          System.out.println("There is no initialized password manager. To begin, initialize with the command: init [master password].");
			          System.exit(1);
		      }
		
		      // Definiranje algoritma za kriptiranje (algoritam/način/podstava)
		      cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		      // Kreiranje HMAC-a kako bismo provjerili integritet
		
		      mac = Mac.getInstance("HmacSHA256");
		      byte[] fileContent = Files.readAllBytes(file.toPath());
		      byte[] macSalt = Arrays.copyOfRange(fileContent, 0, SIZE);
		      // generiranje tajnog ključa na temelju (masterPassword, sol)
		      SecretKey macSecretKey = generateSecretKey(masterPassword, macSalt);
		      // inicijalizacija HMAC-a na temelju tajnog ključa
		      mac.init(macSecretKey);
		
		      // Čitanje kriptiranih podataka s diska
		      byte[] macFromBefore = Arrays.copyOfRange(fileContent, SIZE, SIZE + mac.getMacLength());
		      salt = Arrays.copyOfRange(fileContent, SIZE + mac.getMacLength(), 2 * SIZE + mac.getMacLength());
		      iv = Arrays.copyOfRange(fileContent, 2 * SIZE + mac.getMacLength(), 2 * SIZE + mac.getMacLength() + cipher.getBlockSize());
		      encryptedContent = Arrays.copyOfRange(fileContent, 2 * SIZE + mac.getMacLength() + cipher.getBlockSize(), fileContent.length);

		      /* Kreiranje HMAC-a nad podacima:  
		        *      # encryptedContent --> kriptirano polje okteta dobiveno šifriranjem baze adresa i zaporka
		        *      # iv --> inicijalizacijski vektor korišten kod kriptiranja baze
		        *      # salt --> sol korištena kod kriptiranja baze
		        *      # macSalt --> sol korištena kod izračuna integriteta
		        */
		      mac.update(encryptedContent);
		      mac.update(iv);
		      mac.update(salt);
		      mac.update(macSalt);
		      byte[] macCalculated = mac.doFinal();
		
		      // PROVJERA INTEGRITETA
		      if (!Arrays.equals(macFromBefore, macCalculated)) {
			          System.out.println("Master password incorrect or integrity check failed. ");
			          System.exit(1);
		      }
		      // System.out.println("masterCheck prošo u redu.");
		
	  }
	
	  /**
	    * Pohrana para [adresa, zaporka]. 
	    * Ako je već pohranjena zaporka pod istom adresom, funkcija će ju zamijeniti sa novom zaporkom.
      * @param masterPassword 
      * @param adress
      * @param password
	    * @throws InvalidKeySpecException 
	    * @throws NoSuchAlgorithmException 
	    * @throws InvalidAlgorithmParameterException 
	    * @throws InvalidKeyException 
	    * @throws BadPaddingException 
	    * @throws IllegalBlockSizeException 
	    * @throws IOException 
	    * @throws FileNotFoundException 
      */
	  public static void putPassword(String masterPassword, String adress, String password) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException  {
		
		      // DEKRIPTIRANJE PODATAKA
		      String content = decryption(masterPassword);
		
		      // Kreiranje baze, odnosno mape, parova [adresa, zaporka].
		      if (!content.isEmpty()) {
			          String[] pairs = content.split("\n");
			          for (String pair : pairs) {
				              String[] both = pair.split("\t");
				              map.put(both[0], both[1]);
			          }	
		      }
		
		      // Dodavanje novog para u bazu
		      map.put(adress, password);
		      System.out.println("Stored password for " + adress + ".");
		
		      // KRIPTIRANJE PODATAKA
		      encryption(masterPassword);
	  }
	
	  /**
	    * Dohvaćanje pohranjene zaporke za zadanu adresu.
      * @param masterPassword 
      * @param adress
	    * @throws InvalidKeySpecException 
	    * @throws NoSuchAlgorithmException 
	    * @throws InvalidAlgorithmParameterException 
	    * @throws InvalidKeyException 
	    * @throws BadPaddingException 
	    * @throws IllegalBlockSizeException 
	    * @throws IOException 
	    * @throws FileNotFoundException 
      */
	  public static void getPassword(String masterPassword, String adress) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException {
		
		      // DEKRIPTIRANJE PODATAKA
		      String content = decryption(masterPassword);
		
		      // Kreiranje baze, odnosno mape, parova [adresa, zaporka].
		      String[] pairs = content.split("\n");
		      for (String pair : pairs) {
			          String[] both = pair.split("\t");
			          map.put(both[0], both[1]);
		      }
		
		      // Čitanje passworda za zadanu adressu
		      String password = map.get(adress);
		      System.out.println("Password for " + adress + " is: " + password + ".");
		
		      // KRIPTIRANJE PODATAKA
		      encryption(masterPassword);
		
	  }
	
	  // Funkcija DEKRIPTIRANJA
	  private static String decryption(String masterPassword) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		      SecretKey secretKey = generateSecretKey(masterPassword, salt);
		      SecretKeySpec keySpecification = new SecretKeySpec(secretKey.getEncoded(), "AES");		
		      AlgorithmParameterSpec parameterSpecification = new IvParameterSpec(iv);

		      cipher.init(Cipher.DECRYPT_MODE, keySpecification, parameterSpecification);

		      byte[] decryptedContent = cipher.doFinal(encryptedContent);

		      // Pretvorba niza bajtova u string
		      String s = new String(decryptedContent, StandardCharsets.UTF_8);
		      return(s);
	  }
	
	  // Funkcija KRIPTIRANJA
	  private static void encryption(String masterPassword) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException {
		
		      // generiranje soli
		      salt = randomBytes(SIZE);
		      // generiranje tajnog ključa na temelju (masterPassword, soli)
		      SecretKey secretKey = generateSecretKey(masterPassword, salt);
		      SecretKeySpec keySpecification = new SecretKeySpec(secretKey.getEncoded(), "AES");		
		      // generiranje inicijalizacijskog vektora
		      iv = randomBytes(cipher.getBlockSize());
		      AlgorithmParameterSpec parameterSpecification = new IvParameterSpec(iv);
		      // finalno kreiranje postupka kriptiranja
		      cipher.init(Cipher.ENCRYPT_MODE, keySpecification, parameterSpecification);
		
		      // kriptiranje mape
		      String string = "";
		      for (Entry<String, String> e : map.entrySet()) {
			          string = string + e.getKey() + "\t" + e.getValue() + "\n";
		      }
		      encryptedContent = cipher.doFinal(string.getBytes());
		
		
		      // PRIPREMA I KREIRANJE HMAC-a
		
		      // Definiranje algoritma za integritet "HmacSHA256"
		      mac = Mac.getInstance("HmacSHA256");
		
		      // generiranje soli 
		      byte[] macSalt = randomBytes(SIZE);
		      // generiranje tajnog ključa na temelju (masterPassword, sol)
		      SecretKey macSecretKey = generateSecretKey(masterPassword, macSalt);
		      // inicijalizacija HMAC-a na temelju tajnog ključa
		      mac.init(macSecretKey);

		      /* Kreiranje HMAC-a nad podacima:  
		        *      # encryptedContent --> kriptirano polje okteta dobiveno šifriranjem baze adresa i zaporka
		        *      # iv --> inicijalizacijski vektor korišten kod kriptiranja baze
		        *      # salt --> sol korištena kod kriptiranja baze
		        *      # macSalt --> sol korištena kod izračuna integriteta
		        */
		      mac.update(encryptedContent);
          mac.update(iv);
          mac.update(salt);
          mac.update(macSalt);
		      byte[] macCalculated = mac.doFinal();

          // Spremanje kriptiranih stavki na disk
		      try (FileOutputStream disk = new FileOutputStream(file)) {
			          disk.write(macSalt);
			          disk.write(macCalculated);
			          disk.write(salt);
			          disk.write(iv);
			          disk.write(encryptedContent);
		      }
	  }
	
	  // Funkcija za generiranje random bajtova zadane velicine
	  private static byte[] randomBytes(int length) {
		      SecureRandom random = new SecureRandom();
		      byte[] b = new byte[length];
		      random.nextBytes(b);
		      return b;
	  }
	
	  // Funkcija za generiranje sigurnog ključa 
	  private static SecretKey generateSecretKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		      PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, SIZE);
		      SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");;
		      return keyFactory.generateSecret(pbeKeySpec);
	  }
}
