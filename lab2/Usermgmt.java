package hr.fer.srs.labosi.lab2;

import java.io.BufferedWriter;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.TreeMap;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;


public class Usermgmt {
    
	private static final int SIZE = 256; 
	private static final int ITERATIONS = 1000;
	private static int help = 0;
 	private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
	private static String file = new String("accountStorage.txt");
	private static Map<String, Pair> mapPasswords = new TreeMap<>();
	private static Map<String, String> mapSalts = new TreeMap<>();

    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
    	
    	// Provjera valjanosti argumenata naredbe
    	if (args.length == 2) {
    		if (args[0].equals("add")) {
				addNewUser(args[1]);
				write();
			} else if (args[0].equals("passwd")) {
				read();
				changePassword(args[1]);
				write();
			} else if (args[0].equals("forcepass")) {
				read();
				forcedChangePassword(args[0], args[1]);
				write();
			} else if (args[0].equals("del")) {
				read();
				deleteUser(args[1]);
				write();
			} else {
				throw new IllegalArgumentException("You entered wrong command!");
			}
    	} else {
    		throw new IllegalArgumentException("There must be 2 arguments in command!");
    	}
    	return;
    }

    private static HashMap<Object, Object> addNewUser (String username) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (checkIfUserExist(username) == false) {
        	Console cons = System.console();
        	if (cons == null) {
        		System.out.println("Console is not available.");
        		return;
        	}
        	String password = String.valueOf(cons.readPassword("Password: "));
        	String repeatedPassword = String.valueOf(cons.readPassword("Repeated password: "));
        	if (!repeatedPassword.equals(password)) throw new IllegalArgumentException("User add failed. Password mismatch.");
        	
        	// loading existing users        	
        	Map<String, User> users = Utils.loadUsers();
            if (!Files.exists(Path.of(file))) return new HashMap<>();
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file));
            ois.readObject();
            if (ois.available() != 0) throw new RuntimeException("File has ben tampered!");
            ois.close();
            return o;
            
        } else {
        	throw new IllegalArgumentException("There already exist user with that username.");
        }
        System.out.println("User add successfuly added.");
    }


	private static void changePassword(String username) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
    	if(checkIfUserExist(username) == true) {
        	Console cons = System.console();
        	String password = String.valueOf(cons.readPassword("Password: "));
        	String repeatedPassword = String.valueOf(cons.readPassword("Repeated password: "));
        	if(!repeatedPassword.equals(password)) throw new IllegalArgumentException("You entered different passwords.");
        	else {   		
        		byte[] oldSalt = hexToBytes(mapSalts.get(username));
        		
        		KeySpec keySpec = new PBEKeySpec(password.toCharArray(), oldSalt, ITERATIONS, SIZE);
        		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");       		
        		byte[] passwordInBytes = secretKeyFactory.generateSecret(keySpec).getEncoded();
        		
        		password = new String(bytesToHex(passwordInBytes));
        		String salt2 = new String(bytesToHex(oldSalt));
        		mapPasswords.put(username, new Pair(password, false));
        		mapSalts.put(username, salt2);
        	}
        } else {
        	throw new IllegalArgumentException("There is no user with that username.");
        }
        System.out.println("Password change successful.");
    }



    
    private static void forcedChangePassword(String command, String username) throws IOException, ClassNotFoundException {
    	if(checkIfUserExist(username) == true) {
    		Pair pair = mapPasswords.get(username);
    		if (!pair.y) {
    			mapPasswords.replace(username, new Pair(pair.x, true));
    		}
        } else {
        	throw new IllegalArgumentException("There is no user with that username.");
        }
        System.out.println("User will be requested to change password on next login.");
    }



    
    private static void deleteUser(String username) throws IOException, ClassNotFoundException {
    	if(checkIfUserExist(username) == true) {
    		mapPasswords.remove(username);
        } else {
        	throw new IllegalArgumentException("There is no user with that username.");
        }
        System.out.println("User successfully removed.");
    } 
    
    
    public static boolean checkIfUserExist(String username) {
    	for(Map.Entry<String, Pair> entry : mapPasswords.entrySet()) {
    		if(entry.getKey() == username) return true;
    	}
    	return false;
    }
 	
 // Funkcija za generiranje random bajtova zadane velicine
 	public static byte[] randomBytes(int length) {
 		SecureRandom random = new SecureRandom();
 		byte[] b = new byte[length];
 		random.nextBytes(b);
 		return b;
 	}
 	
 	public static String bytesToHex(byte[] bytes) {
 	    char[] hexChars = new char[bytes.length * 2];
 	    for (int j = 0; j < bytes.length; j++) {
 	        int v = bytes[j] & 0xFF;
 	        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
 	        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
 	    }
 	    return new String(hexChars);
 	}
 	
 	public static byte[] hexToBytes (String s) {
 	    byte[] arr = new byte[s.length()/2];
 	    for ( int start = 0; start < s.length(); start += 2 )
 	    {
 	        String thisByte = s.substring(start, start+2);
 	        arr[start/2] = Byte.parseByte(thisByte, 16);
 	    }
 	    return arr;
 	}
 	
 	@SuppressWarnings("resource")
	public static void read() {
 		try {
 		    Scanner myReader = new Scanner(file);
 		    mapPasswords.clear();
 		    mapSalts.clear();
 		    if(help == 0) return;
 		    help = 1;
 		      while (myReader.hasNextLine()) {
 		        String data = myReader.nextLine();
 		        String[] podjela = data.split(" ");
 		        if (podjela[2].equals("false"))  mapPasswords.put(podjela[0], new Pair(podjela[1],false));
 		        else  mapPasswords.put(podjela[0], new Pair(podjela[1],true));
 		        mapSalts.put(podjela[0], podjela[3]);
 		      }
 		      myReader.close();
 		    } catch (FileNotFoundException e) {
 		      System.out.println("An error occurred.");
 		      e.printStackTrace();
 		    }
 	}
 	
 	public static void write() throws IOException {
 		BufferedWriter writer = new BufferedWriter(new FileWriter(file));
 	    for (Map.Entry<String, Pair> entry : mapPasswords.entrySet()) {
 	    	writer.write(entry.getKey() + " ");
 	    	writer.write(entry.getValue().x + " ");
 	    	if (entry.getValue().y) writer.write("true");
 	    	else writer.write("false");
 	    	writer.newLine();
 	    }	    
 	    writer.close();
 	}
}

class Pair {

    public String x;
    public boolean y;

    public Pair(String x, boolean b) {
        this.x = x;
        this.y = b;
    }
 
    @Override
    public String toString() {
        return "[" + x + ", " + y + "]";
    }
    
    public String getKey() {
    	return this.x;
    }
    
    public boolean getValue() {
    	return this.y;
    }
}


