package io.virgo.virgoCryptoLib;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class Converter {

	private final static List<Character> hexArray = Arrays.asList('0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F');
	
	/**
	 * Convert a byte array to an hexadecimal string equivalent
	 * 
	 * @param bytes the bytes array you want to convert
	*/
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray.get(v >>> 4);
	        hexChars[j * 2 + 1] = hexArray.get(v & 0x0F);
	    }
	    return new String(hexChars);
	}
	
	/**
	 * Convert an hexadecimal string to a byte array
	 * 
	 * @param s the hexadecimal string you want to convert
	 * 
	*/
	public static byte[] hexToBytes(String s) throws IllegalArgumentException {
		s = s.toUpperCase();
		
		if(s.length() % 2 != 0)
			throw new IllegalArgumentException("One of the byte is not complete.");
		
		for(Character character : s.toCharArray()) {
			if(!hexArray.contains(character))
				throw new IllegalArgumentException(character+" Is not valid");
		}
		
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	/**
	 * Compress a hash to 32 bytes and add an identifier to it
	 * 
	 * @param base the hash to addressify's hash
	 * @param identifier the byte array you want to add as identifier
	 */
	public static String Addressify(byte[] base, byte[] identifier) {
		
		byte[] sha_hash = Sha256.getHash(base).toBytes();
		byte[] ripemd_sha_hash = Ripemd160.getHash(sha_hash);
		
		byte[] hash_w_identifier = concatByteArrays(identifier,ripemd_sha_hash);
		
		byte[] checksum = Arrays.copyOf(Sha256.getDoubleHash(hash_w_identifier).toBytes(), 4);
		
		return Base58.encode(concatByteArrays(hash_w_identifier,checksum));
		
	}
	
	/**
	 * Concat bytes arrays
	 * 
	 * @param the byte arrays you want to concat
	 */
	public static byte[] concatByteArrays(byte[]... arrays) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		for(byte[] byte_array : arrays) {
			try {
				outputStream.write(byte_array);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return outputStream.toByteArray();
	}
	
	/**
	 * Convert decimal (bigint) to hexadecimal string
	 * 
	 * @param the bigint you want to convert
	 */
	public static String decToHex(BigInteger r) {
		String hex="";
		int rem = 0;
	    while(r.compareTo(BigInteger.ZERO) == 1){
	    	rem= r.mod(new BigInteger("16")).intValue(); 
	        hex=hexArray.get(rem)+hex; 
	        r=r.divide(new BigInteger("16"));
	    }
	    return hex;
	}
	
	/**
	 * Convert hexadecimal string to decimal (bigint)
	 * 
	 * @param the hex string you want to convert
	 * @throws NumberFormatException given string is not an hexadecimal representation
	 */
	public static BigInteger hexToDec(String s) throws NumberFormatException {
		return new BigInteger(s, 16);
	}
	
	private Converter() {} // Not instantiable
	
}
