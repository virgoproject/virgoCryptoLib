package io.virgo.virgoCryptoLib;

import io.virgo.virgoCryptoLib.Exceptions.Base58FormatException;

public class Utils {

	/**
	 * Check if given String is a valid address for given prefix
	 * 
	 * @param hash The address to check
	 * @param prefix The prefix to match against
	 * @return true if address is valid, false otherwise
	 */
	public static boolean validateAddress(String hash, byte[] prefix) {
		try {
			byte[] decodedAddr = Base58.decodeChecked(hash);
			if(!byteArrayStartsWith(decodedAddr, 0, prefix))
				return false;
			return true;
		}catch(Base58FormatException e) {
			return false;
		}
	}
	
	/**
	 * Check if a bytes array starts with a given set of bytes
	 * 
	 * @param source The byte array to check from
	 * @param offset The number of bytes to skip before starting comparing
	 * @param desiredStart The byte array that must match with the start of source
	 * @return true if source byte array starts with desired one
	 */
	public static boolean byteArrayStartsWith(byte[] source, int offset, byte[] desiredStart) {

		if(desiredStart.length > (source.length - offset))
			return false;

		for(int i = 0; i < desiredStart.length; i++)
	    	if(source[offset + i] != desiredStart[i])
	    		return false;
	    
		return true;
	}
	
}
