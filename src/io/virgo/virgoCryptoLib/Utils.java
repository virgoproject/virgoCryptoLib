package io.virgo.virgoCryptoLib;

import io.virgo.virgoCryptoLib.Exceptions.Base58FormatException;

public class Utils {

	/**
	 * Check if given hash is a valid address for given prefix
	 * 
	 * @param hash
	 * @param prefix
	 * @return
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
	
	public static boolean byteArrayStartsWith(byte[] source, int offset, byte[] match) {

		if(match.length > (source.length - offset))
			return false;

		for(int i = 0; i < match.length; i++)
	    	if(source[offset + i] != match[i])
	    		return false;
	    
		return true;
	}
	
}
