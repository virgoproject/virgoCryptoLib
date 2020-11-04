package io.virgo.virgoCryptoLib;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;

/**
 * Utility to generate PBKDF2 hashes
 */
public class PBKDF2 {

	 private static final DigestRandomGenerator generator = new DigestRandomGenerator(new SHA3Digest(512));
	
	 	//make this non instantiable
	    private PBKDF2() {}
	    
	    /**
	     * Hashes given String using PBKDF2 and given salt
	     * @param password The String to hash
	     * @param salt The salt to use
	     * @return The resulting hash as a byte array
	     */
	    public static byte[] hash(String password, byte[] salt) {

	        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator();
	        generator.init(PBEParametersGenerator.PKCS5PasswordToBytes(
	        		password.toCharArray()),
	                salt,
	                256000);
	        
	        return ((KeyParameter) generator.generateDerivedParameters(256)).getKey();
	    }

	    /**
	     * Safely generate random salt
	     * 
	     * @return the generated salt as a byte array
	     */
	    public static byte[] generateSalt() {
	        byte[] salt = new byte[128];
	        generator.nextBytes(salt);
	        return salt;
	    }

}
