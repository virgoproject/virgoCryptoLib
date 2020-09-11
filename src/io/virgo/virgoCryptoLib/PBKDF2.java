package io.virgo.virgoCryptoLib;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;

public class PBKDF2 {

	 private static final DigestRandomGenerator generator = new DigestRandomGenerator(new SHA3Digest(512));
	
	 	//make this non instantiable
	    private PBKDF2() {}
	    
	    public static byte[] hash(String password, byte[] salt) {

	        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator();
	        generator.init(PBEParametersGenerator.PKCS5PasswordToBytes(
	        		password.toCharArray()),
	                salt,
	                256000);
	        
	        return ((KeyParameter) generator.generateDerivedParameters(256)).getKey();
	    }

	    public static byte[] generateSalt() {
	        byte[] salt = new byte[128];
	        generator.nextBytes(salt);
	        return salt;
	    }

}
