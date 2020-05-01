package io.virgo.virgoCryptoLib;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {

	public static byte[] encrypt(byte[] data, Sha256Hash key, byte[] iv) throws IllegalBlockSizeException, BadPaddingException,
	InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		
	    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

	    SecretKey K = new SecretKeySpec(key.toBytes(), "AES");
		
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");

        cipher.init(Cipher.ENCRYPT_MODE, K, new IvParameterSpec(iv));

        return cipher.doFinal(data);
        
	}
	
	public static byte[] decrypt(byte[] data, Sha256Hash key, byte[] iv) throws NoSuchAlgorithmException, NoSuchProviderException,
	NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		SecretKey K = new SecretKeySpec(key.toBytes(), "AES");
		
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
		
        cipher.init(Cipher.DECRYPT_MODE, K, new IvParameterSpec(iv));

        return cipher.doFinal(data);
        
	}
	
}
