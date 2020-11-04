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

	/**
	 * Encrypts given data with given key and IV using AES/CTR/NoPadding
	 * 
	 * @param data the data to encrypt
	 * @param key the key to encrypt data with, if you want to encrypt using a short password simply use Sha256.getHash() on it
	 * @param iv the initialization vector for encryption, must remain the same for decryption
	 * 
	 * @return a byte array representing the encrypted data
	 * 
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 */
	//TODO: remove most throws ?
	public static byte[] encrypt(byte[] data, Sha256Hash key, byte[] iv) throws IllegalBlockSizeException, BadPaddingException,
	InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		
	    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

	    SecretKey K = new SecretKeySpec(key.toBytes(), "AES");
		
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");

        cipher.init(Cipher.ENCRYPT_MODE, K, new IvParameterSpec(iv));

        return cipher.doFinal(data);
        
	}
	
	/**
	 * Decrypts given data with given key and IV using AES/CTR/NoPadding
	 * 
	 * @param data the data to decrypt
	 * @param key the key to decrypt data with, if you want to decrypt using a short password simply use Sha256.getHash() on it
	 * @param iv the initialization vector used during encryption
	 * 
	 * @return a byte array representing the decrypted data
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	//TODO: remove most throws ?
	public static byte[] decrypt(byte[] data, Sha256Hash key, byte[] iv) throws NoSuchAlgorithmException, NoSuchProviderException,
	NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		SecretKey K = new SecretKeySpec(key.toBytes(), "AES");
		
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
		
        cipher.init(Cipher.DECRYPT_MODE, K, new IvParameterSpec(iv));

        return cipher.doFinal(data);
        
	}
	
}
