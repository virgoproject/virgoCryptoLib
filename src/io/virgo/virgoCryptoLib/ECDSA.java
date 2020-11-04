package io.virgo.virgoCryptoLib;

import java.math.BigInteger;
import java.security.Security;
import java.util.Random;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;


/**
 * Utility to sign and verify hashes with ECDSA secp256k1
 * Also contains functions to generate private keys and derivate public keys from them
 * 
 * <p>
 * To sign and verify:<br><br>
 * {@code ECDSA signer = new ECDSA();}<br>
 * {@code ECDSASignature signature = signer.Sign(hash, privateKey);}<br>
 * {@code boolean isPublicKeyMatching = signer.Verify(hash, signature, publicKey)}
 * </p>
 * <p>
 * To generate a privateKey and derivate publicKey from it:<br><br>
 * {@code byte[] privateKey = ECDSA.generatePrivateKey();}<br>
 * {@code byte[] publicKey = ECDSA.getPublicKey(privateKey);}
 * </p>
 */
public class ECDSA {

	ECDomainParameters DOMAIN;
	
	
	public ECDSA() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
		DOMAIN = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN());
	}
	
	/**
	 * Signs a hash with given private key using ECDSA secp256k1
	 * 
	 * @param hash The hash to sign, typically the Sha256 hash of a message
	 * @param privateKey The private key to sign with
	 * 
	 * @return An object representing the resulting signature
	 */
	public ECDSASignature Sign(Sha256Hash hash, byte[] privateKey) {
		
		BigInteger privateKey_integer = new BigInteger(1,privateKey);
		
		ECPrivateKeyParameters privateKey_parameters = new ECPrivateKeyParameters(privateKey_integer, DOMAIN);
		
		ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
		signer.init(true, privateKey_parameters);
		BigInteger[] components = signer.generateSignature(hash.toBytes());
		
		return new ECDSASignature(components[0],components[1]);
	}
	
	/**
	 * Check if a signature corresponds to given hash and public key
	 * 
	 * @param hash The sha256Hash of the original message
	 * @param signature The signature to check
	 * @param publicKey The public key derivated from the privateKey used to generate the signature
	 * 
	 * @return true if everything corresponds, false otherwise
	 */
	public boolean Verify(Sha256Hash hash, ECDSASignature signature, byte[] publicKey) {
		ECPublicKeyParameters publicKey_parameters = new ECPublicKeyParameters(DOMAIN.getCurve().decodePoint(publicKey), DOMAIN);
		
		ECDSASigner signer = new ECDSASigner();
		signer.init(false, publicKey_parameters);
        try {
        	
            return signer.verifySignature(hash.toBytes(), signature.getR(), signature.getS());
            
        } catch (NullPointerException e) {//resolve bouncy castle NPE bug when signature is invalid
        	return false;
        }
        
	}
	
	/**
	 * Derivates a publicKey from a given private key
	 * 
	 * @param privateKey the private key to derivate from
	 * @return The resulting public key
	 */
	public static byte[] getPublicKey(byte[] privateKey) {
		  try {
		    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
		    return spec.getG().multiply(new BigInteger(1, privateKey)).getEncoded(true);
		  } catch (Exception e) {
			  throw new IllegalArgumentException("Invalid private key");
		  }
	}
	
	/**
	 * Randomly generate a new valid secp256k1 private key
	 * 
	 * @return the generated private key
	 */
	public static byte[] generatePrivateKey() {
		BigInteger key;
		BigInteger maxVal = new BigInteger("115792089237316195423570985008687907852837564279074904382605163141518161494336");//max valid private key value for ECDSA secp256k1
		
		do {//generate random bigInteger while value > maxValue to avoid invalid private key
			key = new BigInteger(256, new Random());
		} while(key.compareTo(maxVal) > 0);
		
		return key.toByteArray();
	}
}
