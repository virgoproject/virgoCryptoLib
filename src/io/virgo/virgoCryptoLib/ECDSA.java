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

/*
 * Copyright (c) 2018 Virgo.
 * Copyright (c) 2000 - 2011 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

public class ECDSA {

	ECDomainParameters DOMAIN;
	
	
	public ECDSA() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256k1");
		DOMAIN = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN());
	}
	
	
	public ECDSASignature Sign(Sha256Hash hash, byte[] privateKey) {
		
		BigInteger privateKey_integer = new BigInteger(1,privateKey);
		
		ECPrivateKeyParameters privateKey_parameters = new ECPrivateKeyParameters(privateKey_integer, DOMAIN);
		
		ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
		signer.init(true, privateKey_parameters);
		BigInteger[] components = signer.generateSignature(hash.toBytes());
		
		return new ECDSASignature(components[0],components[1]);
	}
	
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
	
	
	public static byte[] getPublicKey(byte[] privateKey) {
		  try {
		    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
		    return spec.getG().multiply(new BigInteger(1, privateKey)).getEncoded(true);
		  } catch (Exception e) {
			  throw new IllegalArgumentException("Invalid private key");
		  }
	}
	
	/**
	 * Randomly generate a new valid private key
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
