package io.virgo.virgoCryptoLib;

import java.math.BigInteger;
import java.util.Arrays;

/*
 * Copyright (c) 2018 Virgo.
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

/**
 * Stores the R and S components of an ECDSA signature under one object
 */
public class ECDSASignature {
	
	
	private BigInteger R;
	private BigInteger S;
	
	
	public ECDSASignature(BigInteger R, BigInteger S) {
		this.R = R;
		this.S = S;
	}
	
	/**
	 * @return The R component of the ECDSA signature
	 */
	public BigInteger getR() {
		return R;
	}
	
	/**
	 * @return The S component of the ECDSA signature
	 */
	public BigInteger getS() {
		return S;
	}
	
	/**
	 * @return A String of the hexadecimal representation of the signature
	 */
	public String toHexString() {
		return Converter.bytesToHex(toByteArray());
	}
	
	/**
	 * Creates an ECDSASignature object from an hexadecimal representation
	 * 
	 * @param hexString A String of the hexadecimal representation of the signature
	 * @return The equivalent ECDSASignature object
	 * @throws IllegalArgumentException If the hexadecimal representation is invalid
	 */
	public static ECDSASignature fromHexString(String hexString) throws IllegalArgumentException {
		byte[] byteFormat = Converter.hexToBytes(hexString);
		return fromByteArray(byteFormat);
	}
	
	/**
	 * @return A byte array representing the signature, first 33 bytes represents the R component,
	 * the 33 last the S one
	 */
	public byte[] toByteArray() {
		byte[] rByte = new byte[33];
		System.arraycopy(R.toByteArray(), 0, rByte, 33-R.toByteArray().length, R.toByteArray().length);
		byte[] sByte = new byte[33];
		System.arraycopy(S.toByteArray(), 0, sByte, 33-S.toByteArray().length, S.toByteArray().length);
		
		return Converter.concatByteArrays(rByte, sByte);
	}
	
	/**
	 * Creates an ECDSASignature object from a byte array representation
	 * @param array The array representing the signature
	 * @return The equivalent ECDSASignature object
	 * @throws IllegalArgumentException If the given byte array represents an invalid signature
	 */
	public static ECDSASignature fromByteArray(byte[] array) throws IllegalArgumentException {
		if(array.length != 66) {
			throw new IllegalArgumentException("input must be 66 bytes long");
		}
		
		BigInteger r = new BigInteger(1,Arrays.copyOfRange(array, 0, 33));
		BigInteger s = new BigInteger(1,Arrays.copyOfRange(array, 34, 66));
		
		return new ECDSASignature(r,s);
	}
}