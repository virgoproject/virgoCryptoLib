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

//Store the R and S components of an ECDSA signature under one object
public class ECDSASignature {
	
	
	private BigInteger R;
	private BigInteger S;
	
	
	public ECDSASignature(BigInteger R, BigInteger S) {
		this.R = R;
		this.S = S;
	}
	
	
	public BigInteger getR() {
		return R;
	}
	
	
	public BigInteger getS() {
		return S;
	}
	
	public String toHexString() {
		return Converter.bytesToHex(toByteArray());
	}
	
	public static ECDSASignature fromHexString(String hexString) throws IllegalArgumentException {
		byte[] byteFormat = Converter.hexToBytes(hexString);
		return fromByteArray(byteFormat);
	}
	
	public byte[] toByteArray() {
		byte[] rByte = new byte[33];
		System.arraycopy(R.toByteArray(), 0, rByte, 33-R.toByteArray().length, R.toByteArray().length);
		byte[] sByte = new byte[33];
		System.arraycopy(S.toByteArray(), 0, sByte, 33-S.toByteArray().length, S.toByteArray().length);
		
		return Converter.concatByteArrays(rByte, sByte);
	}
	
	public static ECDSASignature fromByteArray(byte[] array) throws IllegalArgumentException {
		if(array.length != 66) {
			throw new IllegalArgumentException("input must be 66 bytes long");
		}
		
		BigInteger r = new BigInteger(1,Arrays.copyOfRange(array, 0, 33));
		BigInteger s = new BigInteger(1,Arrays.copyOfRange(array, 34, 66));
		
		return new ECDSASignature(r,s);
	}
}