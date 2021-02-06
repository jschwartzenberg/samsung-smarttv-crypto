package com.github.jschwartzenberg;

import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;

import com.google.common.io.BaseEncoding;

public class CalculateCtx {

	static final String AES = "AES";
	private static final String AES_CBC_NOPADDING = "AES/CBC/NoPadding";

	public static void main(String[] args)
			throws UnsupportedEncodingException, GeneralSecurityException {
		Map<String, byte[]> params = parseServerHello("010200000000000000008A000000063635343332313115AEB523ED4EA162135BE74B03589D9F11F6B996B0200A37A7A7CE830B218DB7302950FF419B0F345A462BAB6C3337100C89F382B3564A00F4C0CECC309CE5B9EA8C686CD5116D4D41B7D959E8F12A4B428D81E3EBBA9B007F3DB09C85F154705FE8F00C3AC1A9C4D60AA3700428C5FEEC2027DD75288E1E6B05D3521278A30000000000");

		String clientHello = "010100000000000000009E000000063635343332316C03518210862F7C401BFF6D82A540BE2E2D036D03B5BDF2624B553B04140B66F793B0AAE29CA16FBA5C78A899A77A0D48C9CA5CBAEE798FC68CFF843FEF91B1631E63F751B2313D9B31DB16C608134068B7DFB1FBD1098F915227795A7D1F60DF7481A017BD0E7D63DF84C7D74C6439A579D4AB0A800187791AD8B3EF97C72E8A31CDB038BD1FEB03DA9467EA878DD7AD2319910000000000";
		String gUserId = "654321";
		Map<String, byte[]> parseClientHello = Crypto.parseClientHello(clientHello, params.get("dataHash"), params.get("aesKey"), gUserId);
		System.err.println("ctx: " + BaseEncoding.base16().encode(parseClientHello.get("ctx")));
		System.err.println("SKPrime: " + BaseEncoding.base16().encode(parseClientHello.get("SKPrime")));
	}

	private static Map<String, byte[]> parseServerHello(String serverHello) throws UnsupportedEncodingException, GeneralSecurityException {
		ByteBuffer bb = ByteBuffer.wrap(BaseEncoding.base16().decode(serverHello));

		bb.position(7); // skip standard bytes

		int userIdLength1 = bb.getInt() - 132;
		int userIdLength2 = bb.getInt();
		System.err.println("userIdLength[1,2]: " + userIdLength1 + "," + userIdLength2);

		byte[] userIdBa = new byte[userIdLength2];
		bb.get(userIdBa, 0, userIdLength2);
		String userId = new String(userIdBa, "UTF8");
		System.err.println("userId: " + userId);

		byte[] encryptedPublicKeyWithPin = new byte[128];
		bb.get(encryptedPublicKeyWithPin, 0, Crypto.publicKey.length);
		byte[] aesKey = getAesKey(encryptedPublicKeyWithPin, Crypto.publicKey);

		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		byte[] dataBuffer = new byte[138];
		bb.get(7, dataBuffer, 0, dataBuffer.length);
		byte[] dataHash = sha1.digest(dataBuffer);

		Map<String, byte[]> retMap = new HashMap<>();
		retMap.put("aesKey", aesKey);
		retMap.put("dataHash", dataHash);
		return retMap;
	}

	private static byte[] getAesKey(byte[] encryptedPublicKeyWithPin, byte[] publicKey) throws UnsupportedEncodingException, GeneralSecurityException {
		for (int i = 0; i < 10000; i++) {
			MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
			String pin = String.format("%04d", i);
			byte[] pinHash = sha1.digest(pin.getBytes("UTF8"));
			byte[] aesKey = new byte[16];
			System.arraycopy(pinHash, 0, aesKey, 0, 16);

			Cipher cipher = Cipher.getInstance(AES_CBC_NOPADDING);
			cipher.init(ENCRYPT_MODE, new SecretKeySpec(aesKey, AES), new IvParameterSpec(new byte[Crypto.BLOCK_SIZE]));
			byte[] encrypted = cipher.doFinal(publicKey);
			byte[] swapped = Crypto.EncryptParameterDataWithAES(encrypted);
			if (Arrays.areEqual(encryptedPublicKeyWithPin, swapped)) {
				System.err.println("figuredOutPin: " + pin);
				return aesKey;
			}
		}
		throw new RuntimeException("PIN not found");
	}

}
