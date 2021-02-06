package com.github.jschwartzenberg;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import com.google.common.io.BaseEncoding;

public class Crypto {

	static final Charset UTF8 = Charset.forName("UTF8");
	public static final int BLOCK_SIZE = 16;
	public static final int SHA_DIGEST_LENGTH = 20;
	static final String AES = "AES";
	private static final String AES_CBC_NOPADDING = "AES/CBC/NoPadding";
	private static final String RIJNDAEL = "Rijndael";

	private static Properties keys = readPropertiesFile("keys.properties");
	private static SecretKeySpec wbKey = new SecretKeySpec(
			BaseEncoding.base16().decode(keys.getProperty("wbKey").toUpperCase()), AES);
	private static SecretKeySpec transKey = new SecretKeySpec(
			BaseEncoding.base16().decode(keys.getProperty("transKey").toUpperCase()), RIJNDAEL);
	static byte[] publicKey = BaseEncoding.base16().decode(keys.getProperty("publicKey").toUpperCase());

	public static Properties readPropertiesFile(String fileName) {
		try (InputStream is = Crypto.class.getResourceAsStream(fileName)) {
			Properties prop = new Properties();
			prop.load(is);
			return prop;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	static byte[] EncryptParameterDataWithAES(byte[] input) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(AES_CBC_NOPADDING);
		cipher.init(ENCRYPT_MODE, wbKey, new IvParameterSpec(new byte[BLOCK_SIZE]));
		ByteBuffer output = ByteBuffer.allocate(input.length);
		ByteBuffer wrapInput = ByteBuffer.wrap(input);
		while (wrapInput.hasRemaining()) {
			byte[] tmp = new byte[16];
			wrapInput.get(tmp, 0, 16);
			output.put(cipher.doFinal(tmp));
		}
		return output.array();
	}

	static byte[] DecryptParameterDataWithAES(byte[] input) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(AES_CBC_NOPADDING);
		cipher.init(DECRYPT_MODE, wbKey, new IvParameterSpec(new byte[BLOCK_SIZE]));
		ByteBuffer output = ByteBuffer.allocate(input.length);
		ByteBuffer wrapInput = ByteBuffer.wrap(input);
		while (wrapInput.hasRemaining()) {
			byte[] tmp = new byte[16];
			wrapInput.get(tmp, 0, 16);
			output.put(cipher.doFinal(tmp));
		}
		return output.array();
	}

	static byte[] applySamyGOKeyTransform(byte[] input) {
		RijndaelEngine rijndael = new RijndaelEngine();
		rijndael.init(true, new KeyParameter(BaseEncoding.base16().decode(keys.getProperty("transKey").toUpperCase())));
		byte[] output = new byte[input.length];
		rijndael.processBlock(input, 0, output, 0);
		return output;
	}

	static Map<String, byte[]> generateServerHello(String userId, String pin) throws GeneralSecurityException {
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		byte[] pinHash = sha1.digest(pin.getBytes(UTF8));
		byte[] aesKey = new byte[16];
		System.arraycopy(pinHash, 0, aesKey, 0, 16);
		System.err.println("AES key: " + BaseEncoding.base16().encode(aesKey));
		Cipher cipher = Cipher.getInstance(AES_CBC_NOPADDING);
		cipher.init(ENCRYPT_MODE, new SecretKeySpec(aesKey, AES), new IvParameterSpec(new byte[BLOCK_SIZE]));
		byte[] encrypted = cipher.doFinal(publicKey);
		System.err.println("AES encrypted: " + BaseEncoding.base16().encode(encrypted));
		byte[] swapped = EncryptParameterDataWithAES(encrypted);
		System.err.println("AES swapped: " + BaseEncoding.base16().encode(swapped));
		// convert length userId to big endian unsigned int +
		ByteBuffer data = ByteBuffer.allocate(138);
		data.putInt(userId.length());
		data.put(userId.getBytes(UTF8));
		data.put(swapped);
		byte[] dataBuffer = data.array();
		System.err.println("data buffer: " + BaseEncoding.base16().encode(dataBuffer));
		byte[] dataHash = sha1.digest(dataBuffer);
		System.err.println("hash: " + BaseEncoding.base16().encode(dataHash));
		ByteBuffer serverHello = ByteBuffer.allocate(168);
		serverHello.put((byte) 0x01).put((byte) 0x02);
		serverHello.put((byte) 0x00).put((byte) 0x00).put((byte) 0x00);
		serverHello.put((byte) 0x00).put((byte) 0x00);
		serverHello.putInt(userId.length() + 132);
		serverHello.put(dataBuffer);
		serverHello.put((byte) 0x00).put((byte) 0x00).put((byte) 0x00);
		serverHello.put((byte) 0x00).put((byte) 0x00);

		Map<String, byte[]> retMap = new HashMap<>();
		retMap.put("serverHello", serverHello.array());
		retMap.put("hash", dataHash);
		retMap.put("AES_key", aesKey);
		return retMap;
	}

	static Map<String, byte[]> parseClientHello(String clientHello, byte[] dataHash, byte[] aesKey, String gUserId)
			throws GeneralSecurityException {
		int USER_ID_POS = 15;
		int USER_ID_LEN_POS = 11;
		int GX_SIZE = 0x80;
		ByteBuffer data = ByteBuffer.wrap(BaseEncoding.base16().decode(clientHello.toUpperCase()));
		int firstLen = data.getInt(7);
		System.err.println("firstLen: " + firstLen);
		int userIdLen = data.getInt(11);
		System.err.println("userIdLen: " + userIdLen);
		int destLen = userIdLen + 132 + SHA_DIGEST_LENGTH; // # Always equals firstLen????:);
		System.err.println("destLen: " + destLen);
		int thirdLen = userIdLen + 132;
		System.err.println("thirdLen: " + thirdLen);
		System.err.println("hello: " + BaseEncoding.base16().encode(data.array()));
		byte[] dest = new byte[172];
		data.get(USER_ID_LEN_POS, dest, 0, thirdLen + USER_ID_LEN_POS);
		ByteBuffer.wrap(dest).put(dataHash);
		System.err.println("dest: " + BaseEncoding.base16().encode(dest));
		byte[] userId = new byte[userIdLen];
		data.get(USER_ID_POS, userId, 0, userIdLen);
		System.err.println("userId: " + new String(userId, UTF8));
		byte[] pEncWBGx = new byte[GX_SIZE];
		data.get(USER_ID_POS + userIdLen, pEncWBGx, 0, GX_SIZE);
		System.err.println("pEncWBGx: " + BaseEncoding.base16().encode(pEncWBGx));
		byte[] pEncGx = DecryptParameterDataWithAES(pEncWBGx);
		System.err.println("pEncGx: " + BaseEncoding.base16().encode(pEncGx));
		Cipher cipher = Cipher.getInstance(AES_CBC_NOPADDING);
		cipher.init(DECRYPT_MODE, new SecretKeySpec(aesKey, AES), new IvParameterSpec(new byte[BLOCK_SIZE]));
		byte[] pGx = cipher.doFinal(pEncGx);
		System.err.println("pGx: " + BaseEncoding.base16().encode(pGx));
		BigInteger bnPGx = new BigInteger(1, pGx);
		BigInteger bnPrime = new BigInteger(1, BaseEncoding.base16().decode(keys.getProperty("prime").toUpperCase()));
		System.err.println("bnPrime: " + bnPrime.toString());
		BigInteger bnPrivateKey = new BigInteger(1,
				BaseEncoding.base16().decode(keys.getProperty("privateKey").toUpperCase()));
		BigInteger secret = bnPGx.modPow(bnPrivateKey, bnPrime);
		byte[] dataHash2 = new byte[SHA_DIGEST_LENGTH];
		data.get(USER_ID_POS + userIdLen + GX_SIZE, dataHash2, 0, SHA_DIGEST_LENGTH);
		System.err.println("hash2: " + BaseEncoding.base16().encode(dataHash2));
		byte[] secretBA = secret.toByteArray();
		ByteBuffer secret2 = ByteBuffer.allocate(userId.length + secretBA.length).put(userId).put(secretBA);
		System.err.println("secret2: " + BaseEncoding.base16().encode(secret2.array()));
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		byte[] dataHash3 = sha1.digest(secret2.array());
		System.err.println("hash3: " + BaseEncoding.base16().encode(dataHash3));
		if (dataHash2.equals(dataHash3)) {
			System.err.println("Pin error!!!");
			throw new RuntimeException("Pin incorrect!");
		}
		System.err.println("Pin OK :)\n");
		int flagPos = userIdLen + USER_ID_POS + GX_SIZE + SHA_DIGEST_LENGTH;
		byte[] value = new byte[1];
		data.get(flagPos, value, 0, 1);
		byte[] value2 = new byte[4];
		data.get(flagPos, value2, 0, 4);
		System.err.println("value2[0]: " + value2[0]);
		System.err.println("value2[1]: " + value2[1]);
		System.err.println("value2[2]: " + value2[2]);
		System.err.println("value2[3]: " + value2[3]);
		byte[] dest_hash = sha1.digest(dest);
		System.err.println("dest_hash: " + BaseEncoding.base16().encode(dest_hash));
		byte[] gUserIdBa = gUserId.getBytes(UTF8);
		ByteBuffer finalBuffer = ByteBuffer
				.allocate(userId.length + gUserIdBa.length + pGx.length + publicKey.length + secretBA.length);
		finalBuffer.put(userId);
		finalBuffer.put(gUserIdBa);
		finalBuffer.put(pGx);
		finalBuffer.put(publicKey);
		finalBuffer.put(secretBA);
		byte[] SKPrime = sha1.digest(finalBuffer.array());
		System.err.println("SKPrime: " + BaseEncoding.base16().encode(SKPrime));
		ByteBuffer SKPrimeHash = ByteBuffer
				.wrap(sha1.digest(ByteBuffer.allocate(SKPrime.length + 1).put(SKPrime).put((byte) 0x00).array()));
		System.err.println("SKPrimeHash: " + BaseEncoding.base16().encode(SKPrimeHash.array()));
		byte[] SKPrimeHash16 = new byte[16];
		SKPrimeHash.get(0, SKPrimeHash16, 0, 16);
		byte[] ctx = applySamyGOKeyTransform(SKPrimeHash16);

		Map<String, byte[]> retMap = new HashMap<>();
		retMap.put("ctx", ctx);
		retMap.put("SKPrime", SKPrime);
		return retMap;
	}

	static String generateServerAcknowledge(byte[] SKPrime) throws GeneralSecurityException {
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		byte[] SKPrimeHash = sha1.digest(ByteBuffer.allocate(SKPrime.length + 1).put(SKPrime).put((byte) 0x01).array());
		return "0103000000000000000014" + BaseEncoding.base16().encode(SKPrimeHash).toUpperCase() + "0000000000";
	}

	static boolean parseClientAcknowledge(String clientAck, byte[] SKPrime) throws GeneralSecurityException {
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		byte[] SKPrimeHash = sha1.digest(ByteBuffer.allocate(SKPrime.length + 1).put(SKPrime).put((byte) 0x02).array());
		String tmpClientAck = "0104000000000000000014" + BaseEncoding.base16().encode(SKPrimeHash).toUpperCase()
				+ "0000000000";
		return clientAck.equals(tmpClientAck);
	}

}
