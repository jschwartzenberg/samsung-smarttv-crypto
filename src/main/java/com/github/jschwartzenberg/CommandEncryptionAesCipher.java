package com.github.jschwartzenberg;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.io.BaseEncoding;

public class CommandEncryptionAesCipher {

	private static final String AES_ECB_NOPADDING = "AES/ECB/NoPadding";

	private SecretKeySpec key;
	private int sessionId;

	public CommandEncryptionAesCipher(byte[] key, int sessionId) {
		this.key = new SecretKeySpec(key, Crypto.AES);
		this.sessionId = sessionId;
	}

	byte[] encrypt(String input) throws GeneralSecurityException, UnsupportedEncodingException {
		System.err.println("input:                " + input);
		System.err.println("input.length():       " + input.length());
		String paddedInput = pad(input);
		System.err.println("paddedInput:          " + paddedInput);
		System.err.println("paddedInput.length(): " + paddedInput.length());
		System.err.println("input hex: " + BaseEncoding.base16().encode(input.getBytes("UTF8")));
		System.err.println("paddedInput hex: " + BaseEncoding.base16().encode(paddedInput.getBytes("UTF8")));
		Cipher cipher = Cipher.getInstance(AES_ECB_NOPADDING);
		cipher.init(ENCRYPT_MODE, key);
		return cipher.doFinal(paddedInput.getBytes("UTF8"));
	}

	byte[] decrypt(byte[] input) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(AES_ECB_NOPADDING);
		cipher.init(DECRYPT_MODE, key);
		return cipher.doFinal(input);
	}

	String pad(String input) throws UnsupportedEncodingException {
		int BLOCK_SIZE = 16;
		int padding = BLOCK_SIZE - input.length() % BLOCK_SIZE;
		ByteBuffer padText = ByteBuffer.allocate(padding);
		int i = padding;
		while (i-- > 0) {
			padText.put((byte) padding);
		}
		return input + new String(padText.array(), "UTF8");
	}

//	String unPad(String input) {
//		return input.substring(0, (int)Character.toChars(Integer.parseInt(input.substring(input.length() - 1)))[0]);
//	}

	String generate_command(String key_press) throws UnsupportedEncodingException, GeneralSecurityException {
		ByteBuffer command_bytes = ByteBuffer.wrap(this.encrypt(generate_json(key_press)));
		List<String> bytes = IntStream.generate(() -> Byte.toUnsignedInt(command_bytes.get()))
				.limit(command_bytes.remaining()).mapToObj(Integer::toString).collect(Collectors.toList());
		String int_array = String.join(",", bytes);
		System.err.println("int_array: " + int_array);
		checkIntArray(int_array);
		return "5::/com.samsung.companion:{\"name\":\"callCommon\",\"args\":[{\"Session_Id\":" + this.sessionId
				+ ",\"body\":\"[" + int_array + "]\"}]}";
	}

	private void checkIntArray(String int_array) throws GeneralSecurityException, UnsupportedEncodingException {
		String[] split = int_array.split(",");
		ByteBuffer ba = ByteBuffer.allocate(split.length);
		Arrays.stream(split).map(Integer::parseInt).forEach(i -> ba.put((byte) i.intValue()));
		String decrypted = new String(decrypt(ba.array()), "UTF8");
		System.err.println("decryped: " + decrypted);
	}

	String generate_json(String key_press) {
		return "{\"method\":\"POST\",\"body\":{\"plugin\":\"RemoteControl\",\"param1\":\"uuid:12345\",\"param2\":\"Click\",\"param3\":\""
				+ key_press + "\",\"param4\":false,\"api\":\"SendRemoteKey\",\"version\":\"1.000\"}}";
	}

}
