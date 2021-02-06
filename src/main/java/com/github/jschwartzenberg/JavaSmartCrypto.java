package com.github.jschwartzenberg;

import static java.net.http.HttpClient.Version.HTTP_1_1;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.http.WebSocket;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import com.google.common.io.BaseEncoding;

import jakarta.json.Json;
import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParser.Event;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;

public class JavaSmartCrypto {

	static HttpClient client = HttpClient.newHttpClient();

	static String UserId = "654321";
	static String AppId = "12345";
	static String deviceId = "7e509404-9d7c-46b4-8f6a-e2a9668ad184";
	static String tvIP = "192.168.27.125";
	static String tvPort = "8080";

	static int lastRequestId = 0;

	static String getFullUrl(String urlPath) {
		return "http://" + tvIP + ":" + tvPort + urlPath;
	}

	static String GetFullRequestUri(int step, String appId, String deviceId) {
		return getFullUrl("/ws/pairing?step=" + step + "&app_id=" + appId + "&device_id=" + deviceId);
	}

	static void ShowPinPageOnTv() throws IOException, InterruptedException {
		var request = HttpRequest.newBuilder(URI.create(getFullUrl("/ws/apps/CloudPINPage")))
				.POST(BodyPublishers.ofString("pin4")).build();
		client.send(request, BodyHandlers.discarding());
	}

	static boolean CheckPinPageOnTv() throws IOException, InterruptedException {
		String full_url = getFullUrl("/ws/apps/CloudPINPage");
		var request = HttpRequest.newBuilder(URI.create(full_url)).GET().build();
		var page = client.send(request, BodyHandlers.ofString());
		System.err.println(page.body());
		if (page.body().contains("stopped")) {
			return true;
		}
		return false;
	}

	static String FirstStepOfPairing() throws IOException, InterruptedException {
		String firstStepURL = GetFullRequestUri(0, AppId, deviceId) + "&type=1";
		var request = HttpRequest.newBuilder(URI.create(firstStepURL)).GET().build();
		return client.send(request, BodyHandlers.ofString()).body();
	}

	static void StartPairing() throws IOException, InterruptedException {
		if (CheckPinPageOnTv()) {
			System.err.println("Pin NOT on TV");
			ShowPinPageOnTv();
		} else {
			System.err.println("Pin ON TV");
		}
	}

	static Map<String, byte[]> HelloExchange(String pin)
			throws IOException, InterruptedException, GeneralSecurityException {
		Map<String, byte[]> hello_output = Crypto.generateServerHello(UserId, pin);
		String content = "{\"auth_Data\":{\"auth_type\":\"SPC\",\"GeneratorServerHello\":\""
				+ BaseEncoding.base16().encode(hello_output.get("serverHello")).toUpperCase() + "\"}}";
		String secondStepURL = GetFullRequestUri(1, AppId, deviceId);
		System.out.println("secondStepURL: " + secondStepURL);
		System.err.println("Sending content to TV: " + content);
		var request = HttpRequest.newBuilder(URI.create(secondStepURL)).POST(BodyPublishers.ofString(content)).build();
		HttpResponse<String> resp = client.send(request, BodyHandlers.ofString());
		if (resp.statusCode() == 400) {
			System.err.println("TV returned 400");
			System.exit(1);
		}
		String secondStepResponse = resp.body();
		System.out.println("secondStepResponse: " + secondStepResponse);
		final JsonParser parser = Json.createParser(new StringReader(secondStepResponse));
		Map<String, String> output = new HashMap<String, String>();
		while (parser.hasNext()) {
			final Event event = parser.next();
			switch (event) {
			case KEY_NAME:
				System.err.println("key: " + parser.getString());
				break;
			case VALUE_STRING:
				String subArray = parser.getString();
				System.err.println("val: " + subArray);
				String cut = subArray.substring(1, subArray.length() - 1);
				String[] split = cut.split(",");
				for (String s : split) {
					String[] split2 = s.split(":");
					output.put(split2[0].replace("\"", ""), split2[1].replace("\"", ""));
				}
				break;
			default:
				break;
			}
		}
		parser.close();
		String requestId = output.get("request_id");
		String clientHello = output.get("GeneratorClientHello");
		lastRequestId = Integer.parseInt(requestId);
		return Crypto.parseClientHello(clientHello, hello_output.get("hash"), hello_output.get("AES_key"), UserId);
	}

	static int AcknowledgeExchange(byte[] SKPrime) throws GeneralSecurityException, IOException, InterruptedException {
		String serverAckMessage = Crypto.generateServerAcknowledge(SKPrime);
		String content = "{\"auth_Data\":{\"auth_type\":\"SPC\",\"request_id\":\"" + lastRequestId
				+ "\",\"ServerAckMsg\":\"" + serverAckMessage + "\"}}";
		String thirdStepURL = GetFullRequestUri(2, AppId, deviceId);
		var request = HttpRequest.newBuilder(URI.create(thirdStepURL)).POST(BodyPublishers.ofString(content)).build();
		HttpResponse<String> resp = client.send(request, BodyHandlers.ofString());
		if (resp.statusCode() == 403) {
			System.err.println("TV returned 403");
			System.exit(1);
		}
		String thirdStepResponse = resp.body();
		if (thirdStepResponse.contains("secure-mode")) {
			System.err.println("TODO: Implement handling secondStepResponseof encryption flag!!!!");
			System.exit(-1);
		}
		System.err.println("thirdStepResponse: " + thirdStepResponse);
		Map<String, String> output = new HashMap<String, String>();
		final JsonParser parser = Json.createParser(new StringReader(thirdStepResponse));
		while (parser.hasNext()) {
			final Event event = parser.next();
			switch (event) {
			case KEY_NAME:
				System.err.println("key: " + parser.getString());
				break;
			case VALUE_STRING:
				String subArray = parser.getString();
				System.err.println("val: " + subArray);
				String cut = subArray.substring(1, subArray.length() - 1);
				String[] split = cut.split(",");
				for (String s : split) {
					String[] split2 = s.split(":");
					output.put(split2[0].replace("\"", ""), split2[1].replace("\"", ""));
				}
				break;
			default:
				break;
			}
		}
		parser.close();
		String clientAck = output.get("ClientAckMsg");
		if (!Crypto.parseClientAcknowledge(clientAck, SKPrime)) {
			System.err.println("Parse client ac message failed.");
			System.exit(-1);
		}
		int sessionId = Integer.parseInt(output.get("session_id"));
		System.out.print("sessionId: " + sessionId);
		return sessionId;
	}

	static void ClosePinPageOnTv() throws IOException, InterruptedException {
		String full_url = getFullUrl("/ws/apps/CloudPINPage/run");
		var request = HttpRequest.newBuilder(URI.create(full_url)).DELETE().build();
		client.send(request, BodyHandlers.discarding());
	}

	static void send_command(int currentSessionId, byte[] ctx, String key_command)
			throws InterruptedException, ExecutionException, GeneralSecurityException, IOException {
		long millis = System.currentTimeMillis();
		String step4_url = "http://" + tvIP + ":8000/socket.io/1/?t=" + millis;
		System.out.println("step4_url: " + step4_url);
		var request = HttpRequest.newBuilder(URI.create(step4_url)).version(HTTP_1_1).GET().build();
		HttpResponse<String> resp = client.send(request, BodyHandlers.ofString());
		System.err.println("step 4 response: " + resp.body());
		String websocket_url = "ws://" + tvIP + ":8000/socket.io/1/websocket/" + resp.body().split(":")[0];
		System.out.println("websocket_url: " + websocket_url);

		CommandEncryptionAesCipher aesLib = new CommandEncryptionAesCipher(ctx, currentSessionId);
		WebSocket.Listener listener = new WebSocket.Listener() {

		};
		CompletableFuture<WebSocket> connection = HttpClient.newBuilder().build().newWebSocketBuilder()
				.buildAsync(URI.create(websocket_url), listener);
		connection = connection.get().sendText("1::/com.samsung.companion", true);

		connection.get().sendText(aesLib.generate_command(key_command), true);
	}

	public static void main(String[] args)
			throws IOException, InterruptedException, GeneralSecurityException, ExecutionException {
		ArgumentParser parser = ArgumentParsers.newFor("Checksum").build().defaultHelp(true)
				.description("Calculate checksum of given files.");
		parser.addArgument("--sessionid");
		parser.addArgument("--ctx");
		int sessionId = -1;
		String ctxHex = null;
		try {
			Namespace ns = parser.parseArgs(args);
			String sessionidString = ns.get("sessionid");
			sessionId = sessionidString != null ? Integer.parseInt(sessionidString) : -1;
			ctxHex = ns.get("ctx");
		} catch (ArgumentParserException e) {
			parser.handleError(e);
			System.exit(1);
		}

		byte[] ctx;
		if (ctxHex == null) {
			StartPairing();
			System.out.println("Please enter pin from tv: ");
			String tvPIN = new Scanner(System.in).next();
			System.out.print("Got pin: '" + tvPIN + "'\n");
			FirstStepOfPairing();
			Map<String, byte[]> output = HelloExchange(tvPIN);
			if (output != null) {
				System.out.println("ctx: " + BaseEncoding.base16().encode(output.get("ctx")));
				System.out.println("Pin accepted :)\n");
			} else {
				System.err.println("Pin incorrect. Please try again...\n");
			}

			int currentSessionId = AcknowledgeExchange(output.get("SKPrime"));
			System.err.println("SessionID: " + currentSessionId);

			ClosePinPageOnTv();
			System.out.println("Authorization successfull :)\n");

			ctx = output.get("ctx");
			sessionId = currentSessionId;
		} else {
			ctx = BaseEncoding.base16().decode(ctxHex.toUpperCase());
		}

		System.out.println("Attempting to send command to tv");
		send_command(sessionId, ctx, "KEY_CHUP");
	}

}
