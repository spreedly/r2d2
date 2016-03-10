This file contains test data obtained from AndroidPay decryption code.
The values were used to confirm the steps of the processs were completing correctly.
This represents all needed info to confirm each step of the decryption process.

Note: for the HDFK step, the keying material is the ephemeral public key + the shared secret


```
{
"ephemeralPublicKey":"BPhVspn70Zj2Kkgu9t8+ApEuUWsI/zos5whGCQBlgOkuYagOis7qsrcbQrcprjvTZO3XOU+Qbcc28FSgsRtcgQE=",
"encryptedMessage":"PHxZxBQvVWwP",
"tag":"s9wa3Q2WiyGi/eDA4XYVklq08KZiSxB7xvRiKK3H7kE="
}
```
```
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAj0rha+IkiGkKa443IRz8g7tjVxXtLwwaE6T5GGivXXoAoGCCqGSM49
AwEHoUQDQgAE52hc/70CrjvdKcbCDclTVqI2mx328faiCerg+0O2UsZrcqPxM9/6
NpA0/INKSHclSGJLQrKuuVaECA1kodgXZg==
-----END EC PRIVATE KEY-----
```

Keys include the byte array first, then the hex underneath

encryptionKey

```
[16, 79, 44, -105, -90, -108, -104, -111, 8, 18, -18, -101, 121, 100, -109, 98]
104F2C97A69498910812EE9B79649362
```

macKey

```
[-28, -1, 49, -64, 121, -124, -9, 98, -89, 11, -22, 96, -37, -118, -47, 28]
E4FF31C07984F762A70BEA60DB8AD11C
```

sharedKey

```
[16, 79, 44, -105, -90, -108, -104, -111, 8, 18, -18, -101, 121, 100, -109, 98, -28, -1, 49, -64, 121, -124, -9, 98, -89, 11, -22, 96, -37, -118, -47, 28]
104F2C97A69498910812EE9B79649362E4FF31C07984F762A70BEA60DB8AD11C
```

Java class for decryption

```
import org.bouncycastle.crypto.digests.SHA256Digest;

import org.bouncycastle.crypto.generators.HKDFBytesGenerator;

import org.bouncycastle.crypto.params.HKDFParameters;

import org.bouncycastle.jce.ECNamedCurveTable;

import org.bouncycastle.jce.ECPointUtil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import org.bouncycastle.util.encoders.Base64;

import org.bouncycastle.util.encoders.Hex;

import org.json.JSONException;

import org.json.JSONObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;

import java.security.InvalidAlgorithmParameterException;

import java.security.InvalidKeyException;

import java.security.KeyFactory;

import java.security.NoSuchAlgorithmException;

import java.security.NoSuchProviderException;

import java.security.PrivateKey;

import java.security.PublicKey;

import java.security.Security;

import java.security.spec.ECParameterSpec;

import java.security.spec.ECPublicKeySpec;

import java.security.spec.InvalidKeySpecException;

import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;

import javax.crypto.Cipher;

import javax.crypto.IllegalBlockSizeException;

import javax.crypto.KeyAgreement;

import javax.crypto.Mac;

import javax.crypto.NoSuchPaddingException;

import javax.crypto.spec.IvParameterSpec;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/** Utility for decrypting encrypted network tokens as per Android Pay InApp

spec. */

class NetworkTokenDecryptionUtil {

	private static final String SECURITY_PROVIDER = "BC";

	private static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

	private static final String ASYMMETRIC_KEY_TYPE = "EC";

	private static final String KEY_AGREEMENT_ALGORITHM = "ECDH";

	/** OpenSSL name of the NIST P­126 Elliptic Curve */

	private static final String EC_CURVE = "prime256v1";

	private static final String SYMMETRIC_KEY_TYPE = "AES";

	private static final String SYMMETRIC_ALGORITHM = "AES/CTR/NoPadding";

	private static final byte[] SYMMETRIC_IV = Hex.decode("00000000000000000000000000000000");

	private static final int SYMMETRIC_KEY_BYTE_COUNT = 16;

	private static final String MAC_ALGORITHM = "HmacSHA256";

	private static final int MAC_KEY_BYTE_COUNT = 16;

	private static final byte[] HKDF_INFO = "Android".getBytes(DEFAULT_CHARSET);

	private static final byte[] HKDF_SALT = null /* equivalent to a zeroed salt of hashLen */;

	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

	private PrivateKey privateKey;

	private NetworkTokenDecryptionUtil(PrivateKey privateKey) {

		if (!ASYMMETRIC_KEY_TYPE.equals(privateKey.getAlgorithm())) {

			throw new IllegalArgumentException("Unexpected type of private key");

		}

		this.privateKey = privateKey;

	}

	public static NetworkTokenDecryptionUtil createFromPkcs8EncodedPrivateKey(byte[] pkcs8PrivateKey) {

		PrivateKey privateKey = null;

		try {

			KeyFactory asymmetricKeyFactory = KeyFactory.getInstance(ASYMMETRIC_KEY_TYPE, SECURITY_PROVIDER);

			privateKey = asymmetricKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8PrivateKey));
//			System.out.println("Private key");
//			System.out.println(privateKey);
//			JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(System.out));
//			writer.writeObject(privateKey);
//			writer.close();

		} catch (NoSuchAlgorithmException | NoSuchProviderException |

			InvalidKeySpecException e) {

			throw new RuntimeException("Failed to create NetworkTokenDecryptionUtil", e);

		}

		return new NetworkTokenDecryptionUtil(privateKey);

	}

	/**

	* Sets up the {@link #SECURITY_PROVIDER} if not yet set up.

	*

	* <p>You must call this method at least once before using this class.

	*/

	public static void setupSecurityProviderIfNecessary() {

		if (Security.getProvider(SECURITY_PROVIDER) == null) {

			Security.addProvider(new BouncyCastleProvider());

		}

	}

	/**

	* Verifies then decrypts the given payload according to the Android Pay

	Network Token

	* encryption spec.

	*/

	public String verifyThenDecrypt(String encryptedPayloadJson) {

		try {

			JSONObject object = new JSONObject(encryptedPayloadJson);

			byte[] ephemeralPublicKeyBytes = Base64.decode(object.getString("ephemeralPublicKey"));
			System.out.println("ephemeralPublicKey");
			System.out.println(object.getString("ephemeralPublicKey"));
			System.out.println("encryptedMessage");
			System.out.println(object.getString("encryptedMessage"));
			System.out.println("tag");
			System.out.println(object.getString("tag"));
			byte[] encryptedMessage = Base64.decode(object.getString("encryptedMessage"));

			byte[] tag = Base64.decode(object.getString("tag"));

			// Parsing public key.

			ECParameterSpec asymmetricKeyParams = generateECParameterSpec();

			KeyFactory asymmetricKeyFactory = KeyFactory.getInstance(ASYMMETRIC_KEY_TYPE, SECURITY_PROVIDER);

			PublicKey ephemeralPublicKey = asymmetricKeyFactory.generatePublic(new ECPublicKeySpec( ECPointUtil.decodePoint(asymmetricKeyParams.getCurve(), ephemeralPublicKeyBytes), asymmetricKeyParams));

			// Deriving shared secret.

			KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM,SECURITY_PROVIDER);

			keyAgreement.init(privateKey);

			keyAgreement.doPhase(ephemeralPublicKey, true);

			byte[] sharedSecret = keyAgreement.generateSecret();
			System.out.println("Shared Secret Byte Array");
			System.out.println(Arrays.toString(sharedSecret));
			char[] hexChars = new char[sharedSecret.length * 2];
		    for ( int j = 0; j < sharedSecret.length; j++ ) {
		        int v = sharedSecret[j] & 0xFF;
		        hexChars[j * 2] = hexArray[v >>> 4];
		        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		    }
			System.out.println("Shared Secret Hex Array");
			System.out.println(hexChars);


			// Deriving encryption and mac keys.

			HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(new SHA256Digest());

			byte[] khdfInput = ByteUtils.concatenate(ephemeralPublicKeyBytes, sharedSecret);

			hkdfBytesGenerator.init(new HKDFParameters(khdfInput, HKDF_SALT, HKDF_INFO));
			byte[] sharedKey = new byte[SYMMETRIC_KEY_BYTE_COUNT * 2];
			hkdfBytesGenerator.generateBytes(sharedKey, 0, SYMMETRIC_KEY_BYTE_COUNT*2);
			System.out.println("sharedKey");
			System.out.println(Arrays.toString(sharedKey));
			char[] sharedChars = new char[sharedKey.length * 2];
		    for ( int j = 0; j < sharedKey.length; j++ ) {
		        int v = sharedKey[j] & 0xFF;
		        sharedChars[j * 2] = hexArray[v >>> 4];
		        sharedChars[j * 2 + 1] = hexArray[v & 0x0F];
		    }
			System.out.println(sharedChars);

			byte[] encryptionKey = new byte[SYMMETRIC_KEY_BYTE_COUNT];

			hkdfBytesGenerator.generateBytes(encryptionKey, 0, SYMMETRIC_KEY_BYTE_COUNT);
			System.out.println("encryptionKey");
			System.out.println(Arrays.toString(encryptionKey));
			char[] encryptChars = new char[encryptionKey.length * 2];
		    for ( int j = 0; j < encryptionKey.length; j++ ) {
		        int v = encryptionKey[j] & 0xFF;
		        encryptChars[j * 2] = hexArray[v >>> 4];
		        encryptChars[j * 2 + 1] = hexArray[v & 0x0F];
		    }
			System.out.println(encryptChars);

			byte[] macKey = new byte[MAC_KEY_BYTE_COUNT];
			hkdfBytesGenerator.generateBytes(macKey, 0, MAC_KEY_BYTE_COUNT);
			System.out.println("macKey");
			System.out.println(Arrays.toString(macKey));
			char[] macChars = new char[macKey.length * 2];
		    for ( int j = 0; j < macKey.length; j++ ) {
		        int v = macKey[j] & 0xFF;
		        macChars[j * 2] = hexArray[v >>> 4];
		        macChars[j * 2 + 1] = hexArray[v & 0x0F];
		    }
			System.out.println(macChars);



			// Verifying Message Authentication Code (aka mac/tag)

			Mac macGenerator = Mac.getInstance(MAC_ALGORITHM, SECURITY_PROVIDER);

			macGenerator.init(new SecretKeySpec(macKey, MAC_ALGORITHM));

			byte[] expectedTag = macGenerator.doFinal(encryptedMessage);

			if (!isArrayEqual(tag, expectedTag)) {

				throw new RuntimeException("Bad Message Authentication Code!");

			}

			// Decrypting the message.

			Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);

			cipher.init( Cipher.DECRYPT_MODE, new SecretKeySpec(encryptionKey, SYMMETRIC_KEY_TYPE), new IvParameterSpec(SYMMETRIC_IV));

			return new String(cipher.doFinal(encryptedMessage), DEFAULT_CHARSET);

		} catch (JSONException | NoSuchAlgorithmException |NoSuchProviderException| InvalidKeySpecException | InvalidKeyException |NoSuchPaddingException

			| InvalidAlgorithmParameterException | IllegalBlockSizeException |BadPaddingException e) {

				throw new RuntimeException("Failed verifying/decrypting message", e);

		}

	}

	private ECNamedCurveSpec generateECParameterSpec() {

		ECNamedCurveParameterSpec bcParams =ECNamedCurveTable.getParameterSpec(EC_CURVE);

		ECNamedCurveSpec params = new ECNamedCurveSpec(bcParams.getName(),bcParams.getCurve(),bcParams.getG(), bcParams.getN(), bcParams.getH(),bcParams.getSeed());

		return params;

	}

	/**

	* Fixed­timing array comparison.

	*/

	public static boolean isArrayEqual(byte[] a, byte[] b) {

		if (a.length != b.length) {

			return false;

		}

		int result = 0;

		for (int i = 0; i < a.length; i++) {

			result |= a[i] ^ b[i];

		}

		return result == 0;

		}

}
```

Java Test class

```
import static org.junit.Assert.assertEquals;import static org.junit.Assert.fail;

import com.google.common.io.BaseEncoding;

import org.bouncycastle.util.encoders.Base64;

import org.json.JSONObject;

import org.junit.Before;

import org.junit.Test;

import org.junit.runner.RunWith;

import org.junit.runners.JUnit4;

/** Unit tests for {@link NetworkTokenDecryptionUtil}. */

@RunWith(JUnit4.class)

public class NetworkTokenDecryptionUtilTest {

	/**

	* Created with:

	* <pre>

	* openssl pkcs8 ­topk8 ­inform PEM ­outform PEM ­in merchant­key.pem ­nocrypt

	* </pre>

	*/

	private static final String MERCHANT_PRIVATE_KEY_PKCS8_BASE64 =
		"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjj" +

		"chHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx" +

		"9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm";

	private static final String ENCRYPTED_PAYLOAD = "{"

		+ "\"encryptedMessage\":\"PHxZxBQvVWwP\","

		+ "\"ephemeralPublicKey\":\"BPhVspn70Zj2Kkgu9t8+ApEuUWsI\\/zos5whGCQBlgOkuYagOis7qsrcbQrcpr"

		+ "jvTZO3XOU+Qbcc28FSgsRtcgQE=\","

		+ "\"tag\":\"TNwa3Q2WiyGi\\/eDA4XYVklq08KZiSxB7xvRiKK3H7kE=\"}";

	private NetworkTokenDecryptionUtil util;

	@Before
	public void setUp() {

		NetworkTokenDecryptionUtil.setupSecurityProviderIfNecessary();
		System.out.println("Merchant private key array");
		System.out.println(MERCHANT_PRIVATE_KEY_PKCS8_BASE64);

		util = NetworkTokenDecryptionUtil.createFromPkcs8EncodedPrivateKey( BaseEncoding.base64().decode(MERCHANT_PRIVATE_KEY_PKCS8_BASE64));

	}

	@Test
	public void testShouldDecrypt() {

		assertEquals("plaintext", util.verifyThenDecrypt(ENCRYPTED_PAYLOAD));

	}

	@Test
	public void testShouldFailIfBadTag() throws Exception {

		JSONObject payload = new JSONObject(ENCRYPTED_PAYLOAD);

		byte[] tag = Base64.decode(payload.getString("tag"));
		// Messing with the first byte

		tag[0] = (byte) ~tag[0];

		payload.put("tag", new String(Base64.encode(tag)));

		try {

			util.verifyThenDecrypt(payload.toString());

			fail();

		} catch (RuntimeException e) {

			assertEquals("Bad Message Authentication Code!", e.getMessage());

		}
	}

		@Test

	public void testShouldFailIfEncryptedMessageWasChanged() throws Exception {

		JSONObject payload = new JSONObject(ENCRYPTED_PAYLOAD);

		byte[] encryptedMessage =

		Base64.decode(payload.getString("encryptedMessage"));

		// Messing with the first byte

		encryptedMessage[0] = (byte) ~encryptedMessage[0];

		payload.put("encryptedMessage", new

		String(Base64.encode(encryptedMessage)));

		try {

			util.verifyThenDecrypt(payload.toString());

			fail();

		} catch (RuntimeException e) {

			assertEquals("Bad Message Authentication Code!", e.getMessage());

		}
	}
}
```




