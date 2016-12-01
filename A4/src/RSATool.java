import java.io.*;
import java.math.*;
import java.security.*;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * This class provides an implementation of 1024-bit RSA-OAEP.
 *
 * @author Mike Jacobson
 * @version 1.0, October 23, 2013
 */
public class RSATool {

	// PrimeUtil
	private PrimeUtil primUtil = new PrimeUtil(256, false);
	// OAEP constants
	private final static int K = 128; // size of RSA modulus in bytes
	private final static int K0 = 16; // K0 in bytes
	private final static int K1 = 16; // K1 in bytes

	// RSA key data
	private BigInteger n;
	private BigInteger e, d, p, q;

	// TODO: add whatever additional variables that are required to implement
	// Chinese Remainder decryption as described in Problem 2
	private BigInteger d_p, d_q, x, y;
	private BigInteger totient_n;

	// SecureRandom for OAEP and key generation
	private SecureRandom rnd;

	private boolean debug = false;

	/**
	 * Utility for printing protocol messages
	 * 
	 * @param s
	 *            protocol message to be printed
	 */
	private void debug(String s) {
		if (debug)
			System.out.println("Debug RSA: " + s);
	}

	/**
	 * G(M) = 1st K-K0 bytes of successive applications of SHA1 to M
	 */
	private byte[] G(byte[] M) {
		MessageDigest sha1 = null;
		try {
			sha1 = MessageDigest.getInstance("SHA1");
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e);
			System.exit(1);
		}

		byte[] output = new byte[K - K0];
		byte[] input = M;

		int numBytes = 0;
		while (numBytes < K - K0) {
			byte[] hashval = sha1.digest(input);

			if (numBytes + 20 < K - K0)
				System.arraycopy(hashval, 0, output, numBytes, K0);
			else
				System.arraycopy(hashval, 0, output, numBytes, K - K0
						- numBytes);

			numBytes += 20;
			input = hashval;
		}

		return output;
	}

	/**
	 * H(M) = the 1st K0 bytes of SHA1(M)
	 */
	private byte[] H(byte[] M) {
		MessageDigest sha1 = null;
		try {
			sha1 = MessageDigest.getInstance("SHA1");
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e);
			System.exit(1);
		}

		byte[] hashval = sha1.digest(M);

		byte[] output = new byte[K0];
		System.arraycopy(hashval, 0, output, 0, K0);

		return output;
	}

	/**
	 * Construct instance for decryption. Generates both public and private key
	 * data.
	 *
	 * TODO: implement key generation for RSA as per the description in your
	 * write-up. Include whatever extra data is required to implement Chinese
	 * Remainder decryption as described in Problem 2.
	 */
	public RSATool(boolean setDebug) {
		// set the debug flag
		debug = setDebug;

		rnd = new SecureRandom();

		// TODO: include key generation implementation here (remove init of d)
		d = BigInteger.ONE;
		n = BigInteger.ONE;
		e = BigInteger.ONE;

		initializeValues();

	}

	/**
	 * Construct instance for encryption, with n and e supplied as parameters.
	 * No key generation is performed - assuming that only a public key is
	 * loaded for encryption.
	 */
	public RSATool(BigInteger new_n, BigInteger new_e, boolean setDebug) {
		// set the debug flag
		debug = setDebug;

		// initialize random number generator
		rnd = new SecureRandom();

		n = new_n;
		e = new_e;

		d = p = q = null;

		// TODO: initialize RSA decryption variables here		
		initializeValues();		
	}

	

	/**
	 * Encrypts the given byte array using RSA-OAEP.
	 *
	 * TODO: implement RSA encryption
	 *
	 * @param plaintext
	 *            byte array representing the plaintext
	 * @throw IllegalArgumentException if the plaintext is longer than K-K0-K1
	 *        bytes
	 * @return resulting ciphertext
	 */
	public byte[] encrypt(byte[] plaintext) {
		debug("In RSA encrypt");

		// make sure plaintext fits into one block
		if (plaintext.length > K - K0 - K1)
			throw new IllegalArgumentException(
					"plaintext longer than one block");

		// TODO: implement RSA-OAEP encryption here (replace following return
		
		//1 Generate a random K0-bit number r
		int KObits = BigInteger.valueOf(K0).bitLength();
		BigInteger r = new BigInteger(KObits,rnd);
				
		//2 Compute s = (M||0^K1) XOR G(r)
		byte[] G_r = G(r.toByteArray());
		int K1bits = BigInteger.valueOf(K1).bitLength();
		byte[] K1_zeros = new byte[K1bits];
		byte[] mAppend = new byte[plaintext.length + K1_zeros.length];
		byte[] s = new byte[mAppend.length];
		System.arraycopy(plaintext, 0, mAppend, 0, plaintext.length);
		System.out.println("Mappend: " + mAppend.length);
		System.out.println("G(r): " +G_r.length);
		
		//3 Compute t = r XOR H(s)
		//4 RSA-Encrypt (s||t) i.e. computer C = (s||t)^e (mod N)
		// statement)
		return plaintext;
	}

	/**
	 * Decrypts the given byte array using RSA.
	 *
	 * TODO: implement RSA-OAEP decryption using the Chinese Remainder method
	 * described in Problem 2
	 *
	 * @param ciphertext
	 *            byte array representing the ciphertext
	 * @throw IllegalArgumentException if the ciphertext is not valid
	 * @throw IllegalStateException if the class is not initialized for
	 *        decryption
	 * @return resulting plaintexttext
	 */
	public byte[] decrypt(byte[] ciphertext) {
		debug("In RSA decrypt");

		// make sure class is initialized for decryption
		if (d == null)
			throw new IllegalStateException(
					"RSA class not initialized for decryption");

		// TODO: implement RSA-OAEP encryption here (replace following return
		// statement)
		return ciphertext;
	}
	
	private void initializeValues() {
		p = set_p();
		q = set_q();
		n = set_n(p, q);
		totient_n = this.setTotient_N();
		e = set_e();
		d = e.modInverse(totient_n);
	}

	private BigInteger set_p() {
		this.p = PrimeUtil.getPrime();
		return p;
	}

	private BigInteger set_q() {
		this.q = PrimeUtil.getPrime();
		return q;
	}

	private BigInteger set_n(BigInteger p, BigInteger q) {
		this.n = p.multiply(q);
		return n;
	}

	private BigInteger setTotient_N() {
		BigInteger p_min1 = this.p.subtract(BigInteger.ONE);
		BigInteger q_min1 = this.q.subtract(BigInteger.ONE);

		this.totient_n = p_min1.multiply(q_min1);
		return this.totient_n;
	}

	public BigInteger getTotient_N() {
		return this.totient_n;
	}

	private BigInteger set_e() {
		int numBits = totient_n.bitCount();
		BigInteger likely_e = new BigInteger(numBits, rnd);
		BigInteger gcd = totient_n.gcd(likely_e);

		while (gcd.equals(BigInteger.ONE) == false) {
			likely_e = new BigInteger(numBits, rnd);
			gcd = totient_n.gcd(likely_e);
		}
		return likely_e;
	}

	public BigInteger get_n() {
		return n;
	}

	public BigInteger get_e() {
		return e;
	}
}
