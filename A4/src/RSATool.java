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
	private PrimeUtil primUtil = new PrimeUtil(1024, false);
	// OAEP constants
	private final static int K = 128; // size of RSA modulus in bytes
	private final static int K0 = 16; // K0 in bytes
	private final static int K1 = 16; // K1 in bytes

	// RSA key data
	private BigInteger N;
	private int n;
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
		N = BigInteger.ONE;
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

		N = new_n;
		e = new_e;

		d = p = q = null;

		// TODO: initialize RSA decryption variables here		
		//initializeValues();		
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
		
		//debug("d: " + d);
		//debug("n: " + n);
		debug("N: " + N);
		debug("e: " + e);
		debug("\n");

		// make sure plaintext fits into one block
		if (plaintext.length > K - K0 - K1)
			throw new IllegalArgumentException(
					"plaintext longer than one block");

		// TODO: implement RSA-OAEP encryption here (replace following return		
		int N_Bits = N.toByteArray().length * 8;
		debug("N has "+N_Bits+" bits");
		
		//1 Generate a random K0-bit number r
		byte[] r = new byte[K0];
		rnd.nextBytes(r);
		
		debug("\n");
		debug("Outputting r in bytes: " + CryptoUtilities.toHexString(r));
		debug("\n");		
		//2 Compute s = (M||0^K1) XOR G(r)
		
		//set up G(r)
		byte[] G_r = G(r);
		
		//set up M||0^K1
		byte[] mAppend = new byte[plaintext.length + K1];
		System.arraycopy(plaintext, 0, mAppend, 0, plaintext.length);
		
		//Compute s = (M||0^K1) XOR G(r)
		byte[] s = new BigInteger(mAppend).xor(new BigInteger(G_r)).toByteArray();		
		debug("Encrypt s has :"+s.length*8 +" bits");
		////debug("n+ K1 = " + (n+K1));
		
		//3 Compute t = r xOr H(s)
		byte[] H_s = H(s);
		byte[] t = new BigInteger(r).xor(new BigInteger(H_s)).toByteArray();// xOr(r,H_s);
		
		//ToDO check and see if s||t > N, if so return to step 1, 
		//Determine how to implement this logic
		byte[] sAppend_t = new byte[s.length + t.length];		
		
		
		// Append t to s, ie create s||t
		System.arraycopy(s, 0, sAppend_t, 0, s.length);
		System.arraycopy(t, 0, sAppend_t, s.length, t.length);
		
		BigInteger sApp_t = new BigInteger(sAppend_t);
		if(sApp_t.compareTo(BigInteger.valueOf(0)) == -1){
			return encrypt(plaintext);
		}
		debug("\n");
		debug("Value of s||t: " + sApp_t);
		debug("Value of N: " + N);
		debug("\n");
		debug("Encrypt s||t has: " + sAppend_t.length*8 +" bits");
		debug("\n");
		debug("Pre-Encryption s||t : "+CryptoUtilities.toHexString(sAppend_t));
		
		//4 RSA-Encrypt (s||t) i.e. compute C = (s||t)^e (mod N)
		byte[] C = sApp_t.modPow(e, N).toByteArray();
		
		//just a check, remove from final version
		//byte[] C_prim = new BigInteger(C).modPow(d, N).toByteArray();
		
		//BigInteger modInvTest = e.multiply(d).mod(totient_n);
		debug("\n");
		//System.out.println("Mod Inverse Test: " + modInvTest);
		debug("\n");
		System.out.println("Mappend: " + mAppend.length);
		debug("\n");
		System.out.println("G(r): " +G_r.length);
		
		//debug("Encrypt C' has: " + C_prim.length*8 +" bits");
		debug("\n");
		
		// statement)
		debug("Encypted: " + CryptoUtilities.toHexString(C));
		debug("\n");
		//debug("\nC prime (C^d (mod N): " + CryptoUtilities.toHexString(C_prim));
		debug("\n");
		return C;
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
		debug("d: " + d);
		debug("n: " + n);
		debug("N: " + N);
		debug("e: " + e);
		debug("\n");
		
		BigInteger modInv = e.multiply(d).mod(totient_n);
		debug("mod inverse: " + modInv);
		debug("\n");
		
		debug("Pre-Decryption: " + CryptoUtilities.toHexString(ciphertext));

		// make sure class is initialized for decryption
		if (d == null)
			throw new IllegalStateException(
					"RSA class not initialized for decryption");

		// TODO: implement RSA-OAEP encryption here (replace following return
		// statement)
		
		//BigInteger C = new BigInteger(ciphertext);
		//BigInteger decSappT = C.modPow(d, N);
		//debug("\n");
		//debug("Cipher Text^d (mod N) as big int: "+decSappT);
		//debug("\n");
		//debug("Cipher Text as Big int: " + C);
		//debug("\n");
		byte[] testing = new BigInteger(ciphertext).modPow(d,N).toByteArray();// C.toByteArray();
		
		//debug("Ouputting Big Int C as bytes: " + CryptoUtilities.toHexString(testing));
		//Step1 compute s||t
		byte[] s_append_t = new BigInteger(ciphertext).modPow(d, N).toByteArray();
		//debug("Decrypt s||t has: "+s_append_t.length*8+"bits");
		
		debug("Ouputting C mod N as bytes: " + CryptoUtilities.toHexString(s_append_t));
		
		byte[] s = new byte[K-K0];
		
		byte[] t = new byte[K0];
		
		System.arraycopy(s_append_t, 0, s, 0,112);
		System.arraycopy(s_append_t, 112, t,0, K0);
		
		debug("\n");
		debug("Outputting s in bytes: " + CryptoUtilities.toHexString(s));
		
		debug("\n");
		debug("Outputting t in bytes: " + CryptoUtilities.toHexString(t));
		
		
		
		byte[] H_s = H(s);
		debug("\n");
		debug("Outputting H_s in bytes: " + CryptoUtilities.toHexString(H_s));
		byte[] u = new BigInteger(t).xor(new BigInteger(H_s)).toByteArray(); //xOr(t,H_s);
		byte[] G_u = G(u);
		debug("\n");
		debug("Outputting G_u in bytes: " + CryptoUtilities.toHexString(G_u));
		byte[] v = new BigInteger(s).xor(new BigInteger(G_u)).toByteArray();//xOr(s,G_u);
		debug("\n");
		debug("Outputting u in bytes: " + CryptoUtilities.toHexString(u));
		debug("\n");
		debug("Outputting v in bytes: " + CryptoUtilities.toHexString(v));
		System.out.println("WTF");
		debug("\n");
		//debug("\n");
		
		//do some logic here to check v
		return v;
	}	
	
	private void initializeValues() {
		p = set_p();
		q = set_q();
		//p = BigInteger.valueOf(11);
		//q = BigInteger.valueOf(2);
		N = set_N(p, q);
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

	private BigInteger set_N(BigInteger p, BigInteger q) {
		this.N = p.multiply(q);
		set_n(N.toByteArray());
		return N;
	}
	
	private void set_n(byte[] in){
		n = in.length*8;
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
		//BigInteger likely_e = BigInteger.valueOf(3);
		BigInteger gcd = totient_n.gcd(likely_e);

		while (gcd.equals(BigInteger.ONE) == false) {
			likely_e = new BigInteger(numBits, rnd);
			//likely_e = likely_e.add(BigInteger.valueOf(2));
			gcd = totient_n.gcd(likely_e);
		}
		return likely_e;
	}

	public BigInteger get_N() {
		return N;
	}

	public BigInteger get_e() {
		return e;
	}
}
