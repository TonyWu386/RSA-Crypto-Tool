/*
 * File name: RSAsystem.java
 * Package name: rsasystem
 * Date created: 8/15/2015
 * Date last modified: 8/20/2015
 *
 * Author: Tony Wu (Xiangbo)
 * Email: xb.wu@mail.utoronto.ca
 *
 * JRE version: 1.8.0_51
 *
 * License: GNU GPL v2.0
 *
 * Copyright (c) 2015 [Tony Wu], All Right Reserved
 *
 * NOTICE:
 * While functional in use, this program is not built for serious
 * cryptography usage. Recommended for recreational or education purposes only.
 */

package rsasystem;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

/**
 * @author Tony Wu
 *
 */

public class RSAsystem {

	private static Random rng = new Random();
	private static boolean pass = false;

	/**
	 * @param bits the number of bit the generated keypair should be;
	 * this value must be powers of 2 and greater than 8
	 * @return an array with 1st element being the public key,
	 * second element being the exponent, and third element being
	 * the private key
	 */
	private static String[] keyGen(int bits) {
		//generate primes
		BigInteger p = BigInteger.probablePrime(bits/2, rng);
		BigInteger q = BigInteger.probablePrime(bits/2, rng);
		//generate public key
		BigInteger n = p.multiply(q);
		//begin generating private key
		BigInteger totient = ((p.subtract(new BigInteger("1"))).multiply(q.subtract(new BigInteger("1"))));
		BigInteger e = null;
		//ensure exponent is valid
		while (pass == false) {
			e = BigInteger.probablePrime(8, rng);
			if (totient.mod(e) != new BigInteger("0")) {
				pass = true;
			}
		}
		//finish generating private key
		BigInteger d = e.modInverse(totient);
		String[] retArray = {n.toString(),e.toString(),d.toString()};
		//done
		return retArray;
	}

	/**
	 * @param pubKey RSA public key of type BigInteger
	 * @param exp RSA exponent of type BigInteger
	 * @param msg text to be encrypted of type String
	 * @return the resulting ciphertext of type string
	 */
	private static String encrpyt(BigInteger pubKey, BigInteger exp, String msg) {
		return (new BigInteger(msg.getBytes())).modPow(exp, pubKey).toString();
	}

	/**
	 * @param pubKey RSA public key of type BigInteger
	 * @param priKey RSA private key of type BigInteger
	 * @param ctext ciphertext of type BigInteger
	 * @return the resulting unencrypted text of type string
	 */
	private static String decrpyt(BigInteger pubKey, BigInteger priKey, BigInteger ctext) {
		return new String (ctext.modPow(priKey, pubKey).toByteArray());
	}

	/**
	 * @param fileName name of file to write to
	 * @param holdArray array that holds keys
	 * @param bits number of bits of keypair
	 */
	private static void toFile(String fileName, String[] holdArray, int bits) {
		System.out.println("Saving keys to txt file...");
		PrintWriter writer;
		try {
			//create file
			writer = new PrintWriter(fileName, "UTF-8");
			//write to file
			writer.println("START OF " + bits + "-BIT RSA KEYPAIR");
			writer.println("---PUBLIC KEY:");
			writer.println(holdArray[0]);
			writer.println("---EXPONENT:");
			writer.println(holdArray[1]);
			writer.println("---PRIVATE KEY:");
			writer.println(holdArray[2]);
			writer.println("END OF " + bits + "-BIT RSA KEYPAIR");
			writer.close();
			System.out.println("Done.");
		} catch (FileNotFoundException e) {
			// FileNotFoundException
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// UnsupportedEncodingException
			e.printStackTrace();
		}
	}

	/**
	 * @param args
	 */

	public static void main(String[] args){

		Scanner in = new Scanner(System.in);

		int bits = 0;
		String strIn = "";

		while (!(strIn.equals("4"))) {
			//user input
			System.out.println("(1) generate, (2) encrypt, (3) decrypt, (4) exit");
			strIn = in.next();
			//response
			if (strIn.equals("1")) {
				//generate keys
				System.out.println("(1) 256-bit, (2) 512-bit, (3) 1024-bit, (4) 2048-bit");
				strIn = in.next();
				if (strIn.equals("1")) {
					bits = 256;
				} else if (strIn.equals("2")) {
					bits = 512;
				} else if (strIn.equals("3")) {
					bits = 1024;
				} else if (strIn.equals("4")) {
					bits = 2048;
				} else {
					System.out.println("Invalid input! Defaulting to 1024-bit");
					bits = 1024;
				}
				System.out.println("Enter full name of txt file you want to save keys to:");
				strIn = in.next();
				System.out.println("Generating keys...");
				String[] holdArray = keyGen(bits);
				RSAsystem.toFile(strIn, holdArray, bits);
			} else if (strIn.equals("2")) {
				//encryption
				System.out.println("Public key:");
				strIn = in.next();
				BigInteger pubKey = new BigInteger(strIn);
				System.out.println("Exponent:");
				strIn = in.next();
				BigInteger exp = new BigInteger(strIn);
				System.out.println("Message (no spaces):");
				strIn = in.next();
				System.out.println(RSAsystem.encrpyt(pubKey, exp, strIn));
			} else if (strIn.equals("3")){
				//decryption
				System.out.println("Public key:");
				strIn = in.next();
				BigInteger pubKey = new BigInteger(strIn);
				System.out.println("Private key:");
				strIn = in.next();
				BigInteger priKey = new BigInteger(strIn);
				System.out.println("Ciphertext:");
				strIn = in.next();
				BigInteger ctext = new BigInteger(strIn);
				System.out.println(RSAsystem.decrpyt(pubKey, priKey, ctext));
			} else if (!(strIn.equals("4"))) {
				System.out.println("Invalid command!");
			} else {
				System.out.println("Program exiting!");
			}
		}
		in.close();
	}
}
