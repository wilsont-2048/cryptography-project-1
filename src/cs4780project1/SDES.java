package cs4780project1;

import java.util.*;

public class SDES {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		System.out.println("=================================== SDES Program ==================================");
		
		byte rawkey[][] = new byte[4][];
		byte plaintext[][] = new byte[4][];
		byte ciphertext[][] = new byte[4][];
		
		rawkey[0] = new byte[] {0,0,0,0,0,0,0,0,0,0};
		rawkey[1] = new byte[] {1,1,1,1,1,1,1,1,1,1};
		rawkey[2] = new byte[] {0,0,0,0,0,1,1,1,1,1};
		rawkey[3] = new byte[] {0,0,0,0,0,1,1,1,1,1};
		
		plaintext[0] = new byte[] {0,0,0,0,0,0,0,0};
		plaintext[1] = new byte[] {1,1,1,1,1,1,1,1};
		plaintext[2] = new byte[] {0,0,0,0,0,0,0,0};
		plaintext[3] = new byte[] {1,1,1,1,1,1,1,1};
	
		System.out.println("\n------------------------------------ Encryption -----------------------------------");
	
		System.out.println("Raw Key				 Plaintext		    Ciphertext");
		
		for(int i = 0; i < 4; i++) {
			ciphertext[i] = Encrypt(rawkey[i], plaintext[i]);
			System.out.println(Arrays.toString(rawkey[i]) + "   " + Arrays.toString(plaintext[i]) + "   " + Arrays.toString(ciphertext[i]));
		}
		
		rawkey[0] = new byte[] {1,0,0,0,1,0,1,1,1,0};
		rawkey[1] = new byte[] {1,0,0,0,1,0,1,1,1,0};
		rawkey[2] = new byte[] {0,0,1,0,0,1,1,1,1,1};
		rawkey[3] = new byte[] {0,0,1,0,0,1,1,1,1,1};
		
		ciphertext[0] = new byte[] {0,0,0,1,1,1,0,0};
		ciphertext[1] = new byte[] {1,1,0,0,0,0,1,0};
		ciphertext[2] = new byte[] {1,0,0,1,1,1,0,1};
		ciphertext[3] = new byte[] {1,0,0,1,0,0,0,0};
		
		System.out.println("\n------------------------------------ Decryption -----------------------------------");
		
		System.out.println("Raw Key				 Plaintext		    Ciphertext");
		
		for(int i = 0; i < 4; i++) {
			plaintext[i] = Decrypt(rawkey[i], ciphertext[i]);
			System.out.println(Arrays.toString(rawkey[i]) + "   " + Arrays.toString(plaintext[i]) + "   " + Arrays.toString(ciphertext[i]));
		}
		
		System.out.println("\n================================ Program Terminated ===============================");
	}
		
	private static byte[] Decrypt(byte[] rawkey, byte[] ciphertext) {
		// TODO Auto-generated method stub
		byte[] msgLeft = new byte [4];
		byte[] msgRight = new byte [4];
		
		ciphertext = pIP(ciphertext);
		
		msgLeft[0] = ciphertext[0];
		msgLeft[1] = ciphertext[1];
		msgLeft[2] = ciphertext[2];
		msgLeft[3] = ciphertext[3];
		
		msgRight[0] = ciphertext[4];
		msgRight[1] = ciphertext[5];
		msgRight[2] = ciphertext[6];
		msgRight[3] = ciphertext[7];
		
		byte[] p10key = P10(rawkey);
		byte[] keyLS1 = keyLS1(p10key);
		byte[] subKey1 = P8(keyLS1);

		byte[] keyLS2 = keyLS2(keyLS1);
		byte[] subKey2 = P8(keyLS2);
		
		byte[] firstfK = fK(msgLeft, msgRight, subKey2);
		
		byte[] switchedfI = SW(firstfK);
		
		msgLeft[0] = switchedfI[0];
		msgLeft[1] = switchedfI[1];
		msgLeft[2] = switchedfI[2];
		msgLeft[3] = switchedfI[3];
		
		msgRight[0] = switchedfI[4];
		msgRight[1] = switchedfI[5];
		msgRight[2] = switchedfI[6];
		msgRight[3] = switchedfI[7];
		
		byte[] plaintext = fK(msgLeft, msgRight, subKey1);
		
		plaintext = invpIP(plaintext);
		
		return plaintext;
	}

	private static byte[] Encrypt(byte[] rawkey, byte[] plaintext) {
		// TODO Auto-generated method stub	
		byte[] p10key = P10(rawkey);
		byte[] keyLS1 = keyLS1(p10key);
		byte[] subKey1 = P8(keyLS1);

		byte[] keyLS2 = keyLS2(keyLS1);
		byte[] subKey2 = P8(keyLS2);
		
		byte[] msgLeft = new byte [4];
		byte[] msgRight = new byte [4];
		
		plaintext = pIP(plaintext);
		
		msgLeft[0] = plaintext[0];
		msgLeft[1] = plaintext[1];
		msgLeft[2] = plaintext[2];
		msgLeft[3] = plaintext[3];
		
		msgRight[0] = plaintext[4];
		msgRight[1] = plaintext[5];
		msgRight[2] = plaintext[6];
		msgRight[3] = plaintext[7];
		
		byte[] firstfK = fK(msgLeft, msgRight, subKey1);
		
		byte[] switchedfI = SW(firstfK);
		
		msgLeft[0] = switchedfI[0];
		msgLeft[1] = switchedfI[1];
		msgLeft[2] = switchedfI[2];
		msgLeft[3] = switchedfI[3];
		
		msgRight[0] = switchedfI[4];
		msgRight[1] = switchedfI[5];
		msgRight[2] = switchedfI[6];
		msgRight[3] = switchedfI[7];
		
		byte[] ciphertext = fK(msgLeft, msgRight, subKey2);
		
		ciphertext = invpIP(ciphertext);
		
		return ciphertext;
		
	}

	private static byte[] SW(byte[] key) {
		// TODO Auto-generated method stub
		byte[] result = new byte[8];
		
		result[0] = key[4];
		result[1] = key[5];
		result[2] = key[6];
		result[3] = key[7];
		result[4] = key[0];
		result[5] = key[1];
		result[6] = key[2];
		result[7] = key[3];
		
		return result;
	}

	private static byte[] fK(byte[] msgLeft, byte[] msgRight, byte[] sk) {
		// TODO Auto-generated method stub
		byte[] mapRes = new byte[4];
		byte[] result = new byte[8];
		
		mapRes = mappingF(msgRight, sk);
		
		result[0] = (byte) (msgLeft[0] ^ mapRes[0]);
		result[1] = (byte) (msgLeft[1] ^ mapRes[1]);
		result[2] = (byte) (msgLeft[2] ^ mapRes[2]);
		result[3] = (byte) (msgLeft[3] ^ mapRes[3]);
		result[4] = msgRight[0];
		result[5] = msgRight[1];
		result[6] = msgRight[2];
		result[7] = msgRight[3];
				
		return result;
	}

	private static byte[] mappingF(byte[] msgRight, byte[] sk) {
		// TODO Auto-generated method stub
		byte[] eP = new byte[8];
		
		eP[0] = msgRight[3];
		eP[1] = msgRight[0];
		eP[2] = msgRight[1];
		eP[3] = msgRight[2];
		eP[4] = msgRight[1];
		eP[5] = msgRight[2];
		eP[6] = msgRight[3];
		eP[7] = msgRight[0];
		
		eP[0] = (byte) (eP[0] ^ sk[0]);
		eP[1] = (byte) (eP[1] ^ sk[1]);
		eP[2] = (byte) (eP[2] ^ sk[2]);
		eP[3] = (byte) (eP[3] ^ sk[3]);
		eP[4] = (byte) (eP[4] ^ sk[4]);
		eP[5] = (byte) (eP[5] ^ sk[5]);
		eP[6] = (byte) (eP[6] ^ sk[6]);
		eP[7] = (byte) (eP[7] ^ sk[7]);
		
		// S-Boxes
		int[][] s0 = {{1,0,3,2}, {3,2,1,0}, {0,2,1,3}, {3,1,3,2}};
		int[][] s1 = {{0,1,2,3}, {2,0,1,3}, {3,0,1,0}, {2,1,0,3}};
		
		// S-Boxes Operations, first half bits.
		byte b11 = eP[0];
		byte b12 = eP[1];
		byte b13 = eP[2];
		byte b14 = eP[3];
		
		int row1 = BinaryToDecimal(b11,b14);
		int col1 = BinaryToDecimal(b12,b13);
		
		// Indexing
		int index1 = s0[row1][col1];
		byte[] result1 = DecimalToBinary(index1);
		
		// S-Boxes Operations, second half bits.
		byte b21 = eP[4];
		byte b22 = eP[5];
		byte b23 = eP[6];
		byte b24 = eP[7];
		
		int row2 = BinaryToDecimal(b21,b24);
		int col2 = BinaryToDecimal(b22,b23);
		
		// Indexing
		int index2 = s1[row2][col2];
		byte[] result2 = DecimalToBinary(index2);
		
		byte[] output = new byte[4];
		output[0] = (byte) result1[0];
		output[1] = (byte) result1[1];
		output[2] = (byte) result2[0];
		output[3] = (byte) result2[1];
		
		byte[] resultP4 = P4(output);
		
		return resultP4;
	}

	private static byte[] P4(byte[] output) {
		// TODO Auto-generated method stub
		byte[] result = new byte[4];
		
		result[0] = output[1];
		result[1] = output[3];
		result[2] = output[2];
		result[3] = output[0];
		
		return result;
	}

	private static byte[] DecimalToBinary(int num) {
		// TODO Auto-generated method stub
		if(num == 0) {
			byte[] binNum = new byte[2];
			binNum[0] = 0;
			binNum[1] = 0;
			return binNum;
		}
		
		byte[] binNum = new byte[10];
		
		int count = 0;
		while (num > 0) {
			binNum[count] = (byte) (num % 2);
			num = num / 2;
			count++;
		}
		
		byte[] binNum2 = new byte[count];
		
		for(int i=count-1, j=0; i>=0 && j<count; i--, j++) {
			binNum2[j] = binNum[i];
		}
		
		if(count < 2) {
			binNum = new byte[2];
			binNum[0] = 0;
			binNum[1] = binNum2[0];
			return binNum;
		}
		
		return binNum2;
		
	}

	private static int BinaryToDecimal(byte...bits) {
		// TODO Auto-generated method stub
		int result = 0;
		int base = 1;
		
		for(int i=bits.length-1; i>=0; i--) {
			result = result + (bits[i]*base);
			base = base * 2;
		}
		
		return result;
	}

	private static byte[] invpIP(byte[] msg) {
		// TODO Auto-generated method stub
		byte[] invipkey = new byte[8];
		
		invipkey[0] = msg[3];
		invipkey[1] = msg[0];
		invipkey[2] = msg[2];
		invipkey[3] = msg[4];
		invipkey[4] = msg[6];
		invipkey[5] = msg[1];
		invipkey[6] = msg[7];
		invipkey[7] = msg[5];
		
		return invipkey;
	}

	private static byte[] pIP(byte[] msg) {
		// TODO Auto-generated method stub
		byte[] ipkey = new byte[8];
		
		ipkey[0] = msg[1];
		ipkey[1] = msg[5];
		ipkey[2] = msg[2];
		ipkey[3] = msg[0];
		ipkey[4] = msg[3];
		ipkey[5] = msg[7];
		ipkey[6] = msg[4];
		ipkey[7] = msg[6];
		
		return ipkey;
	}

	private static byte[] keyLS2(byte[] keyLS1) {
		// TODO Auto-generated method stub
		byte[] keyLS2 = new byte[10];
		
		keyLS2[0] = keyLS1[2];
		keyLS2[1] = keyLS1[3];
		keyLS2[2] = keyLS1[4];
		keyLS2[3] = keyLS1[0];
		keyLS2[4] = keyLS1[1];
		keyLS2[5] = keyLS1[7];
		keyLS2[6] = keyLS1[8];
		keyLS2[7] = keyLS1[9];
		keyLS2[8] = keyLS1[5];
		keyLS2[9] = keyLS1[6];
		
		return keyLS2;
	}

	private static byte[] P8(byte[] keyLS) {
		// TODO Auto-generated method stub
		byte[] p8key = new byte[8];
		
		p8key[0] = keyLS[5];
		p8key[1] = keyLS[2];
		p8key[2] = keyLS[6];
		p8key[3] = keyLS[3];
		p8key[4] = keyLS[7];
		p8key[5] = keyLS[4];
		p8key[6] = keyLS[9];
		p8key[7] = keyLS[8];
		
		return p8key;
	}

	private static byte[] keyLS1(byte[] p10key) {
		// TODO Auto-generated method stub
		byte[] keyLS1 = new byte[10];
		
		keyLS1[0] = p10key[1];
		keyLS1[1] = p10key[2];
		keyLS1[2] = p10key[3];
		keyLS1[3] = p10key[4];
		keyLS1[4] = p10key[0];
		keyLS1[5] = p10key[6];
		keyLS1[6] = p10key[7];
		keyLS1[7] = p10key[8];
		keyLS1[8] = p10key[9];
		keyLS1[9] = p10key[5];
		
		return keyLS1;
	}

	private static byte[] P10(byte[] key) {
		// TODO Auto-generated method stub
		byte[] p10Key = new byte[10];

		p10Key[0] = key[2];
	    p10Key[1] = key[4];
	    p10Key[2] = key[1];
	    p10Key[3] = key[6];
	    p10Key[4] = key[3];
	    p10Key[5] = key[9];
	    p10Key[6] = key[0];
	    p10Key[7] = key[8];
	    p10Key[8] = key[7];
	    p10Key[9] = key[5];
	    
	    return p10Key;
	}
		
}
