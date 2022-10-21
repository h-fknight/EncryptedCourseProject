/*************************************************************************
	> File Name: Des.cpp
	> Author: SongLee
	> E-mail: lisong.shine@qq.com
	> Created Time: 2014��06��01�� ������ 19ʱ46��32��
	> Personal Blog: http://songlee24.github.com
 ************************************************************************/

#include <iostream>
#include <fstream>
#include <bitset>
#include <string>
#include "DES.h"
using namespace std;



/**********************************************************************/
/*                                                                    */
/*                            ������DES�㷨ʵ��                         */
/*                                                                    */
/**********************************************************************/

/**
 *  ���뺯��f������32λ���ݺ�48λ����Կ������һ��32λ�����
 */
bitset<32> f(bitset<32> R, bitset<48> k)
{
	bitset<48> expandR;
	// ��һ������չ�û���32 -> 48
	for (int i = 0; i < 48; ++i)
		expandR[47 - i] = R[32 - E[i]];
	// �ڶ��������
	expandR = expandR ^ k;
	// ������������S_BOX�û���
	bitset<32> output;
	int x = 0;
	for (int i = 0; i < 48; i = i + 6)
	{
		int row = expandR[47 - i] * 2 + expandR[47 - i - 5];
		int col = expandR[47 - i - 1] * 8 + expandR[47 - i - 2] * 4 + expandR[47 - i - 3] * 2 + expandR[47 - i - 4];
		int num = S_BOX[i / 6][row][col];
		bitset<4> binary(num);
		output[31 - x] = binary[3];
		output[31 - x - 1] = binary[2];
		output[31 - x - 2] = binary[1];
		output[31 - x - 3] = binary[0];
		x += 4;
	}
	// ���Ĳ���P-�û���32 -> 32
	bitset<32> tmp = output;
	for (int i = 0; i < 32; ++i)
		output[31 - i] = tmp[32 - P[i]];
	return output;
}

/**
 *  ��56λ��Կ��ǰ�󲿷ֽ�������
 */
bitset<28> leftShift(bitset<28> k, int shift)
{
	bitset<28> tmp = k;
	for (int i = 27; i >= 0; --i)
	{
		if (i - shift < 0)
			k[i] = tmp[i - shift + 28];
		else
			k[i] = tmp[i - shift];
	}
	return k;
}

/**
 *  ����16��48λ������Կ
 */
void generateKeys()
{
	bitset<56> realKey;
	bitset<28> left;
	bitset<28> right;
	bitset<48> compressKey;
	// ȥ����ż���λ����64λ��Կ���56λ
	for (int i = 0; i < 56; ++i)
		realKey[55 - i] = key[64 - PC_1[i]];
	// ��������Կ�������� subKeys[16] ��
	for (int round = 0; round < 16; ++round)
	{
		// ǰ28λ���28λ
		for (int i = 28; i < 56; ++i)
			left[i - 28] = realKey[i];
		for (int i = 0; i < 28; ++i)
			right[i] = realKey[i];
		// ����
		left = leftShift(left, shiftBits[round]);
		right = leftShift(right, shiftBits[round]);
		// ѹ���û�����56λ�õ�48λ����Կ
		for (int i = 28; i < 56; ++i)
			realKey[i] = left[i - 28];
		for (int i = 0; i < 28; ++i)
			realKey[i] = right[i];
		for (int i = 0; i < 48; ++i)
			compressKey[47 - i] = realKey[56 - PC_2[i]];
		subKey[round] = compressKey;
	}
}

/**
 *  ���ߺ�������char�ַ�����תΪ������
 */
bitset<64> charToBitset(const char s[8])
{
	bitset<64> bits;
	for (int i = 0; i < 8; ++i)
		for (int j = 0; j < 8; ++j)
			bits[i * 8 + j] = ((s[i] >> j) & 1);
	return bits;
}

/**
 *  DES����
 */
bitset<64> encrypt(bitset<64>& plain)
{
	bitset<64> cipher;
	bitset<64> currentBits;
	bitset<32> left;
	bitset<32> right;
	bitset<32> newLeft;
	// ��һ������ʼ�û�IP
	for (int i = 0; i < 64; ++i)
		currentBits[63 - i] = plain[64 - IP[i]];
	// �ڶ�������ȡ Li �� Ri
	for (int i = 32; i < 64; ++i)
		left[i - 32] = currentBits[i];
	for (int i = 0; i < 32; ++i)
		right[i] = currentBits[i];
	// ����������16�ֵ���
	for (int round = 0; round < 16; ++round)
	{
		newLeft = right;
		right = left ^ f(right, subKey[round]);
		left = newLeft;
	}
	// ���Ĳ����ϲ�L16��R16��ע��ϲ�Ϊ R16L16
	for (int i = 0; i < 32; ++i)
		cipher[i] = left[i];
	for (int i = 32; i < 64; ++i)
		cipher[i] = right[i - 32];
	// ���岽����β�û�IP-1
	currentBits = cipher;
	for (int i = 0; i < 64; ++i)
		cipher[63 - i] = currentBits[64 - IP_1[i]];
	// ��������
	return cipher;
}

/**
 *  DES����
 */
bitset<64> decrypt(bitset<64>& cipher)
{
	bitset<64> plain;
	bitset<64> currentBits;
	bitset<32> left;
	bitset<32> right;
	bitset<32> newLeft;
	// ��һ������ʼ�û�IP
	for (int i = 0; i < 64; ++i)
		currentBits[63 - i] = cipher[64 - IP[i]];
	// �ڶ�������ȡ Li �� Ri
	for (int i = 32; i < 64; ++i)
		left[i - 32] = currentBits[i];
	for (int i = 0; i < 32; ++i)
		right[i] = currentBits[i];
	// ����������16�ֵ���������Կ����Ӧ�ã�
	for (int round = 0; round < 16; ++round)
	{
		newLeft = right;
		right = left ^ f(right, subKey[15 - round]);
		left = newLeft;
	}
	// ���Ĳ����ϲ�L16��R16��ע��ϲ�Ϊ R16L16
	for (int i = 0; i < 32; ++i)
		plain[i] = left[i];
	for (int i = 32; i < 64; ++i)
		plain[i] = right[i - 32];
	// ���岽����β�û�IP-1
	currentBits = plain;
	for (int i = 0; i < 64; ++i)
		plain[63 - i] = currentBits[64 - IP_1[i]];
	// ��������
	return plain;
}


/**********************************************************************/
/* ���ԣ�                                                             */
/*     1.��һ�� 64 λ���ַ������ܣ� ������д���ļ� a.txt                  */
/*     2.��ȡ�ļ� a.txt ��� 64 λ���ģ�����֮����д�� b.txt              */
/**********************************************************************/

//int main() {
//	string s = "romantic";
//	string k = "12345678";
//	bitset<64> plain = charToBitset(s.c_str());
//	key = charToBitset(k.c_str());
//	// ����16������Կ
//	generateKeys();
//	// ����д�� a.txt
//	bitset<64> cipher = encrypt(plain);
//	fstream file1;
//	file1.open("D://a.txt", ios::binary | ios::out);
//	file1.write((char*)&cipher, sizeof(cipher));
//	file1.close();
//
//	// ���ļ� a.txt
//	bitset<64> temp;
//	file1.open("D://a.txt", ios::binary | ios::in);
//	file1.read((char*)&temp, sizeof(temp));
//	file1.close();
//
//	// ���ܣ���д���ļ� b.txt
//	bitset<64> temp_plain = decrypt(temp);
//	file1.open("D://b.txt", ios::binary | ios::out);
//	file1.write((char*)&temp_plain, sizeof(temp_plain));
//	file1.close();
//
//	return 0;
//}


//int main() {
//	string k = "12345678";
//	key = charToBitset(k.c_str());
//	generateKeys();   // ����16������Կ
//
//	// ���ļ� flower.jpg ���ܵ� cipher.txt ��
//	ifstream in;
//	ofstream out;
//	in.open("D://flower.jpg", ios::binary);
//	out.open("D://cipher.dat", ios::binary);
//	bitset<64> plain;
//	while (in.read((char*)&plain, sizeof(plain)))
//	{
//		bitset<64> cipher = encrypt(plain);
//		out.write((char*)&cipher, sizeof(cipher));
//		plain.reset();  // ��0
//	}
//	in.close();
//	out.close();
//
//	// ���� cipher.txt����д��ͼƬ flower1.jpg
//	in.open("D://cipher.dat", ios::binary);
//	out.open("D://flower1.jpg", ios::binary);
//	
//	while (in.read((char*)&plain, sizeof(plain)))
//	{
//		bitset<64> temp = decrypt(plain);
//		out.write((char*)&temp, sizeof(temp));
//		plain.reset();  // ��0
//	}
//	in.close();
//	out.close();
//
//	return 0;
//}

