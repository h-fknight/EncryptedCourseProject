#include "pch.h"
#include <iostream>
#include <bitset>
#include <string>
#include <fstream>
#include "AES.h"
using namespace std;

/**********************************************************************/
/*                                                                    */
/*                              AES�㷨ʵ��                           */
/*                                                                    */
/**********************************************************************/

/******************************�����Ǽ��ܵı任����**********************/
/**
 *  S�б任 - ǰ4λΪ�кţ���4λΪ�к�
 */
void SubBytes(bitset<8> mtx[4 * 4])
{
	for (int i = 0; i < 16; ++i)
	{
		int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];
		int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
		mtx[i] = S_Box[row][col];
	}
}

/**
 *  �б任 - ���ֽ�ѭ����λ
 */
void ShiftRows(bitset<8> mtx[4 * 4])
{
	// �ڶ���ѭ������һλ
	bitset<8> temp = mtx[4];
	for (int i = 0; i < 3; ++i)
		mtx[i + 4] = mtx[i + 5];
	mtx[7] = temp;
	// ������ѭ��������λ
	for (int i = 0; i < 2; ++i)
	{
		temp = mtx[i + 8];
		mtx[i + 8] = mtx[i + 10];
		mtx[i + 10] = temp;
	}
	// ������ѭ��������λ
	temp = mtx[15];
	for (int i = 3; i > 0; --i)
		mtx[i + 12] = mtx[i + 11];
	mtx[12] = temp;
}

/**
 *  �������ϵĳ˷� GF(2^8)
 */
bitset<8> GFMul(bitset<8> a, bitset<8> b) {
	bitset<8> p = 0;
	bitset<8> hi_bit_set;
	for (int counter = 0; counter < 8; counter++) {
		if ((b & bitset<8>(1)) != 0) {
			p ^= a;
		}
		hi_bit_set = (bitset<8>)(a & bitset<8>(0x80));
		a <<= 1;
		if (hi_bit_set != 0) {
			a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
		}
		b >>= 1;
	}
	return p;
}

/**
 *  �б任
 */
void MixColumns(bitset<8> mtx[4 * 4])
{
	bitset<8> arr[4];
	for (int i = 0; i < 4; ++i)
	{
		for (int j = 0; j < 4; ++j)
			arr[j] = mtx[i + j * 4];

		mtx[i] = GFMul(0x02, arr[0]) ^ GFMul(0x03, arr[1]) ^ arr[2] ^ arr[3];
		mtx[i + 4] = arr[0] ^ GFMul(0x02, arr[1]) ^ GFMul(0x03, arr[2]) ^ arr[3];
		mtx[i + 8] = arr[0] ^ arr[1] ^ GFMul(0x02, arr[2]) ^ GFMul(0x03, arr[3]);
		mtx[i + 12] = GFMul(0x03, arr[0]) ^ arr[1] ^ arr[2] ^ GFMul(0x02, arr[3]);
	}
}

/**
 *  ����Կ�ӱ任 - ��ÿһ������չ��Կ�������
 */
void AddRoundKey(bitset<8> mtx[4 * 4], bitset<32> k[4])
{
	for (int i = 0; i < 4; ++i)
	{
		bitset<32> k1 = k[i] >> 24;
		bitset<32> k2 = (k[i] << 8) >> 24;
		bitset<32> k3 = (k[i] << 16) >> 24;
		bitset<32> k4 = (k[i] << 24) >> 24;

		mtx[i] = mtx[i] ^ bitset<8>(k1.to_ulong());
		mtx[i + 4] = mtx[i + 4] ^ bitset<8>(k2.to_ulong());
		mtx[i + 8] = mtx[i + 8] ^ bitset<8>(k3.to_ulong());
		mtx[i + 12] = mtx[i + 12] ^ bitset<8>(k4.to_ulong());
	}
}

/**************************�����ǽ��ܵ���任����***********************/
/**
 *  ��S�б任
 */
void InvSubBytes(bitset<8> mtx[4 * 4])
{
	for (int i = 0; i < 16; ++i)
	{
		int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];
		int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
		mtx[i] = Inv_S_Box[row][col];
	}
}

/**
 *  ���б任 - ���ֽ�Ϊ��λѭ������
 */
void InvShiftRows(bitset<8> mtx[4 * 4])
{
	// �ڶ���ѭ������һλ
	bitset<8> temp = mtx[7];
	for (int i = 3; i > 0; --i)
		mtx[i + 4] = mtx[i + 3];
	mtx[4] = temp;
	// ������ѭ��������λ
	for (int i = 0; i < 2; ++i)
	{
		temp = mtx[i + 8];
		mtx[i + 8] = mtx[i + 10];
		mtx[i + 10] = temp;
	}
	// ������ѭ��������λ
	temp = mtx[12];
	for (int i = 0; i < 3; ++i)
		mtx[i + 12] = mtx[i + 13];
	mtx[15] = temp;
}

void InvMixColumns(bitset<8> mtx[4 * 4])
{
	bitset<8> arr[4];
	for (int i = 0; i < 4; ++i)
	{
		for (int j = 0; j < 4; ++j)
			arr[j] = mtx[i + j * 4];

		mtx[i] = GFMul(0x0e, arr[0]) ^ GFMul(0x0b, arr[1]) ^ GFMul(0x0d, arr[2]) ^ GFMul(0x09, arr[3]);
		mtx[i + 4] = GFMul(0x09, arr[0]) ^ GFMul(0x0e, arr[1]) ^ GFMul(0x0b, arr[2]) ^ GFMul(0x0d, arr[3]);
		mtx[i + 8] = GFMul(0x0d, arr[0]) ^ GFMul(0x09, arr[1]) ^ GFMul(0x0e, arr[2]) ^ GFMul(0x0b, arr[3]);
		mtx[i + 12] = GFMul(0x0b, arr[0]) ^ GFMul(0x0d, arr[1]) ^ GFMul(0x09, arr[2]) ^ GFMul(0x0e, arr[3]);
	}
}

/******************************��������Կ��չ����***********************/
/**
 * ��4�� Byte ת��Ϊһ�� word.
 */
bitset<32> Word(bitset<8>& k1, bitset<8>& k2, bitset<8>& k3, bitset<8>& k4)
{
	bitset<32> result(0x00000000);
	bitset<32> temp;
	temp = k1.to_ulong();  // K1
	temp <<= 24;
	result |= temp;
	temp = k2.to_ulong();  // K2
	temp <<= 16;
	result |= temp;
	temp = k3.to_ulong();  // K3
	temp <<= 8;
	result |= temp;
	temp = k4.to_ulong();  // K4
	result |= temp;
	return result;
}

/**
 *  ���ֽ� ѭ������һλ
 *  ����[a0, a1, a2, a3]���[a1, a2, a3, a0]
 */
bitset<32> RotWord(bitset<32>& rw)
{
	bitset<32> high = rw << 8;
	bitset<32> low = rw >> 24;
	return high | low;
}

/**
 *  ������word�е�ÿһ���ֽڽ���S-�б任
 */
bitset<32> SubWord(bitset<32> sw)
{
	bitset<32> temp;
	for (int i = 0; i < 32; i += 8)
	{
		int row = sw[i + 7] * 8 + sw[i + 6] * 4 + sw[i + 5] * 2 + sw[i + 4];
		int col = sw[i + 3] * 8 + sw[i + 2] * 4 + sw[i + 1] * 2 + sw[i];
		bitset<8> val = S_Box[row][col];
		for (int j = 0; j < 8; ++j)
			temp[i + j] = val[j];
	}
	return temp;
}

/**
 *  ��Կ��չ���� - ��128λ��Կ������չ�õ� w[4*(Nr+1)]
 */
void KeyExpansion(bitset<8> key[4 * Nk], bitset<32> w[4 * (Nr + 1)])
{
	bitset<32> temp;
	int i = 0;
	// w[]��ǰ4�����������key
	while (i < Nk)
	{
		w[i] = Word(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
		++i;
	}

	i = Nk;

	while (i < 4 * (Nr + 1))
	{
		temp = w[i - 1]; // ��¼ǰһ��word
		if (i % Nk == 0)
			w[i] = w[i - Nk] ^ SubWord(RotWord(temp)) ^ Rcon[i / Nk - 1];
		else
			w[i] = w[i - Nk] ^ temp;
		++i;
	}
}

/******************************�����Ǽ��ܺͽ��ܺ���**************************/
/**
 *  ����
 */
void encrypt(bitset<8> in[4 * 4], bitset<32> w[4 * (Nr + 1)])
{
	bitset<32> key[4];
	for (int i = 0; i < 4; ++i)
		key[i] = w[i];
	AddRoundKey(in, key);

	for (int round = 1; round < Nr; ++round)
	{
		SubBytes(in);
		ShiftRows(in);
		MixColumns(in);
		for (int i = 0; i < 4; ++i)
			key[i] = w[4 * round + i];
		AddRoundKey(in, key);
	}

	SubBytes(in);
	ShiftRows(in);
	for (int i = 0; i < 4; ++i)
		key[i] = w[4 * Nr + i];
	AddRoundKey(in, key);
}

/**
 *  ����
 */
void decrypt(bitset<8> in[4 * 4], bitset<32> w[4 * (Nr + 1)])
{
	bitset<32> key[4];
	for (int i = 0; i < 4; ++i)
		key[i] = w[4 * Nr + i];
	AddRoundKey(in, key);

	for (int round = Nr - 1; round > 0; --round)
	{
		InvShiftRows(in);
		InvSubBytes(in);
		for (int i = 0; i < 4; ++i)
			key[i] = w[4 * round + i];
		AddRoundKey(in, key);
		InvMixColumns(in);
	}

	InvShiftRows(in);
	InvSubBytes(in);
	for (int i = 0; i < 4; ++i)
		key[i] = w[i];
	AddRoundKey(in, key);
}


/**
 *  ��һ��char�ַ�����ת��Ϊ������
 *  �浽һ�� Byte ������
 */
void charToByte(bitset<8> out[16], const char s[16])
{
	for (int i = 0; i < 16; ++i)
		for (int j = 0; j < 8; ++j)
			out[i][j] = ((s[i] >> j) & 1); //0�ǵ�λ���±�Խ��λԽ��
}

/**
 *  ��������128λ�ֳ�16�飬�浽һ�� Byte ������
 */
void divideToByte(bitset<8> out[16], bitset<128>& data)
{
	bitset<128> temp;
	for (int i = 0; i < 16; ++i)
	{
		temp = (data << 8 * i) >> 120;
		out[i] = temp.to_ulong();
	}
}

/**
 *  ��16�� Byte �ϲ���������128λ
 */
bitset<128> mergeByte(bitset<8> in[16])
{
	bitset<128> res;
	res.reset();  // ��0
	bitset<128> temp;
	for (int i = 0; i < 16; ++i)
	{
		temp = in[i].to_ulong();
		temp <<= 8 * (15 - i);
		res |= temp;
	}
	return res;
}

//int main()
//{
//	string keyStr = "abcdefghijkllllnop";   //��Կ�ٳ�Ҳֻ��16λ
//	Byte key[16];  //16��8bit������ ����ά���飩
//	charToByte(key, keyStr.c_str());
//	// ��Կ��չ
//	word w[4 * (Nr + 1)];
//	KeyExpansion(key, w);
//
//	bitset<128> data;
//	Byte plain[16];
//	// ���ļ� flower.jpg ���ܵ� cipher.txt ��
//	ifstream in;
//	ofstream out;
//	in.open("D://flower.docx", ios::binary);
//	out.open("D://cipher.txt", ios::binary);
//	while (in.read((char*)&data, sizeof(data)))
//	{
//		divideToByte(plain, data);
//		encrypt(plain, w);
//		data = mergeByte(plain);
//		out.write((char*)&data, sizeof(data));
//		data.reset();  // ��0
//	}
//	in.close();
//	out.close();
//
//	// ���� cipher.txt����д��ͼƬ flower1.jpg
//	in.open("D://cipher.txt", ios::binary);
//	out.open("D://flower1.docx", ios::binary);
//	while (in.read((char*)&data, sizeof(data)))
//	{
//		divideToByte(plain, data);
//		decrypt(plain, w);
//		data = mergeByte(plain);
//		out.write((char*)&data, sizeof(data));
//		data.reset();  // ��0
//	}
//	in.close();
//	out.close();
//
//	return 0;
//}

