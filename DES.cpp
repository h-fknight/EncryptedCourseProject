/*************************************************************************
	> File Name: Des.cpp
	> Author: SongLee
	> E-mail: lisong.shine@qq.com
	> Created Time: 2014年06月01日 星期日 19时46分32秒
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
/*                            下面是DES算法实现                         */
/*                                                                    */
/**********************************************************************/

/**
 *  密码函数f，接收32位数据和48位子密钥，产生一个32位的输出
 */
bitset<32> f(bitset<32> R, bitset<48> k)
{
	bitset<48> expandR;
	// 第一步：扩展置换，32 -> 48
	for (int i = 0; i < 48; ++i)
		expandR[47 - i] = R[32 - E[i]];
	// 第二步：异或
	expandR = expandR ^ k;
	// 第三步：查找S_BOX置换表
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
	// 第四步：P-置换，32 -> 32
	bitset<32> tmp = output;
	for (int i = 0; i < 32; ++i)
		output[31 - i] = tmp[32 - P[i]];
	return output;
}

/**
 *  对56位密钥的前后部分进行左移
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
 *  生成16个48位的子密钥
 */
void generateKeys()
{
	bitset<56> realKey;
	bitset<28> left;
	bitset<28> right;
	bitset<48> compressKey;
	// 去掉奇偶标记位，将64位密钥变成56位
	for (int i = 0; i < 56; ++i)
		realKey[55 - i] = key[64 - PC_1[i]];
	// 生成子密钥，保存在 subKeys[16] 中
	for (int round = 0; round < 16; ++round)
	{
		// 前28位与后28位
		for (int i = 28; i < 56; ++i)
			left[i - 28] = realKey[i];
		for (int i = 0; i < 28; ++i)
			right[i] = realKey[i];
		// 左移
		left = leftShift(left, shiftBits[round]);
		right = leftShift(right, shiftBits[round]);
		// 压缩置换，由56位得到48位子密钥
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
 *  工具函数：将char字符数组转为二进制
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
 *  DES加密
 */
bitset<64> encrypt(bitset<64>& plain)
{
	bitset<64> cipher;
	bitset<64> currentBits;
	bitset<32> left;
	bitset<32> right;
	bitset<32> newLeft;
	// 第一步：初始置换IP
	for (int i = 0; i < 64; ++i)
		currentBits[63 - i] = plain[64 - IP[i]];
	// 第二步：获取 Li 和 Ri
	for (int i = 32; i < 64; ++i)
		left[i - 32] = currentBits[i];
	for (int i = 0; i < 32; ++i)
		right[i] = currentBits[i];
	// 第三步：共16轮迭代
	for (int round = 0; round < 16; ++round)
	{
		newLeft = right;
		right = left ^ f(right, subKey[round]);
		left = newLeft;
	}
	// 第四步：合并L16和R16，注意合并为 R16L16
	for (int i = 0; i < 32; ++i)
		cipher[i] = left[i];
	for (int i = 32; i < 64; ++i)
		cipher[i] = right[i - 32];
	// 第五步：结尾置换IP-1
	currentBits = cipher;
	for (int i = 0; i < 64; ++i)
		cipher[63 - i] = currentBits[64 - IP_1[i]];
	// 返回密文
	return cipher;
}

/**
 *  DES解密
 */
bitset<64> decrypt(bitset<64>& cipher)
{
	bitset<64> plain;
	bitset<64> currentBits;
	bitset<32> left;
	bitset<32> right;
	bitset<32> newLeft;
	// 第一步：初始置换IP
	for (int i = 0; i < 64; ++i)
		currentBits[63 - i] = cipher[64 - IP[i]];
	// 第二步：获取 Li 和 Ri
	for (int i = 32; i < 64; ++i)
		left[i - 32] = currentBits[i];
	for (int i = 0; i < 32; ++i)
		right[i] = currentBits[i];
	// 第三步：共16轮迭代（子密钥逆序应用）
	for (int round = 0; round < 16; ++round)
	{
		newLeft = right;
		right = left ^ f(right, subKey[15 - round]);
		left = newLeft;
	}
	// 第四步：合并L16和R16，注意合并为 R16L16
	for (int i = 0; i < 32; ++i)
		plain[i] = left[i];
	for (int i = 32; i < 64; ++i)
		plain[i] = right[i - 32];
	// 第五步：结尾置换IP-1
	currentBits = plain;
	for (int i = 0; i < 64; ++i)
		plain[63 - i] = currentBits[64 - IP_1[i]];
	// 返回明文
	return plain;
}


/**********************************************************************/
/* 测试：                                                             */
/*     1.将一个 64 位的字符串加密， 把密文写入文件 a.txt                  */
/*     2.读取文件 a.txt 获得 64 位密文，解密之后再写入 b.txt              */
/**********************************************************************/

//int main() {
//	string s = "romantic";
//	string k = "12345678";
//	bitset<64> plain = charToBitset(s.c_str());
//	key = charToBitset(k.c_str());
//	// 生成16个子密钥
//	generateKeys();
//	// 密文写入 a.txt
//	bitset<64> cipher = encrypt(plain);
//	fstream file1;
//	file1.open("D://a.txt", ios::binary | ios::out);
//	file1.write((char*)&cipher, sizeof(cipher));
//	file1.close();
//
//	// 读文件 a.txt
//	bitset<64> temp;
//	file1.open("D://a.txt", ios::binary | ios::in);
//	file1.read((char*)&temp, sizeof(temp));
//	file1.close();
//
//	// 解密，并写入文件 b.txt
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
//	generateKeys();   // 生成16个子密钥
//
//	// 将文件 flower.jpg 加密到 cipher.txt 中
//	ifstream in;
//	ofstream out;
//	in.open("D://flower.jpg", ios::binary);
//	out.open("D://cipher.dat", ios::binary);
//	bitset<64> plain;
//	while (in.read((char*)&plain, sizeof(plain)))
//	{
//		bitset<64> cipher = encrypt(plain);
//		out.write((char*)&cipher, sizeof(cipher));
//		plain.reset();  // 置0
//	}
//	in.close();
//	out.close();
//
//	// 解密 cipher.txt，并写入图片 flower1.jpg
//	in.open("D://cipher.dat", ios::binary);
//	out.open("D://flower1.jpg", ios::binary);
//	
//	while (in.read((char*)&plain, sizeof(plain)))
//	{
//		bitset<64> temp = decrypt(plain);
//		out.write((char*)&temp, sizeof(temp));
//		plain.reset();  // 置0
//	}
//	in.close();
//	out.close();
//
//	return 0;
//}

