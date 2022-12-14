#ifndef MD5_H
#define MD5_H

#define READ_DATA_SIZE	1024
#define MD5_SIZE		16
#define MD5_STR_LEN		(MD5_SIZE * 2)
#define TEST_BLOCK_LEN 10000
#define TEST_BLOCK_COUNT 10000
#include<string>
using namespace std;

static unsigned char PADDING[] =
{
  0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

typedef struct
{
	unsigned int count[2];
	unsigned int state[4];
	unsigned char buffer[64];
} MD5_CTX;

#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y ^ (x | ~z))
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))

#define FF(a,b,c,d,x,s,ac) \
{ \
  a += F(b,c,d) + x + ac; \
  a = ROTATE_LEFT(a,s); \
  a += b; \
}
#define GG(a,b,c,d,x,s,ac) \
{ \
  a += G(b,c,d) + x + ac; \
  a = ROTATE_LEFT(a,s); \
  a += b; \
}
#define HH(a,b,c,d,x,s,ac) \
{ \
  a += H(b,c,d) + x + ac; \
  a = ROTATE_LEFT(a,s); \
  a += b; \
}
#define II(a,b,c,d,x,s,ac) \
{ \
  a += I(b,c,d) + x + ac; \
  a = ROTATE_LEFT(a,s); \
  a += b; \
}
void MD5Init(MD5_CTX* context);
void MD5Update(MD5_CTX* context, unsigned char* input, unsigned int inputlen);
void MD5Final(MD5_CTX* context, unsigned char digest[16]);
void MD5Transform(unsigned int state[4], unsigned char block[64]);
void MD5Encode(unsigned char* output, unsigned int* input, unsigned int len);
void MD5Decode(unsigned int* output, unsigned char* input, unsigned int len);
int Compute_string_md5(unsigned char* dest_str, unsigned int dest_len, char* md5_str);
void MD5String(unsigned char* str, string &out); //两种字符串的MD5皆可使用
void MDFile(const char* filename,string &out);

#endif

