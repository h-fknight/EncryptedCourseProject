#include "BigInt.h"
#include "utils.h"

//Ĭ�Ϲ��캯��,��Ա������0
BigInt::BigInt()
{
    for(int i=0 ;i < _capacity;i++)
        data[i]=0;
    sign=true; 
}


//��int��ʼ������
BigInt::BigInt(const int& input)
{
    for(int i=0 ;i<_capacity ;i++)
        data[i]=0;
    data[0]=input;
    if(input>=0)
        sign=true;
    else
        sign=false;
}

//�ô�����������ֵ
BigInt::BigInt(const BigInt& input)
{
    for(int i = 0; i < _capacity; i++)
        data[i] = input.data[i];
    sign = input.sign;
}

BigInt::BigInt(string str, int base) {
    switch (base) {
        case BIN_STRING:
            GenFromBinString(str);
            break;
        case BYTE_STRING:
            GenFromByteString(str);
            break;
        case HEX_STRING:
            GenFromHexString(str);
            break;
        default:
            LOGLN("BigInt: Error base");
            exit(1);
            break;
    }
}

void BigInt::GenFromHexString(string str)
{
    Clear();
    int index = 0;
    while (str.length() > 8)
    {
        string seg = str.substr(str.length() - 8, 8);
        str.erase(str.length() - 8, 8);
        unsigned int cur = 0;
        for(int i = 0; i < 8; i++)
        {
            cur = cur * 16 + _hexCharToInt(seg[i]);
        }
        data[index++] = cur;
    }
    unsigned int cur = 0;
    for (int i = 0; i < str.length(); i++)
        cur = cur * 16 + _hexCharToInt(str[i]);
    data[index] = cur;
}

void BigInt::GenFromBinString(string str)
{
    Clear();
    int index = 0;
    while (str.length() > 32)
    {
        string seg = str.substr(str.length() - 32, 32);
        str.erase(str.length() - 32, 32);
        unsigned int cur = 0;
        for (int i = 0; i < 32; i++)
        {
            cur = cur * 2 + (seg[i] - '0');
        }
        data[index++] = cur;
    }
    unsigned int cur = 0;
    for (int i = 0; i < str.length(); i++)
        cur = cur * 2 + (str[i] - '0');
    data[index] = cur;
}

void BigInt::GenFromByteString(const string& buf) {
    int len = buf.length();
    int s1, s2, s3, s4;
    Clear();
    int mask[] = {0, 8, 16, 24};
    int validmsk = 0xff;
    size_t curmsk = 0, cur = 0;
    for (int i = 0; i < buf.size(); ++ i) {
        int tmp = (int) buf[i];
        data[cur] |= ((tmp << mask[curmsk]) & (validmsk << mask[curmsk]));
        curmsk ++;
        if (curmsk == 4) {
            curmsk = 0;
            cur ++;
        }
    }
}
string BigInt::ToString() const {
    string res;
    int len = GetLength();
    char ch;
    unsigned int f4 = 0xFF, f3 = 0xFF00, f2 = 0xFF0000, f1 = 0xFF000000;
    
    for (int i = 0; i < len - 1; i++) {
        ch = (char)(data[i] & f4);
        res += ch;
        ch = (char)((data[i] & f3) >> 8);
        res += ch;
        ch = (char)((data[i] & f2) >> 16);
        res += ch;
        ch = (char)((data[i] & f1) >> 24);
        res += ch;
    }
    unsigned int tmp = data[len - 1];
    while(tmp) {
        ch = (char)(tmp & f4);
        res += ch;
        tmp >>= 8;
    }
    return res;
}

//�ô�����������ֵ
BigInt& BigInt::operator= (const BigInt& input)
{
    for (int i = 0; i < _capacity; i++)
        data[i] = input.data[i];
    sign = input.sign;
    return *this;
}

//�Ƚ����������Ĵ�С,a<b,������,���򷵻ؼ�
bool BigInt::operator< (const BigInt& b) const
{
    for (int i = _capacity - 1; i > 0; i--)
    {
        if (this->data[i] < b.data[i])
            return true;
        if (this->data[i] > b.data[i])
            return false;
    }
    return this->data[0] < b.data[0];
}

//�Ƚ����������Ĵ�С,a>b,������,���򷵻ؼ�
bool BigInt::operator> (const BigInt& b) const
{
    for (int i = _capacity - 1; i >= 0; i--)
    {
        if (this->data[i] > b.data[i])
            return true;
        if (this->data[i] < b.data[i])
            return false;
    }
    return false;
}

//�ж����������Ƿ����,��ȷ�����,���򷵻ؼ�
bool BigInt::operator== (const BigInt& b) const
{
    for (int i = 0; i < _capacity; i++)
        if (this->data[i] != b.data[i])
            return false;
    return true;
}

//�ж�һ��������һ��intֵ�Ƿ����,��ȷ�����,���򷵻ؼ�
bool BigInt::operator== (const int& b) const
{
    for (int i = 1; i < this->GetLength(); i++) {
        if (this->data[i] != 0)
            return false;
    }
    return this->data[0] == b;
}

//�������������ĺ�,������ʽ��ӷ�
BigInt BigInt::operator+ (const BigInt& b) const
{
    BigInt result;
    //64λ����,���ÿ��λ����ӵ���ʱ��
    unsigned long long sum;    
    //carryΪ��λ��־,subΪ��������������ʱ,���ÿ��λ���������ʱ��
    unsigned int carry = 0, sub;  
    //ȡa,b�г��Ƚϳ��ĳ���
    int length = (this->GetLength() >= b.GetLength()? this->GetLength() : b.GetLength());   

    //������������ͬʱ,���мӷ�����
    if (this->sign == b.sign)
    {
        //ÿһλ������ʽ���
        for (int i = 0; i < length; i++)
        {
            sum = (unsigned long long)this->data[i] + b.data[i] + carry;
            result.data[i] = (unsigned int)sum;
            //sum�ĸ�λΪ��λ
            carry = (sum >> 32);
        }

        result.sign = this->sign;
        return result;
    }

    //�������Ų�ͬʱ,���м�������
    else
    {
        BigInt tempa, tempb;

        //ȡ��a,b�о���ֵ�ϴ����Ϊ������
        if (*this < b)
        {
            tempa = b;
            tempb = *this;
        }
        else
        {
            tempa = *this;
            tempb = b;
        }

        //ÿһλ������ʽ��
        for (int i = 0; i < length; i++)
        {
            sub = tempb.data[i] + carry;
            if (tempa.data[i] >= sub)
            {
                result.data[i] = tempa.data[i] - sub;
                carry = 0;
            }
            else
            {
                //��λ��
                result.data[i] = (unsigned long long)tempa.data[i] + ((unsigned long long)1<<32) - sub;
                carry = 1;
            }
        }
        result.sign = tempa.sign;
        return result;
    }
}

//�������������Ĳ�,������ʽ�����
BigInt BigInt::operator- (const BigInt& b) const
{
    BigInt result;
    //64λ����,���ÿ��λ����ӵ���ʱ��
    unsigned long long sum;
    //carryΪ��λ��־,subΪ��������������ʱ,���ÿ��λ���������ʱ��
    unsigned int carry = 0, sub;

    //������ͬʱ,���м�������
    if (this->sign == b.sign)
    {
        BigInt tempa, tempb;

        //ȡ��a,b�о���ֵ�ϴ����Ϊ������
        if (*this < b)
        {
            tempa = b;
            tempb = *this;
            tempa.sign = !tempa.sign;
        }
        else
        {
            tempa = *this;
            tempb = b;
        }

        //ÿһλ������ʽ��
        for (int i = 0; i < _capacity; i++)
        {
            sub = tempb.data[i] + carry;
            if (tempa.data[i] >= sub)
            {
                result.data[i] = tempa.data[i] - sub;
                carry = 0;
            }
            else
            {
                //��λ��
                result.data[i] = (unsigned long long)tempa.data[i] + ((unsigned long long)1<<32) - sub;
                carry = 1;
            }
        }
        result.sign = tempa.sign;
        return result;
    }

    //�������Ų�ͬʱ,���мӷ�����
    else
    {
        //ÿһλ������ʽ���
        for (int i = 0; i < _capacity; i++)
        {
            sum = (unsigned long long)this->data[i] + b.data[i] + carry;
            result.data[i] = (unsigned int)sum;
            //sum�ĸ�λΪ��λ
            carry = (sum >> 32);
        }
        result.sign = this->sign;
        return result;
    }
}

//������һ��int��
BigInt BigInt::operator- (const int& b) const
{
    BigInt temp(b);
    BigInt result = *this - temp;
    return result;
}


//��������һ��INT��
BigInt BigInt::operator* (const unsigned int& b) const
{
    BigInt result;
    //���B����A��ÿһλ����ʱ��
    unsigned long long sum;
    //��Ž�λ
    unsigned int carry = 0;

    for (int i = 0; i < _capacity; i++)
    {
        sum = ((unsigned long long)this->data[i]) * b + carry;
        result.data[i] = (unsigned int)sum;
        //��λ��SUM�ĸ�λ��
        carry = (sum>>32);
    }
    result.sign = this->sign;
    return result;
}

//�������,������ʽ��
BigInt BigInt::operator* (const BigInt& b) const
{
    //last�����ʽ��һ�еĻ�,temp��ŵ�ǰ�еĻ�
    BigInt result, last, temp;    
    //sum��ŵ�ǰ�д���λ�Ļ�
    unsigned long long sum;
    //��Ž�λ
    unsigned int carry;

    //������ʽ��
    for (int i = 0; i < b.GetLength(); i++)
    {
        carry = 0;
        //B��ÿһλ��A���
        for (int j = 0; j < this->GetLength() + 1; j++)
        {
            sum = ((unsigned long long)this->data[j]) * b.data[i] + carry;
            if ((i + j) < _capacity)
                temp.data[i + j] = (unsigned int)sum;
            carry = (sum>>32);
        }
        result = (temp + last);
        last = result;
        temp.Clear();
    }

    //�жϻ��ķ���
    if (this->sign == b.sign)
        result.sign = true;
    else
        result.sign = false;

    return result;
}

//������,�������̳���,���ö��ֲ��ҷ��Ż�
BigInt BigInt::operator/ (const BigInt& b) const
{
    //mulΪ��ǰ����,low,highΪ���ֲ�������ʱ���õı�־
    unsigned int mul, low, high;
    //subΪ�����뵱ǰ���̵Ļ�,subsequentΪ��������һ���̵Ļ�
    //dividend�����ʱ������
    BigInt dividend, quotient, sub, subsequent;
    int lengtha = this->GetLength(), lengthb = b.GetLength();

    //���������С�ڳ���,ֱ�ӷ���0
    if (*this < b)
    {
        if (this->sign == b.sign)
            quotient.sign = true;
        else
            quotient.sign = false;
        return quotient;
    }

    //�ѱ������������ĳ��ȴӸ�λ��λ
    for (int i = 0; i < lengthb; i++)
        dividend.data[i] = this->data[lengtha - lengthb + i];

    for (int i = lengtha - lengthb; i >= 0; i--)
    {
        //���������С�ڳ���,������λ
        if (dividend < b)
        {
            for (int j = lengthb; j > 0; j--)
                dividend.data[j] = dividend.data[j - 1];
            dividend.data[0] = this->data[i - 1];
            continue;
        }

        low = 0;
        high = 0xffffffff;

        //���ֲ��ҷ���������
        while (low < high)
        {
            mul = (((unsigned long long)high) + low) / 2;           
            sub = (b * mul);
            subsequent = (b * (mul + 1));

            if (((sub < dividend) && (subsequent > dividend)) || (sub == dividend))
                break;
            if (subsequent == dividend)
            {
                mul++;
                sub = subsequent;
                break;
            }
            if ((sub < dividend) && (subsequent < dividend))
            {
                low = mul;
                continue;
            }
            if ((sub > dividend) && (subsequent > dividend))
            {
                high = mul;
                continue;
            }
        }

        //���̽�����浽����ȥ
        quotient.data[i] = mul;
        //��ʱ��������Ϊ�����������̻��Ĳ�
        dividend = dividend - sub;

        //��ʱ����������λ
        if ((i - 1) >= 0)
        {
            for (int j = lengthb; j > 0; j--)
                dividend.data[j] = dividend.data[j - 1];
            dividend.data[0] = this->data[i - 1];
        }
    }

    //�ж��̵ķ���
    if (this->sign == b.sign)
        quotient.sign = true;
    else
        quotient.sign = false;
    return quotient;
}

//������ģ����,�������������
BigInt BigInt::operator% (const BigInt& b) const
{
    unsigned int mul, low, high;
    BigInt dividend, quotient, sub, subsequent;
    int lengtha = this->GetLength(), lengthb = b.GetLength();

    //���������С�ڳ���,���ر�����Ϊģ
    if (*this < b)
    {
        dividend = *this;
        //����������Զ�뱻������ͬ
        dividend.sign = this->sign;
        return dividend;
    }

    //���г�������
    for (int i = 0; i < lengthb; i++)
        dividend.data[i] = this->data[lengtha - lengthb + i];

    for (int i = lengtha - lengthb; i >= 0; i--)
    {
        if (dividend < b)
        {
            for (int j = lengthb; j > 0; j--)
                dividend.data[j] = dividend.data[j - 1];
            dividend.data[0] = this->data[i - 1];
            continue;
        }

        low = 0;
        high = 0xffffffff;

        while (low <= high)
        {
            mul = (((unsigned long long)high) + low) / 2;
            sub = (b * mul);
            subsequent = (b * (mul + 1));

            if (((sub < dividend) && (subsequent > dividend)) || (sub == dividend))
                break;
            if (subsequent == dividend)
            {
                mul++;
                sub = subsequent;
                break;
            }
            if ((sub < dividend) && (subsequent < dividend))
            {   
                low = mul;
                continue;
            }
            if ((sub > dividend) && (subsequent > dividend))
            {
                high = mul;
                continue;
            }
        }

        quotient.data[i] = mul;
        dividend = dividend - sub;
        if ((i - 1) >= 0)
        {
            for (int j = lengthb; j > 0; j--)
                dividend.data[j] = dividend.data[j - 1];
            dividend.data[0] = this->data[i - 1];
        }
    }

    //��ʱ��������Ϊ����ģ
    dividend.sign = this->sign;
    return dividend;
}
int BigInt::operator% (const int& b) const {
    int len = this->GetLength();
    if (len == 1)
        return this->data[0] % b;

    unsigned long long cur = 0;

    for (int i = len - 1; i >= 0; i--) {
        cur = (cur << 32) + this->data[i];
        cur = cur % b;
    }
    return (int)cur;
}

BigInt BigInt::operator& (const BigInt& b) const {
    int len = max(this->GetLength(), b.GetLength());
    BigInt res;
    for (int i = 0; i < len; i++)
        res.data[i] = (this->data[i] & b.data[i]);
    res.sign = (this->sign & b.sign);
    return res;
}

BigInt BigInt::operator^ (const BigInt& b) const{
    int len = max(this->GetLength(), b.GetLength());
    BigInt res;
    for (int i = 0; i < len; i++)
        res.data[i] = (this->data[i] ^ b.data[i]);
    res.sign = (this->sign ^ b.sign);
    return res;
}

BigInt BigInt::operator| (const BigInt& b) const {
    int len = max(this->GetLength(), b.GetLength());
    BigInt res;
    for (int i = 0; i < len; i++)
        res.data[i] = (this->data[i] ^ b.data[i]);
    res.sign = (this->sign ^ b.sign);
    return res;
}


//��������������������
void BigInt::_output(ostream& out) const
{
    unsigned int temp, result;
    unsigned int filter = 0xf0000000;
    string resStr;
    for(int i = GetLength() - 1; i >= 0; i--)
    {
        temp = data[i];
        //������ÿһλ����ת����16�������
        for (int j = 0; j < 8; j++)
        {
            result = temp & filter;
            result = (result >> 28);
            temp = (temp << 4);
            if (result >= 0 && result <= 9)
                resStr += (result + '0');
            else
            {
                switch (result)
                {
                case 10:
                    resStr += 'A';
                    break;
                case 11:
                    resStr += 'B';
                    break;
                case 12:
                    resStr += 'C';
                    break;
                case 13:
                    resStr += 'D';
                    break;
                case 14:
                    resStr += 'E';
                    break;
                case 15:
                    resStr += 'F';
                    break;
                }           
            }
        }
    }
    while (resStr[0] == '0')
    {
        resStr.erase(0,1);
    }
    out << resStr;
}

//�������������
ostream& operator<< (ostream& out, const BigInt& x)
{
    x._output(out);
    return out;
}

string BigInt::ToHexString() const
{
    unsigned int temp, result;
    unsigned int filter = 0xf0000000;
    string resStr;
    for(int i = GetLength() - 1; i >= 0; i--)
    {
        temp = data[i];
        //������ÿһλ����ת����16�������
        for (int j = 0; j < 8; j++)
        {
            result = temp & filter;
            result = (result >> 28);
            temp = (temp << 4);
            if (result >= 0 && result <= 9)
                resStr += (result + '0');
            else
            {
                switch (result)
                {
                case 10:
                    resStr += 'A';
                    break;
                case 11:
                    resStr += 'B';
                    break;
                case 12:
                    resStr += 'C';
                    break;
                case 13:
                    resStr += 'D';
                    break;
                case 14:
                    resStr += 'E';
                    break;
                case 15:
                    resStr += 'F';
                    break;
                }           
            }
        }
    }
    while (resStr[0] == '0')
    {
        resStr.erase(0,1);
    }
    return resStr;
}
//������0
void BigInt::Clear()
{
    for (int i = 0; i < _capacity; i++)
        data[i] = 0;
}

//���ش�������
int BigInt::GetLength() const
{
    int length = _capacity;
    for (int i = _capacity - 1; i >= 0; i--)
    {
        //��һλ��Ϊ0��ΪLENGTH
        if (data[i] == 0)
            length--;
        else
            break;
    }
    if (length == 0)
        length = 1;
    return length;
}

int BigInt::GetBitLength() const {
    int len = GetLength();
    int res = (len - 1) * 32;
    unsigned int tmp = data[len - 1];
    while (tmp > 0) {
        res ++;
        tmp = (tmp >> 1);
    }
    return res;
}

//������λ������,������a(a < 32)λ
BigInt& BigInt::operator>> (const int& a)
{
    unsigned int bit, filter;
    filter = (1 << a) - 1;
    data[0] = (data[0] >> a);
    for (int i = 1; i < GetLength(); i++)
    {
        //�Ƚ�ÿһλ�ĵ�aλ�Ƶ�BIT��
        bit = data[i] & filter;
        //�ٰ�BIT�Ƶ���һλ�ĸ�λ��
        bit = bit << (32 - a);
        data[i - 1] = data[i - 1] | bit;
        data[i] = (data[i] >> a);
    }
    return *this;
}
//������λ������,������aλ
BigInt& BigInt::operator<< (const int& a) {
    unsigned int bit, filter;
    filter = (1 << a) - 1;
    filter = (filter << (32 - a));
    int len = GetLength();
    for (int i = len - 1; i >= 0; i--) {
        bit = data[i] & filter;
        bit = bit >> (32 - a);
        data[i + 1] = data[i + 1] | bit;
        data[i] = (data[i] << a);
    }
    return *this;
}

//�жϴ�����һ��INT�Ĵ�С
bool BigInt::operator<= (const int& b) const
{
    for (int i = 1; i < this->GetLength(); i++)
    {
        if (this->data[i] != 0)
            return false;
    }
    if (this->data[0] <= b)
        return true;
    else 
        return false;
}


//ģ������,�����ɸ���������ģ���㷨
BigInt BigInt::PowerMode (const BigInt& n, const BigInt& p, const BigInt& m)
{
    BigInt temp = p;
    BigInt r = n % m;
    BigInt k(1);
    while ( !(temp <= 1) )
    {       
        if (temp.IsOdd())
        {
            k = (k * r) % m;
        }
        r = (r * r) % m;
        temp >> 1;
    }
    return ( r * k ) % m;
}

char BigInt::_intToHexChar(int n)
{
    char c;
    if (n >= 0 && n <= 9)
        c = '0' + n;
    else switch (n)
    {
        case 10:
            c = 'A';
            break;
        case 11:
            c = 'B';
            break;
        case 12:
            c = 'C';
            break;
        case 13:
            c = 'D';
            break;
        case 14:
            c = 'E';
            break;
        case 15:
            c = 'F';
            break;
    default:
        break;
    }
    return c;
}

int BigInt::_hexCharToInt(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else switch (c)
    {
        case 'a':
        case 'A':
            return 10;
        case 'b':
        case 'B':
            return 11;
        case 'c':
        case 'C':
            return 12;
        case 'd':
        case 'D':
            return 13;
        case 'e':
        case 'E':
            return 14;
        case 'f':
        case 'F':
            return 15;
        default:
            break;
    }
    LOGLN("BigInt: hexCharToInt error");
    exit(0);
}

//����һ���������,������Ƴ���ΪdigNum
void BigInt::Random(int digNum)
{
    if (digNum < 32) {
        data[0] = (rand() << 17 ) + ( rand() << 2 )+ rand() % 4;
        unsigned int filter = 1;
        filter = (1 << digNum) - 1;
        data[0] = (data[0] & filter);
        return;
    }
    for (int i = 0; i < digNum / 32; i++) {
        //����RAND()���ֻ�ܲ���0X7FFF����,Ϊ���ܲ���32λ�������,��Ҫ
        //3��RAND()����
        data[i] = (rand() << 17 ) + ( rand() << 2 )+ rand() % 4;
    }
    data[digNum/32-1] = data[digNum/32-1] | 0x80000000;
}


//����һ����С���������,������Ƴ���ΪdigNum��1/4;
void BigInt::Randomsmall(int digNum)
{
    if (digNum < 128) {
        data[0] = (rand() << 17 ) + ( rand() << 2 )+ rand() % 4;
        unsigned int filter = 1;
        int tmp = digNum / 4;
        filter = (1 << tmp) - 1;
        data[0] = (data[0] & filter);
        return;
    }
    for (int i = 0; i < digNum / 128; i++) {
        //����RAND()���ֻ�ܲ���0X7FFF����,Ϊ���ܲ���32λ�������,��Ҫ
        //3��RAND()����
        data[i] = (rand() << 17 ) + ( rand() << 2 )+ rand() % 4;
    }
    data[digNum/128-1] = data[digNum/32-1] | 0x80000000;
}

//���������������Լ��,����շת�����
BigInt BigInt::Gcd(const BigInt& m, const BigInt& n)
{
    //cout << "m: ";m.displayByHex(); cout << "n: ";n.displayByHex();cout << endl;
    //outfile << "m: ";outfile << m; outfile << "n: ";outfile << n;outfile << endl;
    if (n == 0)
        return m;
    else
        return Gcd(n, m%n);
}

//����չŷ������㷨��˷�ģ��
BigInt BigInt::ExtendedGcd(const BigInt& a, const BigInt& b, BigInt& x, BigInt& y)
{
    /* naive version
    BigInt t, d;   
    //���һ��������Ϊ�����޷����г�������
    if (b == 0)   
    {
        x = 1, y = 0;
        return a;
    }
    BigInt tb = a % b;
    d = ExtendedGcd(b, tb, x, y);   
    t = x;   
    x = y;   
    y = t - ((a / b) * y);   
    return d;  */
    BigInt x0 = 1, y0 = 0, x1 = 0, y1 = 1, c = a, d = b;
    BigInt k, r, t;
    while (!(d == 0)) { 
        k = c / d;
        r = c % d;
        t = c;
        c = d;
        d = r;
        t = x0;
        x0 = x1;
        x1 = t - k * x1;
        t = y0;
        y0 = y1;
        y1 = t - k * y1;
    }
    x = x0, y = y0;
    return c;
}

BigInt BigInt::Euc(BigInt& E,BigInt& A)
{
    BigInt M, X, Y, I, J;
    int x, y;
    M = A;
    X = 0;
    Y = 1;
    x = y = 1;
    while ((E.GetLength() != 1) || !(E == 0))
    {
        I = M / E;
        J = M % E;
        M = E;
        E = J;
        J = Y;
        Y = Y * I;
        if (x == y)
        {
            if (X > Y)
                Y = X - Y;
            else
            {
                Y = Y - X;
                y = 0;
            }
        }
        else
        {
            Y = X + Y;
            x = 1 - x;
            y = 1 - y;
        }
        X = J;
    }
    if (x == 0)
        X = A - X;
    return X;
}
