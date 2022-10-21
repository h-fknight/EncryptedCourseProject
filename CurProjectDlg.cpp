
#include "DES.h"
#include "AES.h"
#include "Rsa.h"
#include "MD5.h"
#include "BigInt.h"
#include "StringTrans.h"
#include "SHA1.hpp"
#include "pch.h"
#include "framework.h"
#include "CurProject.h"
#include "CurProjectDlg.h"
#include "afxdialogex.h"
#include "stringsplit.hpp"
#include "fileoperation.hpp"
#include <iostream>
#include <algorithm>
#include <direct.h>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CCurProjectDlg 对话框

bool file_or_str; //0代表string 1代表文件

string getcurrentpath() {
	string path;
	char* buffer;
	//也可以将buffer作为输出参数
	if ((buffer = _getcwd(NULL, 0)) == NULL)
	{
		perror("getcwd error");
		return 0;
	}
	else
	{
		path = string(buffer);
		free(buffer);
		return path;
	}

}
void CreateFolder() {
	string folderPath =  "AFile";
	string command;
	command = "mkdir " + folderPath;
	system(command.c_str());

	folderPath = "BFile";
	command = "mkdir " + folderPath;
	system(command.c_str());

}

CCurProjectDlg::CCurProjectDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_CURPROJECT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CCurProjectDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT2, edt_A);
	DDX_Control(pDX, IDC_EDIT1, edt_B);
	DDX_Control(pDX, IDC_BUTTON1, chose_file);
	DDX_Control(pDX, IDC_BUTTON2, open_file);
	DDX_Control(pDX, IDOK, send);
	DDX_Control(pDX, IDC_BUTTON4, decry);
	DDX_Control(pDX, IDC_BUTTON5, encry);
	DDX_Control(pDX, IDC_EDIT6, info_B);
	DDX_Control(pDX, IDC_EDIT5, info_A);
	DDX_Control(pDX, IDC_EDIT3, edt_key);
	DDX_Control(pDX, IDC_PROGRESS1, process);
	DDX_Control(pDX, IDC_PROGRESS_FILE, prcsbar);
	DDX_Control(pDX, IDC_EDIT4, edt_dekey);
	DDX_Control(pDX, IDC_RADIO1, c_md5);
	DDX_Control(pDX, IDC_RADIO2, c_sha1);
	DDX_Control(pDX, IDC_RADIO3, c_des);
	DDX_Control(pDX, IDC_RADIO4, c_aes);
	DDX_Control(pDX, IDC_RADIO6, c_string);
	DDX_Control(pDX, IDC_BUTTON3, initial);
}

BEGIN_MESSAGE_MAP(CCurProjectDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CCurProjectDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CCurProjectDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDOK, &CCurProjectDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_BUTTON3, &CCurProjectDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON4, &CCurProjectDlg::OnBnClickedButton4)
	ON_BN_CLICKED(IDC_BUTTON5, &CCurProjectDlg::OnBnClickedButton5)

	ON_WM_SIZE()
	ON_BN_CLICKED(IDC_BUTTON6, &CCurProjectDlg::OnBnClickedButton6)
	ON_BN_CLICKED(IDC_BUTTON7, &CCurProjectDlg::OnBnClickedButton7)
END_MESSAGE_MAP()


// CCurProjectDlg 消息处理程序

void CCurProjectDlg::ConvertCiphertext2OtherFormat(int iBitsLen, char* szCipherInBytes)
{
	memset(hexCiphertextAnyLength, 0, 16384);
	memset(bitsCiphertextAnyLength, 0, 32768);
	myDES->Bytes2Bits(szCipherInBytes, bitsCiphertextAnyLength, iBitsLen);
	myDES->Bits2Hex(hexCiphertextAnyLength, bitsCiphertextAnyLength, iBitsLen);
	for (int i = 0; i < iBitsLen; i++)
	{
		bitsCiphertextAnyLength[i] += 48;
	}
}

int CCurProjectDlg::ConvertOtherFormat2Ciphertext(char* szCipher)
{
	int iLen = 0;
	memset(szCiphertextData, 0, 8192);

		iLen = ((strlen(szCipher) >> 2) + (strlen(szCipher) % 4 == 0 ? 0 : 1)) << 4;
		memset(hexCiphertextAnyLength, 0, 16384);
		memcpy(hexCiphertextAnyLength, szCipher, strlen(szCipher));
		myDES->Hex2Bits(hexCiphertextAnyLength, bitsCiphertextAnyLength, iLen);
		myDES->Bits2Bytes(szCiphertextData, bitsCiphertextAnyLength, iLen);
	return iLen >> 3;
}

BOOL CCurProjectDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	GetDlgItem(IDC_EDIT7)->SetWindowTextA("1、点击初始化非对称秘钥；\r\n2、填写字符串或选择文件并输入秘钥，点击加密进行特定签名和特定加密；\r\n3、选择传送内容的格式并点击传送；\r\n4、点击解密查看解密字符串或文件，校验是否被篡改！\r\n5、目前只支持txt文件格式的签名加解密！\r\n");
	edt_A.Clear(); edt_B.Clear(); edt_key.SetWindowTextA(_T(""));
	c_md5.SetCheck(1); c_des.SetCheck(1); c_string.SetCheck(1); 
	myDES = new DES2();
	GetDlgItem(success_pic)->ShowWindow(SW_HIDE); 
	GetDlgItem(IDC_STATICsu)->ShowWindow(SW_HIDE);
	send.EnableWindow(FALSE); 
	encry.EnableWindow(FALSE);
	decry.EnableWindow(FALSE);
	memset(szPlaintextData, 0, 8192);
	memset(bitsCiphertextAnyLength, 0, 32768);
	memset(hexCiphertextAnyLength, 0, 16384);
	memset(szCiphertextData, 0, 8192);
	memset(szSourceKey1, 0, 8);
	memset(szSourceKey2, 0, 8);

	//创建初始文件夹
	CreateFolder();

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CCurProjectDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		//CRect rect;
		//CPaintDC dc(this);
		//GetClientRect(rect);
		//dc.FillSolidRect(rect, RGB(255,255,255));
		//dc.FillPath();

		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CCurProjectDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

int write_string_to_file_append(const std::string& file_string, const std::string str)
{
	std::ofstream	OsWrite(file_string, std::ofstream::app);
	OsWrite << str;
	OsWrite << std::endl;
	OsWrite.close();
	return 0;
}




//将1位字符串转化为8bit
string sinStrToBitStr(char c) {
	bitset<8> bits = bitset<8>(c);
	string s = bits.to_string();
	return s;
}

//将8位字符串转化为64bit
string StrToBitStr(string str)
{
	bitset<64> bstr;
	for (int i = 0; i < 8; i++)
	{
		bitset<8> bits = bitset<8>(str[i]);
		for (int j = 0; j < 8; j++)
		{
			bstr[i * 8 + j] = bits[7 - j];
		}
	}
	string s = bstr.to_string();
	//添加一个翻转操作
	reverse(begin(s), end(s));
	return s;
}


string longstrtobit(string str) {
	string bitstring;
	string temp;
	int i = 0, j = 0;
	if (str.length() % 8 == 0) {
		for (int i = 0; i < str.length() / 8; i++) {
			bitstring += StrToBitStr(str.substr(i * 8, i * 8 + 8));
		}
		return bitstring;
	}
	else {
		for (i = 0; i < str.length() / 8; i++) {
			bitstring += StrToBitStr(str.substr(i * 8, i * 8 + 8));
		}
		temp = str.substr(i * 8, i * 8 + str.length() % 8);
		for (j = 0; j < (str.length() % 8); j++)
		{
			bitstring += sinStrToBitStr(temp[j]);
		}
		for (int m = 0; m < 8 - str.length() % 8; m++) {
			bitstring += "00000000";
		}
		return bitstring;
	}
}
// 将64bit二进制字符串转化为字符串
string BitStrToStr(string bstr)
{
	string str = "";
	//每八位转化成十进制，然后将数字结果转化成字符
	int sum;
	for (int i = 0; i < bstr.size(); i += 8)
	{
		sum = 0;
		for (int j = 0; j < 8; j++)
			if (bstr[i + j] == '1')
				sum = sum * 2 + 1;
			else
				sum = sum * 2;
		str = str + char(sum);
	}
	return str;

}

string padding_str(string str) {
	if (str.length() % 128 == 0) {
		return str;
	}
	else {
		string temp = str;
		temp += "0000000000000000000000000000000000000000000000000000000000000000";
		return temp;
	}
}

string en_Aesstring(string k, string str_pl, string& en_text) {
	
	string keyStr = k;   //秘钥再长也只读16位
	bitset<8> key[16];  //16个8bit的数组 （二维数组）
	charToByte(key, keyStr.c_str());
	// 密钥扩展
	bitset<32> w[4 * (Nr + 1)];
	KeyExpansion(key, w);
	bitset<128> data;
	bitset<8> plain[16];
	string in;
	string out, de_out;
	string bitstring = padding_str(longstrtobit(str_pl));

	for (int i = 0; i < bitstring.length() / 128; i++)
	{
		data = bitset<128>(bitstring.substr(i * 128, i * 128 + 128));
		divideToByte(plain, data);
		encrypt(plain, w);
		data = mergeByte(plain);
		out += data.to_string();
		data.reset();  // 置0
	}
	en_text =  out;
	return en_text;
}

void CCurProjectDlg::de_Aesstring(string k, string out) {
	string keyStr = k;   //秘钥再长也只读16位
	bitset<8> key[16];  //16个8bit的数组 （二维数组）
	charToByte(key, keyStr.c_str());
	// 密钥扩展
	bitset<32> w[4 * (Nr + 1)];
	KeyExpansion(key, w);
	bitset<128> data;
	bitset<8> plain[16];
	string  de_out,full_text,full_text2,plain_text,hash_str,_out;

	for (int i = 0; i < out.length() / 128; i++)
	{
		data = bitset<128>(out.substr(i * 128, i * 128 + 128));
		divideToByte(plain, data);
		decrypt(plain, w);
		data = mergeByte(plain);
		de_out += data.to_string();
		data.reset();  // 置0
	}
	de_out = BitStrToStr(de_out);
	info_B.ReplaceSel("字符串AES解密："+ CString(de_out.c_str())+"\r\n");
	full_text = de_out; full_text2 = de_out;
	std::vector<std::string> ls;
	cgl::stringsplit(ls, full_text.c_str(), full_text.length(), '|', false);
	plain_text = ls[0];
	hash_str = full_text2.erase(0, plain_text.length() + 1);
	info_B.ReplaceSel("已分解加密字符串：\r\n");
	info_B.ReplaceSel("明文部分：" + CString(plain_text.c_str()) + "\r\n");
	info_B.ReplaceSel("Hash值部分：" + CString(hash_str.c_str()) + "\r\n");
	RSA::encrypt(st_msg, N_A, E_A);
	info_B.ReplaceSel("A公钥解密Hash值部分：" + CString(st_msg.toString().c_str()) + "\r\n");

	MD5String((unsigned char*)plain_text.c_str(), _out);
	transform(_out.begin(), _out.end(), _out.begin(), ::toupper);
	string comparemd5 = _out;

	SHA1 checksum;
	checksum.update(plain_text.c_str());
	_out = checksum.final();
	transform(_out.begin(), _out.end(), _out.begin(), ::toupper);
	string comparesha = _out;

	if (comparemd5 == MD5_pstr.GetBuffer() || comparesha == SHA1_pstr.GetBuffer()) {
		info_B.ReplaceSel("经Hash值校验，字符串未被篡改！\r\n");
		info_B.ReplaceSel("\r\n");
	}
	else {
		info_B.ReplaceSel("经Hash值校验，字符串已被篡改！\r\n");
		info_B.ReplaceSel("\r\n");
	}
}


void CCurProjectDlg::en_Aesfile(string k, string aes_fpath ,string enaes_path) {

	long fileSize=0, hasDone=0;
	//string append = aes_fpath.substr(aes_fpath.find_last_of(".") + 1);
	string keyStr = k;   //秘钥再长也只读16位
	bitset<8> key[16];  //16个8bit的数组 （二维数组）
	charToByte(key, keyStr.c_str());
	// 密钥扩展
	bitset<32> w[4 * (Nr + 1)];
	KeyExpansion(key, w);

	bitset<128> data;
	bitset<8> plain[16];
	ifstream in;
	ofstream out;

	in.open(aes_fpath, ios::binary);
	

	prcsbar.SetRange(0, 100);
	prcsbar.ShowWindow(SW_SHOW);
	
	in.seekg(0, in.end);
	fileSize = in.tellg();
	in.seekg(0, in.beg);
	out.open(enaes_path, ios::binary);
	while (in.read((char*)&data, sizeof(data)))
	{
		divideToByte(plain, data);
		encrypt(plain, w);
		data = mergeByte(plain);
		out.write((char*)&data, sizeof(data));
		data.reset();  // 置0
		hasDone += 16;
		prcsbar.SetPos((int)(hasDone * 100 / fileSize));
	}
	in.close();
	out.close();
	prcsbar.SetPos(100);
	//remove((getcurrentpath() + "/AFile/aes_cipher.txt").c_str());
}

void CCurProjectDlg::de_DesFile()
{
	FILE* fpSrc, * fpDst;
	CString szSrcPath, szDstPath, szKey1, delhash;
	string out;
	char buff[8] = { 0 };
	long fileSize = 0, hasDone = 0;

	edt_dekey.GetWindowText(szKey1);

	edt_B.GetWindowText(szSrcPath);
	char drive[_MAX_DRIVE];
	char dir[_MAX_DIR];
	char fname[_MAX_FNAME];
	char ext[_MAX_EXT];
	_splitpath(szSrcPath, drive, dir, fname, ext);
	szDstPath = CString(getcurrentpath().c_str()) + "\\BFile\\" + fname +".hash";
	delhash = CString(getcurrentpath().c_str()) + "\\BFile\\" + fname;

	if ((fpSrc = fopen(szSrcPath.GetBuffer(), "rb")) == NULL)
	{
		MessageBox("打不开源文件!", "错误", MB_OK | MB_ICONERROR);
		return;
	}
	if ((fpDst = fopen(szDstPath.GetBuffer(), "wb")) == NULL)
	{
		MessageBox("打不开目的文件!", "错误", MB_OK | MB_ICONERROR);
		return;
	}

	fseek(fpSrc, 0, SEEK_SET);
	fseek(fpSrc, 0, SEEK_END);
	fileSize = ftell(fpSrc);
	rewind(fpSrc);
	prcsbar.SetRange(0, 100);
	prcsbar.ShowWindow(SW_SHOW);
	memset(szSourceKey1, 0, 8);
	memcpy(szSourceKey1, szKey1.GetBuffer(), szKey1.GetLength() < 8 ? szKey1.GetLength() : 8);
	myDES->InitializeKey(szSourceKey1, 0);


		while (!feof(fpSrc))
		{
			memset(buff, 0, 8);
			fread(buff, sizeof(char), 8, fpSrc);
			myDES->DecryptData(buff, 0);
			fwrite(myDES->GetPlaintext(), sizeof(char), 8, fpDst);
			hasDone += 8;
			prcsbar.SetPos((int)(hasDone * 100 / fileSize));
		}

	fclose(fpSrc);
	fclose(fpDst);
	prcsbar.SetPos(100);

	string str = del_hashline(szDstPath.GetBuffer(), delhash.GetBuffer());
	info_B.ReplaceSel("文件DES解密：\r\n");
	info_B.ReplaceSel("已提取Hash值为：" + CString(str.c_str()) + "\r\n");
	RSA::encrypt(st_msg, N_A, E_A);
	info_B.ReplaceSel("A公钥解密Hash值部分：" + CString(st_msg.toString().c_str()) + "\r\n");

	MDFile(delhash.GetBuffer(), out);
	transform(out.begin(), out.end(), out.begin(), ::toupper);
	//string compare = st_msg.toString();
	string comparemd5 = out;

	SHA1 checksum;
	out = checksum.from_file(delhash.GetBuffer());
	transform(out.begin(), out.end(), out.begin(), ::toupper);
	string comparesha = out;

	//省去私钥解密的环节直接用字符串得到的Hash与未加密的Hash进行比对
	if (comparemd5 == MD5_pstr.GetBuffer() || comparesha == SHA1_pstr.GetBuffer()) {
		info_B.ReplaceSel("经Hash值校验，文件未被篡改！\r\n");
		info_B.ReplaceSel("\r\n");
	}
	else {
		info_B.ReplaceSel("经Hash值校验，文件已被篡改！\r\n");
		info_B.ReplaceSel("\r\n");
	}



	MessageBox("解密完成!", "提示", MB_OK | MB_ICONINFORMATION);
	prcsbar.ShowWindow(SW_HIDE);
}

void CCurProjectDlg::de_DesStr()
{
	CString strKey, strPlaintext, strCiphertext;
	string full_text,plain_text, hash_str, full_text2 ,out;

	edt_dekey.GetWindowText(strKey);
	edt_B.GetWindowText(strCiphertext);

	memset(szSourceKey1, 0, 8);
	memset(szCiphertextData, 0, 8192);
	memcpy(szSourceKey1, strKey.GetBuffer(), strKey.GetLength() < 8 ? strKey.GetLength() : 8);

	myDES->InitializeKey(szSourceKey1, 0);
		
	//Decrypt		
	myDES->DecryptAnyLength(szCiphertextData, ConvertOtherFormat2Ciphertext(strCiphertext.GetBuffer()), 0);
	full_text = myDES->GetPlaintextAnyLength(); full_text2 = myDES->GetPlaintextAnyLength();
	info_B.ReplaceSel("字符串DES解密："+ CString(full_text.c_str())+"\r\n");
	std::vector<std::string> ls;
	cgl::stringsplit(ls, full_text.c_str(), full_text.length(), '|',false);
	plain_text = ls[0];
	hash_str = full_text2.erase(0,plain_text.length()+1);
	info_B.ReplaceSel("已分解加密字符串：\r\n");
	info_B.ReplaceSel("明文部分：" + CString(plain_text.c_str())+"\r\n");
	info_B.ReplaceSel("Hash值部分：" + CString(StringTrans(hash_str.c_str(), N_A.GetBitLength() - 17).toString().c_str() )+ "\r\n");
	RSA::encrypt(st_msg, N_A, E_A);
	info_B.ReplaceSel("A公钥解密Hash值部分："+ CString(st_msg.toString().c_str())+ "\r\n"); 

	MD5String((unsigned char*)plain_text.c_str(), out);
	transform(out.begin(), out.end(), out.begin(), ::toupper);
	//string compare = st_msg.toString();
	string comparemd5 = out;

	SHA1 checksum;
	checksum.update(plain_text.c_str());
	out = checksum.final();
	transform(out.begin(), out.end(), out.begin(), ::toupper);
	string comparesha = out;

	//省去私钥解密的环节直接用字符串得到的Hash与未加密的Hash进行比对
	if (comparemd5 == MD5_pstr.GetBuffer() || comparesha == SHA1_pstr.GetBuffer()) {
		info_B.ReplaceSel("经Hash值校验，字符串未被篡改！\r\n");
		info_B.ReplaceSel("\r\n");
	}
	else {
		info_B.ReplaceSel("经Hash值校验，字符串已被篡改！\r\n");
		info_B.ReplaceSel("\r\n");
	}
}

void CCurProjectDlg::de_Aesfile(string k, string enaes_path, string deaes_path) {

	string keyStr = k;   //秘钥再长也只读16位
	bitset<8> key[16];  //16个8bit的数组 （二维数组）
	charToByte(key, keyStr.c_str());
	// 密钥扩展
	bitset<32> w[4 * (Nr + 1)];
	KeyExpansion(key, w);

	bitset<128> data;
	bitset<8> plain[16];
	ifstream in;
	ofstream out;
	in.open(enaes_path, ios::binary);
	out.open(deaes_path, ios::binary);
	while (in.read((char*)&data, sizeof(data)))
	{
		divideToByte(plain, data);
		decrypt(plain, w);
		data = mergeByte(plain);
		out.write((char*)&data, sizeof(data));
		data.reset();  // 置0
	}
	in.close();
	out.close();
}

string en_Desstring(string k,string str_pl ,string &en_text, string &de_text) {
	key = charToBitset(k.c_str());
	generateKeys();   // 生成16个子密钥

	string in;
	string out, de_out;
	string bitstring = longstrtobit(str_pl);
	bitset<64> plain;
	for (int i = 0; i < bitstring.length() / 64; i++)
	{
		plain = bitset<64>(bitstring.substr(i * 64, i * 64 + 64));
		bitset<64> cipher = encrypt(plain);
		out += cipher.to_string();
		plain.reset();  // 置0
	}
	en_text = out;
	for (int i = 0; i < out.length() / 64; i++)
	{
		plain = bitset<64>(out.substr(i * 64, i * 64 + 64));
		bitset<64> temp = decrypt(plain);
		de_out += temp.to_string();
		plain.reset();  // 置0
	}
	de_text = de_out;

	return BitStrToStr(de_out);
}

void en_Desfile(string k, string des_fpath) {
	key = charToBitset(k.c_str());
	generateKeys();   // 生成16个子密钥

	ifstream in;
	ofstream out;
	string append = des_fpath.substr(des_fpath.find_last_of(".") + 1);
	//可以具体指导文件名和拓展但是为了区别传送的和接收的文件不做处理。
	//char path_buffer[_MAX_PATH];
	//char drive[_MAX_DRIVE];
	//char dir[_MAX_DIR];
	//char fname[_MAX_FNAME];
	//char ext[_MAX_EXT];
	//_splitpath(des_fpath.c_str(), drive, dir, fname, ext);
	//printf("Drive:%s\n file name: %s\n file type: %s\n", drive, fname, ext);
	//strcat(fname, ext);
	//printf("File name with extension :%s\n", fname);

	in.open(des_fpath, ios::binary);
	out.open((getcurrentpath() + "/AFile/descipher.txt"), ios::binary);
	bitset<64> plain;
	while (in.read((char*)&plain, sizeof(plain)))
	{
		bitset<64> cipher = encrypt(plain);
		out.write((char*)&cipher, sizeof(cipher));
		plain.reset();  // 置0
	}
	in.close();
	out.close();
	in.open((getcurrentpath() + "/AFile/descipher.txt"), ios::binary);
	out.open((getcurrentpath() + "/BFile/receive."+append), ios::binary);

	while (in.read((char*)&plain, sizeof(plain)))
	{
		bitset<64> temp = decrypt(plain);
		out.write((char*)&temp, sizeof(temp));
		plain.reset();  // 置0
	}
	in.close();
	out.close();
	//remove((getcurrentpath() + "/AFile/descipher.txt").c_str());

}


void CCurProjectDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	file_or_str = 0;
	CString filename;//保存路径

	CFileDialog openfiledlg(TRUE,
		NULL,
		NULL,
		OFN_OVERWRITEPROMPT,
		_T(""),//指定要打开的文件类型
		NULL);
	
	if (openfiledlg.DoModal() == IDOK)
	{
		filename = openfiledlg.GetPathName();
		file_or_str = 1;
	}
	edt_A.SetWindowTextA(filename);

}

void CCurProjectDlg::OnBnClickedButton2()
{

	//CString filename;//保存路径
	//CFileDialog openfiledlg(TRUE,
	//	NULL,
	//	NULL,
	//	OFN_OVERWRITEPROMPT,
	//	_T(""),//指定要打开的文件类型
	//	NULL);
	//string pp = getcurrentpath()+"\\BFile";
	//openfiledlg.m_ofn.lpstrInitialDir = _T(pp.c_str());//.m_ofn.lpstrInitialDir = _T("./ackup");//这里设置默认路径Top
	//if (openfiledlg.DoModal() == IDOK)
	//{
	//	filename = openfiledlg.GetPathName();

	//}
	//edt_B.SetWindowTextA(filename);
	ShellExecute(NULL, _T("explore"), _T(getcurrentpath().c_str() + CString("/BFile")), NULL, NULL, SW_SHOWNORMAL);
}

void ThreadFunc()

{
	CWnd* h_d2 = AfxGetApp()->GetMainWnd();
	//HWND m_hWnd = ::FindWindow(NULL, _T("time"));
	//HWND hWndControl = GetDlgItem(m_hWnd, IDC_STATIC);
	h_d2->GetDlgItem(success_pic)->ShowWindow(SW_SHOW);
	h_d2->GetDlgItem(IDC_STATICsu)->ShowWindow(SW_SHOW);
	Sleep(3000);
	h_d2->GetDlgItem(success_pic)->ShowWindow(SW_HIDE);
	h_d2->GetDlgItem(IDC_STATICsu)->ShowWindow(SW_HIDE);
}

void CCurProjectDlg::OnBnClickedOk()
{
	CString send_key ,plain, filepath_hash;
	edt_key.GetWindowTextA(send_key);
	StringTrans st(send_key.GetBuffer(), N_B.GetBitLength() - 17);
	RSA::encrypt(st, N_B, E_B);
	info_A.ReplaceSel(_T("秘钥已用B的公钥加密并传送!\r\n"));
	rsa_B->decrypt(st);
	edt_dekey.SetWindowTextA(st.toString().c_str());
	info_B.ReplaceSel(_T("传送成功！\r\n"));
	info_B.ReplaceSel(_T("收到与A通信的对称秘钥并显示在秘钥框！\r\n"));

	hThread = CreateThread(NULL,

		0,

		(LPTHREAD_START_ROUTINE)ThreadFunc,

		NULL,

		0,

		&ThreadID);


	UINT nType;
	//process.SetPos(0); 
	//GetDlgItem(success_pic)->ShowWindow(SW_HIDE);
	// TODO: 在此添加控件通知处理程序代码
	nType = GetCheckedRadioButton(IDC_RADIO5, IDC_RADIO6);
	switch (nType)
	{
	case IDC_RADIO6:
		edt_A.GetWindowTextA(plain);
		edt_B.SetWindowTextA(plain);

		
		break;
	case IDC_RADIO5:
		edt_A.GetWindowTextA(plain);
		char drive[_MAX_DRIVE];
		char dir[_MAX_DIR];
		char fname[_MAX_FNAME];
		char ext[_MAX_EXT];
		_splitpath(plain, drive, dir, fname, ext);
		filepath_hash = CString(getcurrentpath().c_str()) + "\\BFile\\" + fname + ext ;
		edt_B.SetWindowTextA(filepath_hash);
		CopyFile(plain.GetBuffer(), filepath_hash.GetBuffer(), FALSE);

	
		break;
	default:
		MessageBox("传输失败！");
		break;
	}
	edt_A.SetWindowTextA("");
	send.EnableWindow(FALSE);
	decry.EnableWindow(TRUE);
	
}




void CCurProjectDlg::OnBnClickedButton3()
{
	// TODO: 在此添加控件通知处理程序代码
	int keyLength = 256;
	rsa_A = new RSA(keyLength);
	rsa_B = new RSA(keyLength);
	rsa_A->getPublicKey(N_A, E_A);
	rsa_B->getPublicKey(N_B, E_B);
	info_A.ReplaceSel(_T("A的公钥:\r\nN:" + CString(N_A.ToHexString().c_str()) + "\r\nE:"+ CString(E_A.ToHexString().c_str())));
	info_A.ReplaceSel(_T("\r\nA的私钥已生成!\r\n"));
	info_B.ReplaceSel(_T("B的公钥:\r\nN:" + CString(N_B.ToHexString().c_str()) + "\r\nE:" + CString(E_B.ToHexString().c_str())));
	info_B.ReplaceSel(_T("\r\nB的私钥已生成!\r\n"));
	encry.EnableWindow(TRUE);
	initial.EnableWindow(FALSE);
}


void CCurProjectDlg::OnBnClickedButton4()
{
	// TODO: 在此添加控件通知处理程序代码
	UINT nEncry;
	CString key, plain, szSrcPath, szDstPath, delhash; string out;
	edt_B.GetWindowTextA(plain); edt_dekey.GetWindowTextA(key);
	nEncry = GetCheckedRadioButton(IDC_RADIO3, IDC_RADIO4);
	BOOL up = UpdateData(TRUE);
	if (up) {
		switch (nEncry) {
		case IDC_RADIO3:
			if (c_string.GetCheck()) {
				de_DesStr();
			}
			else {
				de_DesFile();
			}
			break;
		case IDC_RADIO4:
				if (c_string.GetCheck()) {
					de_Aesstring(key.GetBuffer(), plain.GetBuffer());
				}
				else {
					info_B.ReplaceSel("文件AES解密：\r\n");
					edt_B.GetWindowText(szSrcPath);
					char drive[_MAX_DRIVE];
					char dir[_MAX_DIR];
					char fname[_MAX_FNAME];
					char ext[_MAX_EXT];
					_splitpath(szSrcPath, drive, dir, fname, ext);
					szDstPath = CString(getcurrentpath().c_str()) + "\\BFile\\" + fname + ".hash";
					delhash = CString(getcurrentpath().c_str()) + "\\BFile\\" + fname;
					de_Aesfile(key.GetBuffer(),szSrcPath.GetBuffer(),szDstPath.GetBuffer());

					string str = del_hashline(szDstPath.GetBuffer(), delhash.GetBuffer());
					info_B.ReplaceSel("已提取Hash值为：" + CString(str.c_str()) + "\r\n");
					RSA::encrypt(st_msg, N_A, E_A);
					info_B.ReplaceSel("A公钥解密Hash值部分：" + CString(st_msg.toString().c_str()) + "\r\n");

					MDFile(delhash.GetBuffer(), out);
					transform(out.begin(), out.end(), out.begin(), ::toupper);
					//string compare = st_msg.toString();
					string comparemd5 = out;

					SHA1 checksum;
					out = checksum.from_file(delhash.GetBuffer());
					transform(out.begin(), out.end(), out.begin(), ::toupper);
					string comparesha = out;

					//省去私钥解密的环节直接用字符串得到的Hash与未加密的Hash进行比对
					if (comparemd5 == MD5_pstr.GetBuffer() || comparesha == SHA1_pstr.GetBuffer()) {
						info_B.ReplaceSel("经Hash值校验，文件未被篡改！\r\n");
						info_B.ReplaceSel("\r\n");
					}
					else {
						info_B.ReplaceSel("经Hash值校验，文件已被篡改！\r\n");
						info_B.ReplaceSel("\r\n");
					}
					MessageBox("解密完成!", "提示", MB_OK | MB_ICONINFORMATION);
					prcsbar.ShowWindow(SW_HIDE);
				}
			break;
		default:
			MessageBox(_T("还未选择"), MB_OK);
		}
	}
	decry.EnableWindow(FALSE);
}


void CCurProjectDlg::OnBnClickedButton5()
{	
	// TODO: 在此添加控件通知处理程序代码
	UINT nEncry, nHash;
	CString strKey, strPlaintext,str;
	FILE* fpSrc, * fpDst;
	CString szSrcPath, szDstPath;
	CString file_path, hash_str;
	string out;
	edt_key.GetWindowText(strKey);
	edt_A.GetWindowText(str);

	char buff[8] = { 0 };
	long fileSize = 0, hasDone = 0;
	if (strKey.GetLength() < 9) {
		MessageBox(_T("秘钥最小长度为9！"), _T("警告"), MB_OK | MB_ICONWARNING);
	}
	else {
		if (str.IsEmpty()) {
			MessageBox(_T("还未选择要加密的字符串或文件！"), _T("提示"), MB_OK | MB_ICONWARNING);
		}
		else if (strKey.IsEmpty()) {
			MessageBox(_T("未填入加密秘钥！"), _T("提示"), MB_OK | MB_ICONWARNING);
		}
		else {
			BOOL m_Value = UpdateData(TRUE);
			if ((m_Value)) {
				nEncry = GetCheckedRadioButton(IDC_RADIO3, IDC_RADIO4);
				nHash = GetCheckedRadioButton(IDC_RADIO1, IDC_RADIO2);
				info_A.ReplaceSel(_T("选择Hash算法："));
				switch (nHash) {
				case IDC_RADIO1:
					info_A.ReplaceSel(_T("MD5\r\n"));
					if (file_or_str) {
						edt_A.GetWindowTextA(file_path);
						MDFile(file_path.GetBuffer(0), out);
						transform(out.begin(), out.end(), out.begin(), ::toupper);
						info_A.ReplaceSel(_T("文件的MD5值为:" + CString(out.c_str()) + "\r\n"));
					}
					else {
						edt_A.GetWindowTextA(hash_str);
						MD5String((unsigned char*)hash_str.GetBuffer(0), out);
						transform(out.begin(), out.end(), out.begin(), ::toupper);
						info_A.ReplaceSel(_T("字符串的MD5值为:" + CString(out.c_str()) + "\r\n"));
					}
					MD5_pstr = CString(out.c_str());
					st_msg = StringTrans(out, N_A.GetBitLength() - 17);
					rsa_A->decrypt(st_msg);
					MD5str = st_msg.toHexString().c_str();
					info_A.ReplaceSel("A私钥加密后的消息验证码：" + MD5str + "\r\n");
					SHA1str = "";
					SHA1_pstr = "";
					break;
				case IDC_RADIO2:
					info_A.ReplaceSel(_T("SHA1\r\n"));
					if (file_or_str) {
						edt_A.GetWindowTextA(file_path);
						SHA1 checksum;
						out = checksum.from_file(file_path.GetBuffer());
						transform(out.begin(), out.end(), out.begin(), ::toupper);
						info_A.ReplaceSel(_T("文件的SHA1值为:" + CString(out.c_str()) + "\r\n"));
					}
					else {
						edt_A.GetWindowTextA(hash_str);
						SHA1 checksum;
						checksum.update(hash_str.GetBuffer());
						out = checksum.final();
						transform(out.begin(), out.end(), out.begin(), ::toupper);
						info_A.ReplaceSel(_T("字符串的SHA1值为:" + CString(out.c_str()) + "\r\n"));
					}
					SHA1_pstr = CString(out.c_str());
					st_msg = StringTrans(out, N_A.GetBitLength() - 17);
					rsa_A->decrypt(st_msg);
					SHA1str = st_msg.toHexString().c_str();
					info_A.ReplaceSel("A私钥加密后的消息验证码：" + SHA1str + "\r\n");
					MD5str = "";
					MD5_pstr = "";
					break;
				default:
					MessageBox(_T("还未选择"), MB_OK);
				}

				info_A.ReplaceSel(_T("选择加密算法："));
				switch (nEncry) {
				case IDC_RADIO3:
					info_A.ReplaceSel(_T("DES\r\n"));
					if (!file_or_str) {
						string methond;
						DES2* myDES = new DES2();
						edt_A.GetWindowText(strPlaintext);
						CString window = strPlaintext;
						strPlaintext += '|';

						MD5str.IsEmpty() ? (strPlaintext += SHA1str) : (strPlaintext += MD5str);
						MD5str.IsEmpty() ? methond = "SHA1" : methond = "MD5";
						memset(szSourceKey1, 0, 8);
						memset(szSourceKey2, 0, 8);
						memset(szPlaintextData, 0, 8192);
						memcpy(szSourceKey1, strKey.GetBuffer(), strKey.GetLength() < 8 ? strKey.GetLength() : 8);

						myDES->InitializeKey(szSourceKey1, 0);
						//myDES->EncryptAnyLength((char*)(LPCTSTR)strPlaintext,strPlaintext.GetLength());
						memcpy(szPlaintextData, strPlaintext.GetBuffer(), strPlaintext.GetLength());

						myDES->EncryptAnyLength(szPlaintextData, strlen(szPlaintextData), 0);

						ConvertCiphertext2OtherFormat(strlen(szPlaintextData) % 8 == 0 ? strlen(szPlaintextData) << 3 : ((strlen(szPlaintextData) >> 3) + 1) << 6, myDES->GetCiphertextAnyLength());
						edt_A.SetWindowText((hexCiphertextAnyLength));
						info_A.ReplaceSel("字符串：“" + window + "”已与" + methond.c_str() + "值一同加密！\r\n");
						info_A.ReplaceSel("AES密文已显示在对话框，可以传送！\r\n");
						send.EnableWindow(TRUE);

					}
					else {
						edt_A.GetWindowText(szSrcPath);
						char drive[_MAX_DRIVE];
						char dir[_MAX_DIR];
						char fname[_MAX_FNAME];
						char ext[_MAX_EXT];
						_splitpath(szSrcPath, drive, dir, fname, ext);
						szDstPath = CString(getcurrentpath().c_str()) + "\\AFile\\" + fname + ext + ".des";

						if (MD5str.IsEmpty()) {
							string str = "|"; str = str + SHA1str.GetBuffer();
							add_hash(szSrcPath.GetBuffer(), str);
						}
						else {
							string str = "|"; str = str + MD5str.GetBuffer();
							add_hash(szSrcPath.GetBuffer(), str);
						}
						szSrcPath = szSrcPath + "_hash";

						if ((fpSrc = fopen(szSrcPath.GetBuffer(), "rb")) == NULL)
						{
							MessageBox("打不开源文件!", "错误", MB_OK | MB_ICONERROR);
							return;
						}
						if ((fpDst = fopen(szDstPath.GetBuffer(), "wb")) == NULL)
						{
							MessageBox("打不开目的文件!", "错误", MB_OK | MB_ICONERROR);
							return;
						}

						fseek(fpSrc, 0, SEEK_SET);
						fseek(fpSrc, 0, SEEK_END);
						fileSize = ftell(fpSrc);
						rewind(fpSrc);
						prcsbar.SetRange(0, 100);
						prcsbar.ShowWindow(SW_SHOW);
						memset(szSourceKey1, 0, 8);
						memcpy(szSourceKey1, strKey.GetBuffer(), strKey.GetLength() < 8 ? strKey.GetLength() : 8);
						myDES->InitializeKey(szSourceKey1, 0);


						while (!feof(fpSrc))
						{
							memset(buff, 0, 8);
							fread(buff, sizeof(char), 8, fpSrc);
							myDES->EncryptData(buff, 0);
							fwrite(myDES->GetCiphertextInBytes(), sizeof(char), 8, fpDst);
							hasDone += 8;
							prcsbar.SetPos((int)(hasDone * 100 / fileSize));
						}
						fclose(fpSrc);
						fclose(fpDst);
						prcsbar.SetPos(100);
						edt_A.SetWindowTextA(szDstPath);
						MessageBox("签名加密完成，文件路径已显示在对话框!", "提示", MB_OK | MB_ICONINFORMATION);
						info_A.ReplaceSel(_T("文件已签名DES加密完成可以传送！\r\n"));
						prcsbar.ShowWindow(SW_HIDE);
						//删除临时文件
						DeleteFile(szSrcPath); // 文件名指针
						send.EnableWindow(TRUE);
					}
					break;
				case IDC_RADIO4:
					info_A.ReplaceSel(_T("AES\r\n"));
					if (file_or_str) {
						CString k, str_pl;
						edt_key.GetWindowTextA(k);
						edt_A.GetWindowTextA(str_pl);

						char drive[_MAX_DRIVE];
						char dir[_MAX_DIR];
						char fname[_MAX_FNAME];
						char ext[_MAX_EXT];
						_splitpath(str_pl, drive, dir, fname, ext);
						szDstPath = CString(getcurrentpath().c_str()) + "\\AFile\\" + fname + ext + ".aes";//没有设置好目标地址明天写！

						if (MD5str.IsEmpty()) {
							string str = "|"; str = str + SHA1str.GetBuffer();
							add_hash(str_pl.GetBuffer(), str);
						}
						else {
							string str = "|"; str = str + MD5str.GetBuffer();
							add_hash(str_pl.GetBuffer(), str);
						}
						str_pl = str_pl + "_hash";


						en_Aesfile(k.GetBuffer(), str_pl.GetBuffer(), szDstPath.GetBuffer());
						edt_A.SetWindowTextA(szDstPath);
						MessageBox("签名加密完成，文件路径已显示在对话框!", "提示", MB_OK | MB_ICONINFORMATION);
						info_A.ReplaceSel(_T("文件已签名AES加密完成可以传送！\r\n"));
						send.EnableWindow(TRUE);
						prcsbar.ShowWindow(SW_HIDE);
						//删除临时文件
						DeleteFile(str_pl); // 文件名指针
					}
					else {
						CString k, str_pl, window;
						string en_text, de_text, methond;
						edt_key.GetWindowTextA(k);
						edt_A.GetWindowTextA(str_pl);
						window = str_pl;
						str_pl += '|';
						MD5str.IsEmpty() ? (str_pl += SHA1str) : (str_pl += MD5str);
						MD5str.IsEmpty() ? methond = "SHA1" : methond = "MD5";
						en_Aesstring(k.GetBuffer(), str_pl.GetBuffer(), en_text);
						info_A.ReplaceSel("字符串：“" + window + "”已与" + methond.c_str() + "值一同加密！\r\n");
						info_A.ReplaceSel("AES密文已显示在对话框，可以传送！\r\n");
						send.EnableWindow(TRUE);
						edt_A.SetWindowText(CString(en_text.c_str()));
					}
					break;
				default:
					MessageBox(_T("还未选择"), MB_OK);
				}
				file_or_str = 0;
			}
		}
	}
	
}

//保存对话框及其所有子窗体的Rect区域  
void CCurProjectDlg::GetInitRect()
{

	CRect rect;
	GetWindowRect(&rect);
	m_listRect.AddTail(rect);//对话框的区域  

	CWnd* pWnd = GetWindow(GW_CHILD);//获取子窗体  
	while (pWnd)
	{
		pWnd->GetWindowRect(rect);//子窗体的区域  
		m_listRect.AddTail(rect);           //CList<CRect,CRect> m_listRect成员变量  
		pWnd = pWnd->GetNextWindow();//取下一个子窗体  
	}
}

void CCurProjectDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialogEx::OnSize(nType, cx, cy);

	// TODO: 在此处添加消息处理程序代码
	if (m_listRect.GetCount() > 0)
	{
		CRect dlgNow;
		GetWindowRect(&dlgNow);
		POSITION pos = m_listRect.GetHeadPosition();//第一个保存的是对话框的Rect  

		CRect dlgSaved;
		dlgSaved = m_listRect.GetNext(pos);
		ScreenToClient(dlgNow);

		float x = dlgNow.Width() * 1.0 / dlgSaved.Width();//根据当前和之前保存的对话框的宽高求比例  
		float y = dlgNow.Height() * 1.0 / dlgSaved.Height();
		ClientToScreen(dlgNow);

		CRect childSaved;

		CWnd* pWnd = GetWindow(GW_CHILD);
		while (pWnd)
		{
			childSaved = m_listRect.GetNext(pos);//依次获取子窗体的Rect  
			childSaved.left = dlgNow.left + (childSaved.left - dlgSaved.left) * x;//根据比例调整控件上下左右距离对话框的距离  
			childSaved.right = dlgNow.right + (childSaved.right - dlgSaved.right) * x;
			childSaved.top = dlgNow.top + (childSaved.top - dlgSaved.top) * y;
			childSaved.bottom = dlgNow.bottom + (childSaved.bottom - dlgSaved.bottom) * y;
			ScreenToClient(childSaved);
			pWnd->MoveWindow(childSaved);
			pWnd = pWnd->GetNextWindow();
		}

	}
	Invalidate(); //强制重绘窗口
}


void CCurProjectDlg::OnBnClickedButton6()
{
	// TODO: 在此添加控件通知处理程序代码
	info_A.SetWindowTextA("");
	info_A.ReplaceSel(_T("A的公钥:\r\nN:" + CString(N_A.ToHexString().c_str()) + "\r\nE:" + CString(E_A.ToHexString().c_str())));
	info_A.ReplaceSel(_T("\r\nA的私钥已生成!\r\n"));
}


void CCurProjectDlg::OnBnClickedButton7()
{
	// TODO: 在此添加控件通知处理程序代码
	info_B.SetWindowTextA("");
	info_B.ReplaceSel(_T("B的公钥:\r\nN:" + CString(N_B.ToHexString().c_str()) + "\r\nE:" + CString(E_B.ToHexString().c_str())));
	info_B.ReplaceSel(_T("\r\nB的私钥已生成!\r\n"));
}
