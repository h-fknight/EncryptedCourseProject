
// CurProjectDlg.h: 头文件
//

#pragma once
#include"Rsa.h"
#include"BigInt.h"
#include"DES2.h"
#include "StringTrans.h"

// CCurProjectDlg 对话框
class CCurProjectDlg : public CDialogEx
{
// 构造
public:
	CCurProjectDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CURPROJECT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;
	DES2* myDES;
	char bitsCiphertextAnyLength[32768];
	char hexCiphertextAnyLength[16384];
	char szSourceKey1[8], szSourceKey2[8], szPlaintextData[8192], szCiphertextData[8192];
	bool bIs3DES;
	void ConvertCiphertext2OtherFormat(int iBitsLen, char* szCipherInBytes);
	int ConvertOtherFormat2Ciphertext(char* szCipherInBytes);
	
	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP();
	HANDLE hThread;
	DWORD ThreadID;
public:
	CEdit edt_A;
	CEdit edt_B;
	CButton chose_file;
	CButton open_file;
	CButton send;
	CButton encry;
	CButton decry;
	CEdit info_B;
	CEdit info_A;
	CEdit edt_key;
	CEdit edt_dekey;
	CProgressCtrl process;
	CProgressCtrl prcsbar;
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedOk();

	CButton c_md5;
	CButton c_sha1;
	CButton c_des;
	CButton c_aes;
	CButton c_string;
	CButton initial;
	afx_msg void OnBnClickedButton3();
	RSA* rsa_A;
	RSA* rsa_B;
	BigInt N_A, E_A, N_B, E_B;
	afx_msg void OnBnClickedButton4();
	afx_msg void OnBnClickedButton5();
	void de_Aesfile(string k, string enaes_path, string deaes_path);
	void en_Aesfile(string k, string aes_fpath, string enaes_path);
	void de_Aesstring(string k, string out);
	void de_DesFile();
	void de_DesStr();
	CString MD5_pstr;
	CString SHA1_pstr;
	CString MD5str;
	CString SHA1str;
	StringTrans st_msg;
	CList<CRect, CRect&> m_listRect;
	void CCurProjectDlg::GetInitRect();
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnBnClickedButton6();
	afx_msg void OnBnClickedButton7();
};
