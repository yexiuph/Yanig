#ifndef __METHOD_H__
#define __METHOD_H__

#include <string>
#include <fstream>
#include <atlstr.h>

using namespace std;

class IMethod
{
public:
	
	enum { ECB = 0, CBC = 1, CFB = 2 };
	enum { ZEROES = 0, BLANKS = 1, PKCS7 = 2 };

	IMethod();

	virtual ~IMethod();

protected:
	//Compute Signature
	virtual void Signature(char* pcSig) = 0;
	//Auxiliary Functions
	void Xor(char* buff, char const* chain);
	static void HelpThrow(string const& rostrFileIn);
	static void BytesToWord(unsigned char const* pucBytes, unsigned int& ruiWord);
	static void WordToBytes(unsigned int uiWord, unsigned char* pucBytes);

public:
	//Encryption for a string of chars
	virtual void Encrypt(char const* in, char* result, size_t n) = 0;
	//Decryption for a string of chars
	virtual void Decrypt(char const* in, char* result, size_t n) = 0;
	//Encryption for a File
	virtual void EncryptFile(string const& rostrFileIn, string const& rostrFileOut) = 0;
	//Decryption for a File
	virtual void DecryptFile(string const& rostrFileIn, string const& rostrFileOut) = 0;
	//Setting the Operation Mode
	void SetMode(int iMode);
	//Setting the Padding Mode
	void SetPadding(int iPadding);
	//Getters
	int GetKeyLength();
	int GetBlockSize();
	int GetMode();
	int GetPadding();
	int GetEncryptStringLength(const CString& strIn);
	int GetEncryptLength(int n);
	int Pad(char* in, int iLength);
	virtual void ResetChain() = 0;

protected:
	static char const* sm_szErrorMsg1;
	static char const* sm_szErrorMsg2;
	static char const* sm_szErrorMsg3;
	static char const* sm_szErrorMsg4;
	static char const* sm_szErrorMsg5;
	static char const* sm_szErrorMsg6;
	static char const* sm_szErrorMsg7;
	static char const* sm_szErrorMsg8;
	static char const* sm_szErrorMsg9;
	static char const* sm_szErrorMsg10;
	bool m_bInit;
	int	m_blockSize;
	int m_keylength;
	int m_iMode;
	int m_iPadding;
};

#endif // __METHOD_H__

