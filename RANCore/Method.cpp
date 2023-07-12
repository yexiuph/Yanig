#include "pch.h"
#include "Method.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace std;

char const* IMethod::sm_szErrorMsg1 = "FileCrypt ERROR: Encryption/Decryption Object not Initialized!";
char const* IMethod::sm_szErrorMsg2 = "FileCrypt ERROR: Illegal Operation Mode!";
char const* IMethod::sm_szErrorMsg3 = "FileCrypt ERROR: Illegal Padding Mode!";
char const* IMethod::sm_szErrorMsg4 = "FileCrypt ERROR: No Key DataSpecified!";
char const* IMethod::sm_szErrorMsg5 = "FileCrypt ERROR: Key Data Length should be > 0!";
char const* IMethod::sm_szErrorMsg6 = "Illegal Block Size!";
char const* IMethod::sm_szErrorMsg7 = "FileCrypt ERROR: Cannot open File ";
char const* IMethod::sm_szErrorMsg8 = "FileCrypt ERROR: The same File for Input and Output ";
char const* IMethod::sm_szErrorMsg9 = "FileCrypt ERROR: File ";
char const* IMethod::sm_szErrorMsg10 = " cannot be Correctly Decrypted!";

//CONSTRUCTOR
IMethod::IMethod() : m_bInit(false)
{
}

//DESTRUCTOR
IMethod::~IMethod()
{
}

void IMethod::Xor(char* buff, const char* chain)
{
	if (!m_bInit)
		throw runtime_error(sm_szErrorMsg1);

	for (int i = 0; i < m_blockSize; ++i)
	{
		*(buff + i) ^= *(chain + i);
	}
}

void IMethod::SetMode(int iMode)
{
	if (false == m_bInit)
		throw runtime_error(string(sm_szErrorMsg1));
	if (iMode<ECB || iMode>CFB)
		throw runtime_error(string(sm_szErrorMsg2));
	m_iMode = iMode;
}

void IMethod::SetPadding(int iPadding)
{
	if (false == m_bInit)
		throw runtime_error(string(sm_szErrorMsg1));
	if (iPadding<ZEROES || iPadding>PKCS7)
		throw runtime_error(string(sm_szErrorMsg3));
	m_iPadding = iPadding;
}

int IMethod::GetKeyLength()
{
	if (false == m_bInit)
		throw runtime_error(string(sm_szErrorMsg1));
	return m_keylength;
}

int IMethod::GetBlockSize()
{
	if (false == m_bInit)
		throw runtime_error(string(sm_szErrorMsg1));
	return m_blockSize;
}

int IMethod::GetMode()
{
	if (false == m_bInit)
		throw runtime_error(string(sm_szErrorMsg1));
	return m_iMode;
}

int IMethod::GetPadding()
{
	if (false == m_bInit)
		throw runtime_error(string(sm_szErrorMsg1));
	return m_iPadding;
}

int IMethod::GetEncryptStringLength(const CString& strIn)
{
	int iLen = strIn.GetLength();
	int iBlockSize = GetBlockSize();

	if (iBlockSize > 0)
	{
		int iLen1 = (iLen / iBlockSize) * iBlockSize;
		if (iLen % iBlockSize != 0)
			iLen1 += iBlockSize;
		return iLen1;
	}
	else
	{
		return iLen;
	}
}

int IMethod::GetEncryptLength(int n)
{
	int iBlockSize = GetBlockSize();

	if (iBlockSize > 0)
	{
		int iLen1 = (n / iBlockSize) * iBlockSize;
		if (n % iBlockSize != 0)
			iLen1 += iBlockSize;
		return iLen1;
	}
	else
	{
		return n;
	}
}

//Padding the input string before encryption
int IMethod::Pad(char* in, int iLength)
{
	if (!m_bInit)
		throw runtime_error(sm_szErrorMsg1);

	int iRes = iLength % m_blockSize;
	if (iRes != 0)
	{
		int iPadded = m_blockSize - iRes;
		char* pin = in + iLength;

		switch (m_iPadding)
		{
		case ZEROES:
			memset(pin, 0, iPadded);
			break;

		case BLANKS:
			memset(pin, 0x20, iPadded);
			break;

		case PKCS7:
			memset(pin, static_cast<char>(iPadded), iPadded);
			break;
		}

		return iLength + iPadded;
	}

	return iLength;
}

void IMethod::HelpThrow(string const& rostrFileIn)
{
	string ostrMsg = string("FileCrypt ERROR: Not an FileCrypt Encrypted File ") + rostrFileIn + "!";
	throw runtime_error(ostrMsg);
}

void IMethod::BytesToWord(const unsigned char* pucBytes, unsigned int& ruiWord)
{
	ruiWord = (static_cast<unsigned int>(pucBytes[0]) << 24) |
		(static_cast<unsigned int>(pucBytes[1]) << 16) |
		(static_cast<unsigned int>(pucBytes[2]) << 8) |
		static_cast<unsigned int>(pucBytes[3]);
}

void IMethod::WordToBytes(unsigned int uiWord, unsigned char* pucBytes)
{
	pucBytes[0] = static_cast<unsigned char>((uiWord >> 24) & 0xFF);
	pucBytes[1] = static_cast<unsigned char>((uiWord >> 16) & 0xFF);
	pucBytes[2] = static_cast<unsigned char>((uiWord >> 8) & 0xFF);
	pucBytes[3] = static_cast<unsigned char>(uiWord & 0xFF);
}


