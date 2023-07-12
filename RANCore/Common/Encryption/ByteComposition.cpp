#include "pch.h"
#include "ByteComposition.h"
#include <strstream>

namespace ByteComposition {

	UCHAR ARRAY[256] = { 0xCD, 0xF0, 0xA2, 0xE2, 0xED, 0x88, 0xE3, 0x98, 0xBC, 0x66, 0xC1, 0x7C, 0xF4, 0xDB, 0x47, 0x96, 0xF6,
						0x6C, 0x5E, 0x11, 0xAF, 0x2F, 0x40, 0x42, 0x41, 0x07, 0xDE, 0x4C, 0x8A, 0x63, 0x4D, 0x51, 0xC0, 0x9B,
						0x38, 0x27, 0x19, 0x03, 0x97, 0x65, 0x3D, 0x44, 0xAC, 0xA7, 0x18, 0xA0, 0x61, 0x13, 0xB3, 0xB4, 0xC6,
						0x21, 0x15, 0xE0, 0xC5, 0x0F, 0x78, 0xC4, 0xEF, 0x2C, 0x53, 0x26, 0x2E, 0x67, 0x54, 0x5F, 0xD5, 0xC8,
						0xAA, 0x17, 0x46, 0x95, 0xA3, 0x94, 0xFB, 0xBA, 0xD3, 0xBD, 0x64, 0x2A, 0xBF, 0x34, 0x48, 0x35, 0x43,
						0xD7, 0xF5, 0xCF, 0x90, 0x92, 0x2D, 0xB5, 0x5D, 0x93, 0x99, 0x50, 0x74, 0x72, 0x31, 0x04, 0x58, 0x10,
						0x5A, 0x7F, 0xFF, 0xCA, 0x55, 0x37, 0xB2, 0xDD, 0xE5, 0x0A, 0x0D, 0x69, 0xB1, 0x3A, 0x00, 0x3C, 0xEA,
						0x22, 0x32, 0x8D, 0xF2, 0x9C, 0x86, 0x1C, 0xB0, 0x76, 0x30, 0x01, 0xD2, 0x06, 0xBB, 0x77, 0xF3, 0x80,
						0xE8, 0xA6, 0x05, 0xEC, 0x89, 0x49, 0xFD, 0xD9, 0xD6, 0xD4, 0x45, 0x6F, 0x4F, 0xB8, 0x33, 0x57, 0xD8,
						0x87, 0xA8, 0x9E, 0xF9, 0x5C, 0x23, 0xB6, 0x6B, 0xEB, 0x7E, 0x1F, 0x02, 0xFE, 0x85, 0xE9, 0x12, 0xC9,
						0xAE, 0x08, 0x9F, 0x52, 0x25, 0x71, 0x09, 0x3F, 0x29, 0x68, 0x3B, 0x1A, 0xE7, 0x91, 0x59, 0x7A, 0x6E,
						0x8E, 0x56, 0xA4, 0x1D, 0x1E, 0xA9, 0x9A, 0xDF, 0x70, 0x8C, 0x4E, 0x4B, 0xDC, 0xEE, 0x36, 0x8F, 0xC3,
						0x83, 0x82, 0xE4, 0x8B, 0x79, 0x6D, 0x0C, 0xA1, 0x7D, 0x39, 0x4A, 0xBE, 0xFA, 0xAB, 0xD1, 0xC7, 0x28,
						0x7B, 0xCC, 0xF7, 0xB7, 0xAD, 0x62, 0xB9, 0xD0, 0xF8, 0xF1, 0x0E, 0x1B, 0xCB, 0xDA, 0xE6, 0x2B, 0x60,
						0x16, 0xC2, 0x81, 0x0B, 0x73, 0xA5, 0x20, 0x84, 0x5B, 0x24, 0x9D, 0x75, 0xE1, 0xCE, 0x14, 0x6A, 0x3E,
						0xFC };

	BOOL bDEARRAY;
	UCHAR DEARRAY[256];

	void ByteEncode(BYTE* pbuffer, DWORD dwSize)
	{
		for (DWORD i = 0; i < dwSize; ++i)
		{
			pbuffer[i] = ARRAY[pbuffer[i]];
		}
	}

	void ByteDecode(BYTE* pbuffer, DWORD dwSize)
	{
		static bool bDEARRAY = false;
		static UCHAR DEARRAY[256];

		if (!bDEARRAY)
		{
			for (DWORD i = 0; i < 256; ++i)
			{
				DEARRAY[ARRAY[i]] = static_cast<UCHAR>(i);
			}
			bDEARRAY = true;
		}

		for (DWORD i = 0; i < dwSize; ++i)
		{
			pbuffer[i] = DEARRAY[pbuffer[i]];
		}
	}

	DWORD ByteEncrypt(UCHAR *pbKey, DWORD dwKeySize, const UCHAR *pbPlaintext, UCHAR *pbCipherText, DWORD dwHowMuch)
	{
		HCRYPTPROV hProv = NULL;
		HCRYPTKEY hKey = NULL;
		HCRYPTHASH hHash = NULL;

		DWORD dwRet = 0;

		memcpy(pbCipherText, pbPlaintext, dwHowMuch);

		try
		{
			if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
				throw GetLastError();

			if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
				throw GetLastError();

			if (!CryptHashData(hHash, pbKey, dwKeySize, 0))
				throw GetLastError();

			if (!CryptDeriveKey(hProv, CALG_RC4, hHash, CRYPT_EXPORTABLE, &hKey))
				throw GetLastError();

			if (!CryptEncrypt(hKey, 0, TRUE, 0, pbCipherText, &dwHowMuch, dwHowMuch))
				throw GetLastError();
		}
		catch (const DWORD dwLastError)
		{
			dwRet = dwLastError;
		}

		CryptDestroyKey(hKey);
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);

		return dwRet;
	}

	DWORD ByteDecrypt(UCHAR *pbKey, DWORD dwKeySize, const UCHAR *pbCipherText, UCHAR *pbPlaintext, DWORD dwHowMuch)
	{
		HCRYPTPROV	hProv = NULL;
		HCRYPTKEY	hKey = NULL;
		HCRYPTHASH	hHash = NULL;

		DWORD		dwBuff = dwHowMuch;
		DWORD		dwRet = 0;

		memcpy(pbPlaintext, pbCipherText, dwHowMuch);

		try
		{
			if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE)
				throw GetLastError();

			if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash) == FALSE)
				throw GetLastError();

			if (CryptHashData(hHash, pbKey, dwKeySize, 0) == FALSE)
				throw GetLastError();

			if (CryptDeriveKey(hProv, CALG_RC4, hHash, CRYPT_EXPORTABLE, &hKey) == FALSE)
				throw GetLastError();

			if (CryptDecrypt(hKey, 0, TRUE, 0, pbPlaintext, &dwBuff) == FALSE)
				throw GetLastError();
		}
		catch (const DWORD dwLastError)
		{
			dwRet = dwLastError;
		}

		if (hKey)	CryptDestroyKey(hKey);
		if (hHash)	CryptDestroyHash(hHash);
		if (hProv)	CryptReleaseContext(hProv, 0);

		return dwRet;
	}

	UCHAR CharToHex(char cValue)
	{
		switch (cValue)
		{
			case '0': return 0;
			case '1': return 1;
			case '2': return 2;
			case '3': return 3;
			case '4': return 4;
			case '5': return 5;
			case '6': return 6;
			case '7': return 7;
			case '8': return 8;
			case '9': return 9;

			case 'A': return 10;
			case 'B': return 11;
			case 'C': return 12;
			case 'D': return 13;
			case 'E': return 14;
			case 'F': return 15;

			case 'a': return 10;
			case 'b': return 11;
			case 'c': return 12;
			case 'd': return 13;
			case 'e': return 14;
			case 'f': return 15;
			default: return 0;
		};

		return 0;
	}

	void HexToString(const UCHAR *pbText, const DWORD dwLength, std::string& strDestName)
	{
		static const char hexDigits[] = "0123456789ABCDEF";
		strDestName.clear();

		for (DWORD i = 0; i < dwLength; ++i)
		{
			strDestName += hexDigits[pbText[i] >> 4];
			strDestName += hexDigits[pbText[i] & 0x0F];
		}
	}

	bool StringToHex(const UCHAR* pbText, UCHAR* pbHEX, const DWORD dwLength)
	{
		if (!pbText || !pbHEX)
			return false;

		if (strlen((const char*)pbText) % 2 != 0)
			return false;

		DWORD j = 0;
		for (DWORD i = 0; i < dwLength; i += 2, ++j)
		{
			pbHEX[j] = (CharToHex(pbText[i]) << 4) | CharToHex(pbText[i + 1]);
		}

		pbHEX[j] = '\0';

		return true;
	}

	bool WStringToHex(const UCHAR* pbText, WCHAR* pbHEX, const DWORD dwLength)
	{
		if (!pbText || !pbHEX)
			return false;

		if (wcslen((const WCHAR*)pbText) % 4 != 0)
			return false;

		DWORD j = 0;
		for (DWORD i = 0; i < dwLength; i += 4, ++j)
		{
			pbHEX[j] = (CharToHex(pbText[i]) << 12) | (CharToHex(pbText[i + 1]) << 8) | (CharToHex(pbText[i + 2]) << 4) | CharToHex(pbText[i + 3]);
		}

		pbHEX[j] = L'\0';

		return true;
	}

	void CharToHex(unsigned char ch, char* szHex)
	{
		static unsigned char saucHex[] = "0123456789ABCDEF";
		szHex[0] = saucHex[ch >> 4];
		szHex[1] = saucHex[ch & 0xF];
		szHex[2] = 0;
	}

	bool HexToChar(char const* szHex, unsigned char& rch)
	{
		char c = *szHex;
		if (c >= '0' && c <= '9')
			rch = c - '0';
		else if (c >= 'A' && c <= 'F')
			rch = c - 'A' + 10;
		else if (c >= 'a' && c <= 'f')
			rch = c - 'a' + 10;
		else
			return false;

		c = *(szHex + 1);
		if (c >= '0' && c <= '9')
			rch = (rch << 4) + (c - '0');
		else if (c >= 'A' && c <= 'F')
			rch = (rch << 4) + (c - 'A' + 10);
		else if (c >= 'a' && c <= 'f')
			rch = (rch << 4) + (c - 'a' + 10);
		else
			return false;

		return true;
	}

	void BinaryToHex(unsigned char const* pucBinStr, int iBinSize, char* pszHexStr)
	{
		static const char hexDigits[] = "0123456789ABCDEF";
		*pszHexStr = '\0';

		for (int i = 0; i < iBinSize; i++)
		{
			pszHexStr[2 * i] = hexDigits[pucBinStr[i] >> 4];
			pszHexStr[2 * i + 1] = hexDigits[pucBinStr[i] & 0x0F];
		}

		pszHexStr[2 * iBinSize] = '\0';
	}

	bool HexToBinary(char const* pszHexStr, unsigned char* pucBinStr, int iBinSize)
	{
		for (int i = 0; i < iBinSize; ++i, pszHexStr += 2, ++pucBinStr)
		{
			unsigned char ch;
			if (!HexToChar(pszHexStr, ch))
				return false;
			*pucBinStr = ch;
		}
		return true;
	}
}