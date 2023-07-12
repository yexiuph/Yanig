#pragma once
#include <string>

namespace ByteComposition {

	void ByteEncode(BYTE* pbuffer, DWORD dwSize);
	void ByteDecode(BYTE* pbuffer, DWORD dwSize);

	DWORD ByteEncrypt(UCHAR *pbKey, DWORD dwKeySize, const UCHAR *pbPlaintext, UCHAR *pbCipherText, DWORD dwHowMuch);
	DWORD ByteDecrypt(UCHAR *pbKey, DWORD dwKeySize, const UCHAR *pbCipherText, UCHAR *pbPlaintext, DWORD dwHowMuch);

	void HexToString(const UCHAR* pbText, const DWORD dwLength, std::string& strDestName);
	bool StringToHex(const UCHAR* pbText, UCHAR* pbHEX, const DWORD dwLength);
	bool WStringToHex(const UCHAR* pbText, WCHAR* pbHEX, const DWORD dwLength);

	void CharToHex(unsigned char ch, char* szHex);
	//Function to convert a Hex string of length 2 to an unsigned char
	bool HexToChar(char const* szHex, unsigned char& rch);
	//Function to convert binary string to hex string
	void BinaryToHex(unsigned char const* pucBinStr, int iBinSize, char* pszHexStr);
	//Function to convert hex string to binary string
	bool HexToBinary(char const* pszHexStr, unsigned char* pucBinStr, int iBinSize);

};