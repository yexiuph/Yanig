#ifndef __DOUBLEBUFFERING_H__
#define __DOUBLEBUFFERING_H__

#include <fstream>

using namespace std;

class CDoubleBuffering
{
public:
	//Constructor
	CDoubleBuffering(ifstream& in, char* pcBuff, int iSize, int iDataLen);
	//Get Next Data Buffer
	int GetData(char* pszDataBuf, int iDataLen = -1);

private:
	ifstream& m_rin;
	int m_iSize;
	int m_iSize2; //m_iSize/2
	int m_iDataLen;
	//Current Position
	int m_iCurPos;
	//End Position
	int m_iEnd;
	//Which Buffer
	int m_iBuf;
	char* m_pcBuff;
	//EOF attained
	bool m_bEOF;
};

#endif //__DOUBLEBUFFERING_H__

