#pragma once

template<class TYPE>
struct SGLNODE
{
	TYPE Data;

	SGLNODE* pPrev;
	SGLNODE* pNext;

	SGLNODE() :
		pPrev(nullptr),
		pNext(nullptr)
	{
	}
};

template<class TYPE>
class CGLLIST
{
public:
	typedef SGLNODE<TYPE>* PGLNODE;

public:
	DWORD m_dwAmount;
	SGLNODE<TYPE>* m_pHead;
	SGLNODE<TYPE>* m_pTail;

public:
	CGLLIST() :
		m_dwAmount(0),
		m_pHead(nullptr),
		m_pTail(nullptr)
	{
	}

	void DELALL()
	{
		m_dwAmount = 0;
		while (m_pHead)
		{
			SGLNODE<TYPE>* pNode = m_pHead;
			m_pHead = m_pHead->pNext;
			delete pNode;
		}
		m_pTail = nullptr;
	}

	SGLNODE<TYPE>* ADDHEAD(const TYPE& Data)
	{
		SGLNODE<TYPE>* pNode = new SGLNODE<TYPE>;
		pNode->Data = Data;
		m_dwAmount++;

		if (m_pHead)
			m_pHead->pPrev = pNode;
		pNode->pNext = m_pHead;
		m_pHead = pNode;

		if (!m_pTail)
			m_pTail = pNode;

		return pNode;
	}

	SGLNODE<TYPE>* ADDTAIL(const TYPE& Data)
	{
		if (!m_pTail)
			return ADDHEAD(Data);

		SGLNODE<TYPE>* pNode = new SGLNODE<TYPE>;
		pNode->Data = Data;
		m_dwAmount++;

		m_pTail->pNext = pNode;
		pNode->pPrev = m_pTail;
		m_pTail = pNode;

		return pNode;
	}

	void DELNODE(PGLNODE& pNode)
	{
		if (m_pHead == pNode)
		{
			m_pHead = pNode->pNext;
			if (m_pHead)
				m_pHead->pPrev = nullptr;

			if (m_pTail == pNode)
				m_pTail = nullptr;
		}
		else
		{
			SGLNODE<TYPE>* pPrev = pNode->pPrev;
			SGLNODE<TYPE>* pNext = pNode->pNext;

			if (m_pTail == pNode)
				m_pTail = pPrev;

			pPrev->pNext = pNext;
			if (pNext)
				pNext->pPrev = pPrev;
		}

		delete pNode;
		m_dwAmount--;
	}

	void operator=(const CGLLIST<TYPE>& OldList)
	{
		DELALL();

		SGLNODE<TYPE>* pCur = OldList.m_pHead;
		while (pCur)
		{
			ADDTAIL(pCur->Data);
			pCur = pCur->pNext;
		}
	}
};
