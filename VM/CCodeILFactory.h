// VMPackLib


#ifndef __CCODEILFACTORY__
#define __CCODEILFACTORY__

// Include files

#include <Windows.h>
#include <stdio.h>
#include <algorithm>
#include "CVirtualMemory.h"
#include "CVMFactory.h"
#include <disasm/disasm.h>
#include"Structs.h"
#include"CTree.h"


// 将汇编代码编译为ByteCode,添加到新节内存
class CCodeILFactory
{
public:
	CVirtualMemory m_JumpTable;						//JMP表
	CVirtualMemory m_CodeEngine;					//VM指令引擎
	CVirtualMemory m_EnterStub;						//重新进入vm的代码
	CVirtualMemory m_VMEnterStubCode;				//重新进入的vmcode
	CVirtualMemory m_VMCode;						//通常的vmcode
public:
	// 虚拟机工厂
	CVMFactory VMFactory;
public:
	CCodeILFactory();
public:
	void	Init(DWORD VirtualAddress,ulong OriginSizeofCode);
public:
	// 编译汇编代码为VM字节码,返回成功失败
	BOOL	BuildCode(char* baseaddr,AVL<CodeNode,ulong> *AVLTree,list<AddrNode*> *AddrNodes,char* ErrText);
public:

	// 反汇编代码,识别出函数结束的地方.添加到提供的链表中
	// CodeList : 输出汇编链表
	// base_addr: 2进制代码
	// VirtualAddress : 虚拟地址
	void	DisasmFunction(std::map<ulong,CodeNode> &CodeList,char* base_addr, DWORD VirtualAddress);

	// 反汇编代码,线性扫描所有代码.添加到提供的链表中
	// CodeList : 输出汇编链表
	// base_addr: 2进制代码
	// VirtualAddress : 虚拟地址
	void	DisasmCodes(AVL<CodeNode,ulong> *AVLTree,list<AddrNode*> *AddrNodes,char* base_addr,DWORD size, DWORD VirtualAddress);

	// 反汇编代码,函数迭代扫描代码
	// CodeList : 输出汇编链表
	// base_addr: 2进制代码
	// VirtualAddress : 虚拟地址
	void	RecursiveScanFunctionDisasmCodes(map<DWORD,CFunctionCode*> &mFuncList,char* pBaseAddr,DWORD dwCodeSize,DWORD dwOEPVirAddress,DWORD dwBaseCodeVirAddress);

	// 反汇编代码,按特征码（push ebp,mov ebp,esp）修正顺序扫描函数可能存在的起始地址问题
	// CodeList : 输出汇编链表
	// base_addr: 2进制代码
	// VirtualAddress : 虚拟地址
	void	FuncCharacteristicCheckDisasmCodes(map<DWORD,CFunctionCode*> &mFuncList,char* pBaseAddr,DWORD dwCodeSize,DWORD dwBaseCodeVirAddress);

	// 反汇编代码,搜索函数间隙代码
	// CodeList : 输出汇编链表
	// base_addr: 2进制代码
	// VirtualAddress : 虚拟地址
	void	SeqScanByFuncCharacteristicDisasmCodes(map<DWORD,CFunctionCode*> &mFuncList,char* pBaseAddr,DWORD dwCodeSize,DWORD dwBaseCodeVirAddress);
private:
	// 是否是跳转指令
	BOOL	IsJumpCmd(t_disasm* da);
	// 是否是函数调用指令
	BOOL	IsCallCmd(t_disasm* da);
	// 是否是返回指令
	BOOL	IsRetnCmd(t_disasm* da);
	// 是否是Rare command
	BOOL	IsRareCmd(t_disasm* da);
	//从链表中搜索一个地址的节点
	CodeNode*	SearchAddrAsList( list<CodeNode*>* List,CodeNode* node );
	//扫描代码是否存在间隙
	BOOL	IsContinualCodes(std::list<CodeNode> &mCodes);
};// END CLASS DEFINITION CCodeILFactory

#endif // __CCODEILFACTORY__