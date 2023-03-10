// VMPackLib

#include"../PELib.h"
#include"comm.h"
#include "CCodeILFactory.h"
#include<stack>

CCodeILFactory::CCodeILFactory()
{
}


void CCodeILFactory::Init(DWORD VirtualAddress,ulong OriginSizeofCode)
{
	ulong dwJumpTableLen=JumpTableLen;
	ulong dwCodeEngineLen=OriginSizeofCode*2;
	ulong dwEnterStubAddrLen=OriginSizeofCode*1;
	ulong dwVMEnterCodeLen=OriginSizeofCode*1;
	ulong dwVMCodeLen=OriginSizeofCode*0x10;

	int nJumpTableAddr	= VirtualAddress;
	int nCodeEngineAddr = nJumpTableAddr  + dwJumpTableLen;
	int nEnterStubAddr	= nCodeEngineAddr + dwCodeEngineLen;
	int mVMEnterStubCodeAddr = nEnterStubAddr  + dwEnterStubAddrLen;
	int nVMCodeAddr		= mVMEnterStubCodeAddr  + dwVMEnterCodeLen;

	m_JumpTable.CreateVirtualMemory(nJumpTableAddr,JumpTableLen);
	m_CodeEngine.CreateVirtualMemory(nCodeEngineAddr,dwCodeEngineLen);
	m_EnterStub.CreateVirtualMemory(nEnterStubAddr,dwEnterStubAddrLen);
	m_VMEnterStubCode.CreateVirtualMemory(mVMEnterStubCodeAddr,dwVMEnterCodeLen);
	m_VMCode.CreateVirtualMemory(nVMCodeAddr,dwVMCodeLen);

	VMFactory.SetupVirtualMemory(&m_JumpTable,&m_CodeEngine,&m_EnterStub,&m_VMEnterStubCode,&m_VMCode);

	VMFactory.InitVM();
}

// 编译汇编代码为VM字节码,返回成功失败
BOOL CCodeILFactory::BuildCode(char* baseaddr,AVL<CodeNode,ulong> *AVLTree,list<AddrNode*> *AddrNodes,char* ErrText)
{
	return VMFactory.BuildVMCode(baseaddr,AVLTree,AddrNodes,ErrText);
}

// 反汇编代码,识别出函数结束的地方.添加到提供的链表中
// CodeList : 输出汇编链表
// base_addr: 2进制代码
// VirtualAddress : 虚拟地址
void CCodeILFactory::DisasmFunction(std::map<ulong,CodeNode> &CodeList,char* base_addr,DWORD VirtualAddress)
{
	DWORD Start_VirtualAddress = VirtualAddress;//第一个地址
	DWORD End_VirtualAddress = 0;//最后一句的地址

	t_disasm da;
	int len =0;
	int KeepNum = 0;
	//计算出函数的结尾
	while( TRUE )
	{
		CodeNode code;
		len = Disasm(base_addr,MAXCMDSIZE,VirtualAddress,&da,DISASM_CODE);

		memcpy(&code.disasm,&da,sizeof(t_disasm));
		CodeList.insert(pair<ulong,CodeNode>(code.disasm.ip,code));

		if( KeepNum >= len && KeepNum != 0 )
			KeepNum -= len;

		if( IsJumpCmd(&da) )//是跳转指令
		{
			if( da.jmpconst && da.jmpconst > VirtualAddress )
			{
				KeepNum = da.jmpconst - VirtualAddress;
			}
		}
		if( _stricmp(da.result,"int3") == 0 )//如果找到int3
		{
			break;
		}
		if( _strnicmp(da.result,"retn",4) == 0 )//如果找到返回指令
		{
			if( KeepNum - len <= 0 )//如果没有字节了.则返回
				break;
		}
		base_addr+=len;
		VirtualAddress+=len;
	}
	End_VirtualAddress = VirtualAddress;
}

// 反汇编代码,线性扫描所有代码.添加到提供的链表中
// CodeList : 输出汇编链表
// base_addr: 2进制代码
// VirtualAddress : 虚拟地址
void CCodeILFactory::DisasmCodes(AVL<CodeNode,ulong> *AVLTree,list<AddrNode*> *AddrNodes,char* base_addr,DWORD size,DWORD VirtualAddress)
{
	DWORD Start_VirtualAddress = VirtualAddress;//第一个地址
	DWORD End_VirtualAddress = 0;//最后一句的地址

	t_disasm da;
	CodeNode* code = NULL;
	int len =0;
	int KeepNum = 0;
	DWORD ROffset=0;
	//计算出函数的结尾
	while( ROffset< size)
	{
		code = new CodeNode;
		len = Disasm(base_addr,MAXCMDSIZE,VirtualAddress,&da,DISASM_CODE);

		memcpy(&code->disasm,&da,sizeof(t_disasm));
		AVLTree->Insert(*code,code->disasm.ip);

		if( KeepNum >= len && KeepNum != 0 )
			KeepNum -= len;

		if( IsJumpCmd(&da) )//是跳转指令
		{
			if( da.jmpconst && da.jmpconst > VirtualAddress )
			{
				KeepNum = da.jmpconst - VirtualAddress;
			}
		}
		base_addr+=len;
		ROffset+=len;
		VirtualAddress+=len;
	}
	End_VirtualAddress = VirtualAddress;

	if(AVLTree!=NULL)
	{
		AVLNode<CodeNode,ulong>* p = AVLTree->Root();
		stack<AVLNode<CodeNode,ulong>*> s;
		while (!s.empty() || p)
		{
			if (p)
			{
				s.push(p);
				p = p->lchild;
			}
			else
			{
				p = s.top();
				s.pop();
				{
					CodeNode* code = &p->data;
					//计算需要修正的绝对地址
					if(code&&code->disasm.error==0)
					{
						ulong addrconst=code->disasm.adrconst+code->disasm.immconst+code->disasm.jmpconst+code->disasm.zeroconst;
						if(addrconst)
						{
							PAddrNode paddrcode = NULL;
							paddrcode=new AddrNode();
							paddrcode->ip=code->disasm.ip;
							paddrcode->addrconst=addrconst;
							if( IsJumpCmd(&code->disasm))//是跳转指令
							{
								if(addrconst!=0)
								{
									AddrNodes->push_back(paddrcode);
								}
							}
							else if( IsCallCmd(&code->disasm))//是函数调用指令
							{
								if(addrconst!=0)
									AddrNodes->push_back(paddrcode);
							}
							else if(code->disasm.fixupsize!=0)
							{
								if(addrconst!=0)
									AddrNodes->push_back(paddrcode);
							}
						}
					}
					//计算出各语句的用处
					t_disasm t_da ;
					memcpy(&t_da,&code->disasm,sizeof(t_disasm));
					if(code)
					{
						if( IsJumpCmd(&t_da) )//是跳转指令
						{
							code->IsJmcType=TRUE;
							if( t_da.jmpconst )
							{
								if( t_da.jmpconst > Start_VirtualAddress && t_da.jmpconst < End_VirtualAddress )//在LIST里
								{
						
									//CodeNode* tmpNode = SearchAddrAsList(CodeList,code);//搜索链表
									AVLNode<CodeNode,ulong> *tmpNode=AVLTree->Search(code->disasm.jmpconst);
									if(tmpNode)
									{
										tmpNode->data.IsJmcFromType = TRUE;//标明这一句为从其他地方跳转过来的代码
									}
								}
								else
								{
									code->IsJmcBeSideType = TRUE;//为跳到外部的指令
								}
							}
							else//没有跳转地址,就是动态跳转
							{
								//此时要么跳到t_da.adrconst间接地址，要么跳到寄存器地址
								code->IsJmcDynamicType = TRUE;
							}
						}
						else if( IsCallCmd(&t_da) )//是函数调用指令
						{
							code->IsCallType=TRUE;
							if( t_da.jmpconst )
							{
								if( t_da.jmpconst > Start_VirtualAddress && t_da.jmpconst < End_VirtualAddress )//在LIST里
								{
									//CodeNode* tmpNode = SearchAddrAsList(CodeList,code);//搜索链表
									AVLNode<CodeNode,ulong> *tmpNode=AVLTree->Search(code->disasm.jmpconst);
									if(tmpNode)
									{
										tmpNode->data.IsCallFromType = TRUE;//标明这一句为从其他地方跳转过来的代码
									}
								}
								else
								{
									code->IsCallBeSideType = TRUE;//为跳到外部的指令
								}
							}
							else//没有跳转地址,就是动态跳转
							{
								//此时要么跳到t_da.adrconst间接地址，要么跳到寄存器地址
								code->IsCallDynamicType = TRUE;
							}
						}
					}
				}
				p = p->rchild;
			}
		}
	}
}

// 反汇编代码,函数迭代扫描代码
// CodeList : 输出汇编链表
// base_addr: 2进制代码
// VirtualAddress : 虚拟地址
void CCodeILFactory::RecursiveScanFunctionDisasmCodes(map<DWORD,CFunctionCode*> &mFuncList,char* pBaseAddr,DWORD dwCodeSize,DWORD dwOEPVirAddress,DWORD dwBaseCodeVirAddress)
{	
	//主函数递归扫描调用
	vector<char*> mCallStackTemp1;		//存储base_addr
	vector<DWORD> mCallStackTemp2;		//存储dwBeginVirtualAddress
	vector<DWORD> mCallStackTemp3;		//存储dwEndVirtualAddress
	vector<CFunctionCode*> mCallStackTemp4;//存储CFunctionCode指针
	vector<DWORD> mCallStackTemp5;		//存储dwLastJumpVirtualAddress
	char* base_addr=pBaseAddr;
	DWORD dwBeginVirtualAddress=dwOEPVirAddress;
	DWORD dwEndVirtualAddress=dwOEPVirAddress;
	DWORD dwLastJumpVirtualAddress=dwOEPVirAddress;
	CFunctionCode *pCFunc=new CFunctionCode();
	bool isJumpSection=false;
	while(true)
	{	
		if(dwEndVirtualAddress<dwBaseCodeVirAddress||dwEndVirtualAddress>dwBaseCodeVirAddress+dwCodeSize) break;

		CodeNode code;
		DWORD len = Disasm(base_addr,MAXCMDSIZE,dwEndVirtualAddress,&code.disasm,DISASM_CODE);
		base_addr+=len;
		dwEndVirtualAddress+=len;
		pCFunc->mCodes.insert(pair<ulong,CodeNode>(code.disasm.ip,code));
		if( _stricmp(code.disasm.result,"int3") == 0||_strnicmp(code.disasm.result,"retn",4)==0)
		{
			//call分支代码
			if(dwLastJumpVirtualAddress>=code.disasm.ip)
			{
				//假设一个函数内代码不会跳转到函数外，那么此处并非真正函数末尾，函数并未结束，继续汇编
				continue;
			}
			//pCFunc->mCodes.sort();
			pCFunc->dwBeginVirtualAddress=dwBeginVirtualAddress;
			pCFunc->dwEndVirtualAddress=dwEndVirtualAddress;
			pCFunc->dwSize=pCFunc->dwEndVirtualAddress-pCFunc->dwBeginVirtualAddress;
			mFuncList.insert(pair<DWORD,CFunctionCode*>(dwBeginVirtualAddress,pCFunc));
			if(mCallStackTemp1.size())
			{
				//返回上一层函数
				base_addr=mCallStackTemp1.back();
				mCallStackTemp1.pop_back();
				dwBeginVirtualAddress=mCallStackTemp2.back();
				mCallStackTemp2.pop_back();
				dwEndVirtualAddress=mCallStackTemp3.back();
				mCallStackTemp3.pop_back();
				pCFunc=mCallStackTemp4.back();
				mCallStackTemp4.pop_back();
				dwLastJumpVirtualAddress=mCallStackTemp5.back();
				mCallStackTemp5.pop_back();
				continue;
			}else
				break;		//主函数
		}
		if( IsCallCmd(&code.disasm) )//函数调用指令
		{
			if(code.disasm.optype[0]==Imm && code.disasm.jmpconst &&code.disasm.jmpconst>=dwBaseCodeVirAddress&&code.disasm.jmpconst<=dwBaseCodeVirAddress+dwCodeSize)
			{
					//进入一个新函数
				if(mFuncList.find(code.disasm.jmpconst)==mFuncList.end()&&(find(mCallStackTemp2.begin(), mCallStackTemp2.end(), code.disasm.jmpconst ) == mCallStackTemp2.end ()))//需要判断是否在迭代堆栈中
					{
						mCallStackTemp1.push_back(base_addr);
						mCallStackTemp2.push_back(dwBeginVirtualAddress);
						mCallStackTemp3.push_back(dwEndVirtualAddress);
						mCallStackTemp4.push_back(pCFunc);
						mCallStackTemp5.push_back(dwLastJumpVirtualAddress);
						pCFunc=new CFunctionCode();
						base_addr=base_addr-len+code.disasm.jmpconst-code.disasm.ip;
						dwBeginVirtualAddress=code.disasm.jmpconst;
						dwEndVirtualAddress=code.disasm.jmpconst;
						dwLastJumpVirtualAddress=code.disasm.jmpconst;
					}
			}
		}else if(IsJumpCmd(&code.disasm))
		{
			//修正函数末尾
			if(dwLastJumpVirtualAddress<code.disasm.jmpconst)
				dwLastJumpVirtualAddress=code.disasm.jmpconst;
		}
	}
}

// 反汇编代码,顺序扫描函数起始特征码（push ebp,mov ebp,esp）修正顺序扫描函数可能存在的起始地址问题
// CodeList : 输出汇编链表
// base_addr: 2进制代码
// VirtualAddress : 虚拟地址
void CCodeILFactory::FuncCharacteristicCheckDisasmCodes(map<DWORD,CFunctionCode*> &mFuncList,char* pBaseAddr,DWORD dwCodeSize,DWORD dwBaseCodeVirAddress)
{
	unsigned char* base_addr=NULL;
	map<DWORD,CFunctionCode*>::iterator itr=mFuncList.begin();
	while(itr!=mFuncList.end())
	{
		base_addr=(unsigned char*)pBaseAddr+itr->second->dwBeginVirtualAddress-dwBaseCodeVirAddress;
		if(base_addr[0]!=0x55&&base_addr[1]!=0x8B&&base_addr[2]!=0xEC)
		{
			DWORD temp=0x00EC8B55;
			unsigned char *p=(unsigned char*)memmem(base_addr,itr->second->dwSize,&temp,3);
			if(p!=NULL)
			{
				//假设以push ebp，mov ebp，esp开头函数，前面的代码为非函数代码
				CodeNode mNode;
				mNode.disasm.ip=itr->second->dwBeginVirtualAddress+(p-base_addr);
				std::map<ulong,CodeNode>::iterator itr1=itr->second->mCodes.find(mNode.disasm.ip);
				if(itr1==itr->second->mCodes.end())
				{
					//代码没有对齐，重新编译当前函数代码（RecursiveFunctionDisasmCodes汇编不会出现这种情况）
					CFunctionCode *pFunc=new CFunctionCode();
					pFunc->dwSize=itr->second->dwSize-(p-base_addr);
					pFunc->dwBeginVirtualAddress=mNode.disasm.ip;
					pFunc->dwEndVirtualAddress=itr->second->mCodes.rbegin()->first+itr->second->mCodes.rbegin()->second.disasm.codelen;
					itr->second->mCodes.clear();
					delete itr->second;
					mFuncList.erase(itr++);//防止迭代器失效
					DisasmFunction(pFunc->mCodes,(char*)p,pFunc->dwBeginVirtualAddress);	//BUG：丢失掉函数末尾本来的正确地址
					mFuncList.insert(std::pair<DWORD,CFunctionCode*>(pFunc->dwBeginVirtualAddress,pFunc));
					continue;
				}else
				{
					//代码对齐，去掉前面非函数代码（RecursiveFunctionDisasmCodes汇编不会出现这种情况）
					CFunctionCode *pFunc=itr->second;
					mFuncList.erase(itr->second->dwBeginVirtualAddress);
					pFunc->dwBeginVirtualAddress=mNode.disasm.ip;
					pFunc->dwSize-=(p-base_addr);
					pFunc->mCodes.erase(pFunc->mCodes.begin(),itr1);
					mFuncList.insert(std::pair<DWORD,CFunctionCode*>(pFunc->dwBeginVirtualAddress,pFunc));
				}
			}
			else
			{
				//函数确实没有以push ebp，mov ebp，esp开头，可能为特殊函数
				//暂时忽略这类函数
			}
		}
		itr++;
	}
	
}


// 反汇编代码,搜索函数间隙代码
// CodeList : 输出汇编链表
// base_addr: 2进制代码
// VirtualAddress : 虚拟地址
void CCodeILFactory::SeqScanByFuncCharacteristicDisasmCodes(map<DWORD,CFunctionCode*> &mFuncList,char* pBaseAddr,DWORD dwCodeSize,DWORD dwBaseCodeVirAddress)
{
	//unsigned char* base_addr=NULL;
	//DWORD VirtualAddress = dwBaseCodeVirAddress;//第一个地址
	//int KeepNum = 0;
	//DWORD ROffset=0;
	////计算出函数的结尾
	//while( ROffset< dwCodeSize)
	//{
	//	int len=1;
	//	if(mFuncList.find(VirtualAddress)!=mFuncList.end())
	//	{
	//	}
	//	base_addr=(unsigned char*)pBaseAddr;
	//	if(base_addr[0]!=0x55&&base_addr[1]!=0x8B&&base_addr[2]!=0xEC)
	//	{
	//		//发现特征函数（push ebp,mov ebp,esp）
	//	}

	//	base_addr+=1;
	//	VirtualAddress+=1;
	//}
}


BOOL CCodeILFactory::IsJumpCmd(t_disasm* da)
{
	if(  ( da->cmdtype & C_CAL ) == C_CAL )//CALL不算
	{
		return FALSE;
	}
	if( ( da->cmdtype & C_JMP ) == C_JMP )
	{
		return TRUE;
	}
	if( ( da->cmdtype & C_JMC ) == C_JMC )
	{
		return TRUE;
	}
	return FALSE;
}
BOOL CCodeILFactory::IsCallCmd(t_disasm* da)
{
	if( ( da->cmdtype & C_CAL ) == C_CAL )
	{
		return TRUE;
	}
	return FALSE;
}
BOOL CCodeILFactory::IsRetnCmd(t_disasm* da)
{
	char strretn[32] = "RETN\0";
	_strlwr_s(da->result,TEXTLEN);
	_strlwr_s(strretn,32);
	if( strstr(strretn,da->result) )
	{
		return TRUE;
	}
	return FALSE;
}
BOOL CCodeILFactory::IsRareCmd(t_disasm* da)
{
	if( ( da->cmdtype & C_RARE ) == C_RARE )
	{
		return TRUE;
	}
	return FALSE;
}

//从链表中搜索一个地址的节点
CodeNode* CCodeILFactory::SearchAddrAsList( list<CodeNode*> *List,CodeNode* node )
{
	DWORD GotoAddr = node->disasm.jmpconst;
	DWORD LastAddr = 0;
	list<CodeNode*>::iterator itr;
	for( itr = List->begin(); itr != List->end(); itr++ )
	{
		CodeNode* code = *itr;
		t_disasm t_da ;
		memcpy(&t_da,&code->disasm,sizeof(t_disasm));
		if( GotoAddr == t_da.ip )//找到了
		{
			return code;
		}
		else if( GotoAddr > t_da.ip )
		{
			LastAddr = t_da.ip;
		}
		else if( GotoAddr < t_da.ip )
		{
			if( LastAddr )
			{
				if(node->IsCallType) node->IsCallUndefineType = TRUE;//跳到了不明确的地址
				if(node->IsJmcType) node->IsJmcUndefineType = TRUE;//跳到了不明确的地址
			}
		}
	}
	return NULL;
}

BOOL CCodeILFactory::IsContinualCodes(std::list<CodeNode> &mCodes)
{
	BOOL bRet=TRUE;
	std::list<CodeNode>::iterator itr1=mCodes.begin();
	std::list<CodeNode>::iterator itr2;
	while(itr1!=mCodes.end())
	{
		itr2=itr1;
		itr1++;
		if(itr1==mCodes.end())
			break;
		if(itr2->disasm.ip+itr2->disasm.codelen!=itr1->disasm.ip)
		{
			bRet=FALSE;
			break;
		}
	}
	return bRet;
}


 