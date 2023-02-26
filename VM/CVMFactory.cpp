// VMPackLib

#include"../PELib.h"
#include "CVMFactory.h"
#include <disasm/disasm.h>
#include<stack>

CVMFactory::CVMFactory()
{
	//m_curvhandidx = 0;
	//m_curtableidx = 0;
}

CVMFactory::~CVMFactory()
{
	
}

//获得func_stub指向的地址(jmp xxxx)
HandlerFunc CVMFactory::GetFunctionRVA(HandlerFunc Func)
{
	return (HandlerFunc)((DWORD)Func+*(DWORD*)((DWORD)Func+1)+5);
}
//获得函数长度
int CVMFactory::GetFunctionSize(HandlerFunc FuncName)
{
	int FuncLen = 0;//函数长度
	char* pBody = (char*)GetFunctionRVA(FuncName);//得到jmp xxxx的指向的地址,优化后的代码则不需要这一句
	BOOL NotEnd = TRUE;//未结束
	int i = 0;
	while( NotEnd )
	{
		if( memcmp(pBody+i,"VMEND",5) == 0 )//找到结束标志
		{
			FuncLen = (int)(pBody + i - pBody);
			NotEnd = FALSE;
			break;
		}
		i++;
	}
	return FuncLen;
}

// 获得虚拟内存类
void CVMFactory::SetupVirtualMemory(CVirtualMemory *JumpTable,
									  CVirtualMemory *CodeEngine,
									  CVirtualMemory *EnterStub,
									  CVirtualMemory *VMEnterStub,
									  CVirtualMemory *VMCode)
{
	m_JumpTable = JumpTable;
	m_CodeEngine = CodeEngine;
	m_EnterStub = EnterStub;
	m_VMCode = VMCode;
	m_VMEnterStubCode = VMEnterStub;
}

// 通过名称获得Handler结构
VHandler* CVMFactory::GetHandler(char* vmname)
{
	//for(int i = 0; i < m_curvhandidx; i++)
	//{
	//	if( strcmp(m_vhandler[i].VMInstrName,"") == 0 )
	//		return NULL;
	//	if( strcmp(m_vhandler[i].VMInstrName,vmname) == 0 )
	//	{
	//		return &m_vhandler[i];
	//	}
	//}
	list<VHandler>::iterator itr;
	for( itr = m_vhandler.begin(); itr != m_vhandler.end(); itr++ )
	{
			if( strcmp(itr->VMInstrName,"") == 0 )
				return NULL;
			if( strcmp(itr->VMInstrName,vmname) == 0 )
			{
				return &(*itr);
			}
	}
	return NULL;
}
// 添加一个Handler名称到Handler索引表
BOOL CVMFactory::AddVHandlerName(char* vmname)
{
	//if( m_curtableidx > HANDLERMAXLEN )
	//	return FALSE;
	//strcpy_s(m_RandomTable[m_curtableidx].VMInstrName,VMNAMELEN,vmname);
	//m_RandomTable[m_curtableidx].idx = m_HandlerIdx[m_curtableidx];
	//m_curtableidx++;
	//return TRUE;
	VM_RandomTable mVMTable;
	strcpy_s(mVMTable.VMInstrName,VMNAMELEN,vmname);
	mVMTable.idx = m_RandomTable.size();
	m_RandomTable.push_back(mVMTable);
	return TRUE;
}
// 初始化VM环境.
// 1.初始化寄存器位置
// 2.初始化核心宏代码(将代码拷贝到结构体中)..
// 3.将Handler写入对应新节的内存地址.
// 4.得到Handler所在的虚拟地址后,修复相互间的跳转.设置汇编代码中固定的一些值.
void CVMFactory::InitVM()
{
	InterpretHandler.Init();//初始化

	//RandListIdx(m_HandlerIdx,HANDLERMAXLEN);//打乱Handler索引

	InitCoreMacro();//初始化核心宏的特殊Handler
}
// 编译代码
BOOL CVMFactory::CompileCode(DWORD VirtualAddr,char* asmtext,char *code,int *len)
{
	t_asmmodel am;
	char errtext[TEXTLEN] = {0};

	char linestr[TEXTLEN] = {0};//得到一行的汇编代码字符串
	int lastk = 0;
	int asmlen = (int)strlen(asmtext)+1;
	int codelen = 0;
	for(int k = 0; k < asmlen; k++)
	{
		if( asmtext[k] == '\n' || asmtext[k] == '\0' )
		{
			memset(linestr,0,TEXTLEN);
			memcpy(linestr,&asmtext[lastk],k - lastk );
			lastk = k+1;
			int j=Assemble(linestr,VirtualAddr,&am,0,4,errtext);//编译为2进制代码
			VirtualAddr += j;
			if( strcmp(errtext,"") != 0 )
			{
				OutputDebugStringA("编译出错\n");
				OutputDebugStringA(errtext);
				return FALSE;
			}
			memcpy(&code[codelen],am.code,am.length);
			codelen += am.length;
		}
	}
	*len = codelen;

	return TRUE;
}
// 修复StartVM
void CVMFactory::FixStartVM()
{
	VHandler* vhandler = GetHandler("VStartVM");
	if( !vhandler )
		return;
	vhandler->VirtualAddress = m_CodeEngine->GetCurrentVirtualAddress();

	char code[16] = {0};
	int  len = 0;
	char text[TEXTLEN] = {0};

	sprintf_s( text,TEXTLEN,"jmp [eax*4+%08x]",m_JumpTable->m_VirtualBaseAddress );
	if( !CompileCode(vhandler->VirtualAddress+vhandler->CodeLen,text,code,&len) )
		return;
	memcpy(vhandler->AssembleCode+vhandler->CodeLen,code,len);
	vhandler->CodeLen += len;
	m_CodeEngine->WriteData((STu8*)vhandler->AssembleCode,vhandler->CodeLen );
}
// 修复DCheckESP
void CVMFactory::FixCheckESP()
{
	VHandler* vhandler = GetHandler("DCheckESP");
	if( !vhandler )
		return;
	vhandler->VirtualAddress = m_CodeEngine->GetCurrentVirtualAddress();

	char code[16] = {0};
	int  len = 0;
	char text[TEXTLEN] = {0};

	sprintf_s( text,TEXTLEN,"jl %08x",GetHandler("VStartVM")->VirtualAddress+JMPOFFSET );
	if( !CompileCode(vhandler->VirtualAddress+STACKOFFSET,text,code,&len) )
		return;
	memcpy(vhandler->AssembleCode+STACKOFFSET,code,len);

	sprintf_s( text,TEXTLEN,"jmp %08x",GetHandler("VStartVM")->VirtualAddress+JMPOFFSET );
	if( !CompileCode(vhandler->VirtualAddress+vhandler->CodeLen,text,code,&len) )
		return;
	memcpy(vhandler->AssembleCode+vhandler->CodeLen,code,len);
	vhandler->CodeLen += len;
	m_CodeEngine->WriteData((STu8*)vhandler->AssembleCode,vhandler->CodeLen );
}
// 先放置Handler
void CVMFactory::PlaceHandler()
{
	list<VHandler>::iterator itr;
	for( itr = m_vhandler.begin(); itr != m_vhandler.end(); itr++ )
	{
		if( strcmp(itr->VMInstrName,"") == 0 )
			break;
	/*	if( strcmp(itr->VMInstrName,"VStartVM") != 0 &&				//排除是因为没有对应的指令代码需要跳到此处
			strcmp(itr->VMInstrName,"DCheckESP") != 0 )*/
		{
			itr->VirtualAddress = m_CodeEngine->GetCurrentVirtualAddress();//当前内存地址
			
			char code[16] = {0};
			int  len = 0;
			char text[TEXTLEN] = {0};

			sprintf_s(text,TEXTLEN,"jmp %08x",GetHandler("DCheckESP")->VirtualAddress);
			if( !CompileCode(itr->VirtualAddress+itr->CodeLen,text,code,&len) )
				return;
			memcpy( &itr->AssembleCode[ itr->CodeLen ],code,len);

			itr->CodeLen += len;

			m_CodeEngine->WriteData((STu8*)itr->AssembleCode,itr->CodeLen);//写进去

			int idx = GetIdxFromVMName(itr->VMInstrName);
			m_HandlerTable.push_back(itr->VirtualAddress);
			//m_HandlerTable[idx]=itr->VirtualAddress;
			//*(DWORD*)((DWORD)m_HandlerTable+idx*4) = itr->VirtualAddress;
		}
	}
	//m_JumpTable->WriteData((char*)&m_HandlerTable,sizeof(DWORD)*HANDLERMAXLEN);
	m_JumpTable->WriteData((STu8*)&m_HandlerTable[0],m_HandlerTable.size()*sizeof(m_HandlerTable[0]));
}
// 初始化核心宏和Handler
BOOL CVMFactory::InitCoreMacro()
{
	int binit1 = InitCoreManualHandler(); //初始化手动Handler
	int binit2 = InitCoreVMTableHandler();//初始化VM描述表的Handler

	//变动.放到VM指令分析后放置
	//PlaceHandler();//放置Handler,生成JUMP表
	FixStartVM();
	FixCheckESP();

	return (binit1 && binit2);
}
BOOL CVMFactory::InitCoreVMTableHandler()
{
	char asmtext[ASMTEXTLEN] = {0};
	//循环生成汇编码
	for(int i = 0; i < 5; i++ )//编译前5个重要指令
	{
		if( !InterpretHandler.InterpretASMStr(&vmtable[i],asmtext,1024) )
			break;
		if( !CompileHandler(vmtable[i].VMInstrName,asmtext) )//编译这个Handler
			return FALSE;
	}
	return TRUE;
}
BOOL CVMFactory::InitCoreManualHandler()
{
	int m_curvhandidx=0;
	while(TRUE)
	{
		if( strcmp(vm_dname[m_curvhandidx].vm_dname,"") == 0 || vm_dname[m_curvhandidx].FuncAddr == NULL )
			break;
		if( m_curvhandidx >= HANDLERMAXLEN )
		{
			OutputDebugString("超过Handler最大容量");
			return FALSE;
		}
		VHandler mVHandler;
		strcpy_s(mVHandler.VMInstrName,VMNAMELEN,vm_dname[m_curvhandidx].vm_dname);
		mVHandler.CodeLen = GetFunctionSize(vm_dname[m_curvhandidx].FuncAddr);
		memcpy(mVHandler.AssembleCode,GetFunctionRVA(vm_dname[m_curvhandidx].FuncAddr),mVHandler.CodeLen);
		m_vhandler.push_back(mVHandler);
		//修复手工的代码没有写的地方,如handler间的相互跳转

		if( !AddVHandlerName(mVHandler.VMInstrName) )
			return FALSE;

		m_curvhandidx++;
	}
	return TRUE;
}
// 编译生成的Handler代码并添加到Handler
BOOL CVMFactory::CompileHandler(char* handlername,char* asmtext)
{
	if( handlername == NULL || asmtext == NULL )
		return FALSE;

	char Code[CODEMAXLEN] = {0};
	int  codelen = 0;

	t_asmmodel am;
	char errtext[TEXTLEN] = {0};

	char linestr[TEXTLEN] = {0};//得到一行的汇编代码字符串
	int lastk = 0;
	int len = (int)strlen(asmtext);
	for(int k = 0; k < len; k++)
	{
		if( asmtext[k] == '\n' || asmtext[k] == '\0' )
		{
			memset(linestr,0,TEXTLEN);
			memcpy(linestr,&asmtext[lastk],k - lastk );
			lastk = k+1;
			int j=Assemble(linestr,0,&am,0,4,errtext);//编译为2进制代码
			if( strcmp(errtext,"") != 0 )
			{
				OutputDebugStringA("编译出错\n");
				OutputDebugStringA(errtext);
				return FALSE;
			}
			memcpy(&Code[codelen],am.code,am.length);
			codelen += am.length;
		}
	}
	if( codelen == 0 )
	{
		OutputDebugStringA("这个Handler没有代码");
		return FALSE;
	}

	VHandler mVHandler;
	strcpy_s(mVHandler.VMInstrName,VMNAMELEN,handlername);
	memcpy(mVHandler.AssembleCode,Code,codelen);
	mVHandler.CodeLen=codelen;
	m_vhandler.push_back(mVHandler);
	
	if( !AddVHandlerName(mVHandler.VMInstrName) )
		return FALSE;

	return TRUE;
}

//如果是V(自动生成的)指令,返回结构,否则返回NULL
VMTable* CVMFactory::SearchForVMTable(char* vmname)
{
	if( !vmname )
		return NULL;

	for( int i = 0; i < VMTABLEMAXLEN; i++ )
	{
		if( _stricmp(vmtable[i].VMInstrName,"") == 0  ) 
			return NULL;
		if( _stricmp(vmtable[i].VMInstrName,vmname) == 0 )
			return &vmtable[i];
	}
	return NULL;
}

//从VMTABLE中寻找一个VM命令并加载
VMTable* CVMFactory::GetVMTableForAlready(char* vmname)
{
	char asmtext[ASMTEXTLEN] = {0};
	VMTable* table = SearchForVMTable(vmname);
	if( !table )//找不到
	{
		return NULL;
	}
	if( GetHandler(vmname) )//如果已经编译
		return table;
	//找到了则编译在返回
	if( !InterpretHandler.InterpretASMStr(table,asmtext,1024) )
		return NULL;
	if( !CompileHandler(table->VMInstrName,asmtext) )//编译这个Handler
		return NULL;
	return table;
}
// 通过VM指令名称获得索引
int CVMFactory::GetIdxFromVMName(char* vmname)
{
	if( !vmname )
		return -1;
	GetVMTableForAlready(vmname);
	for( int i = 0; i < m_RandomTable.size(); i++ )
	{
		if( _stricmp(m_RandomTable[i].VMInstrName,vmname) == 0 )
			return m_RandomTable[i].idx;
	}
	return -1;
}

void CVMFactory::ClearList()
{
	list<VCodeNode*>::iterator itr;
	for( itr = vmlist.begin(); itr != vmlist.end(); itr++ )
	{
		VCodeNode* tmpnode = *itr;
		delete tmpnode;
	}
	vmlist.clear();
}

// 修改链表中的一些数据(如跳转)
void CVMFactory::FixVCodeList(list<AddrNode*> *AddrNodes)
{	
	//list<VCodeNode*>::iterator itr;
	//VCodeNode* lastcode = NULL;
	//VCodeNode* vcode = NULL;
	//for( itr = vmlist.begin(); itr != vmlist.end(); itr++ )
	//{
	//	vcode = *itr;
	//	if( vcode )
	//	{
	//		if( strstr(vcode->VMInstrName,"LOOP") || vcode->VMInstrName[1] == 'J' )//跳转指令
	//		{
	//			lastcode->immconst[0] = (int)GetVMAddrFromVirtualAddress(lastcode->immconst[0]);
	//			CompileVMCode(lastcode,m_VMCode);//覆盖
	//		}
	//	}
	//	lastcode = vcode;
	//}
	list<VCodeNode*>::iterator itr;
	VCodeNode* vcode = NULL;
	bool isCorrect=false;
	for( itr = vmlist.begin(); itr != vmlist.end(); itr++ )
	{
		vcode = *itr;
		list<AddrNode*>::iterator addrNodeitr;
		for(addrNodeitr=AddrNodes->begin();addrNodeitr!=AddrNodes->end();addrNodeitr++)
		{
			if((*addrNodeitr)->ip==vcode->InAddress)
			{
				//找到了对应项，校验地址
				if((*addrNodeitr)->addrconst==vcode->immconst[0]) isCorrect=true;
				break;
			}
		}
		if(isCorrect)
		{
			int addrconst=(int)GetVMAddrFromVirtualAddress(vcode->immconst[0]);
			//addrconst==0说明引用地址在其他区段，暂时不修正
			if(addrconst)
			{
				vcode->immconst[0]=addrconst;
				CompileVMCode(vcode,m_VMCode);//覆盖
			}
			isCorrect=false;
		}
	}
}
// 编译代码为字节码
BOOL CVMFactory::BuildVMCode(char* baseaddr,AVL<CodeNode,ulong> *AVLTree,list<AddrNode*> *AddrNodes,char* ErrText)
{
	list<CodeNode*>::iterator itr;

	ClearList();//清空VM链表

	//AddBeginHanlder(&vmlist,m_VMCode);//添加第一句恢复堆栈的VM指令


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
					if( code )
					{
						//判断AddressOfEntryPoint,添加第一句恢复堆栈的VM指令
						if(code->disasm.ip==0x401000)
							AddBeginHanlder(&vmlist,m_VMCode);//添加第一句恢复堆栈的VM指令

						//转换并添加到vm列表
						if( !TranslateVM(code) )
							return FALSE;
					}
				}
				p = p->rchild;
			}
		}
	}

	PlaceHandler();//放置Handler,生成JUMP表

	FixVCodeList(AddrNodes);
	return TRUE;
}
// 转换为VM结构并加入链表(非编译为字节码)
BOOL CVMFactory::TranslateVM(CodeNode* code)
{
	CodeNode mCodeNode;
	memcpy( &mCodeNode,code,sizeof(CodeNode) );
	
	//检测是否为段寄存器
	for(int opidx = 2; opidx > 0; opidx--)
	{
		if( mCodeNode.disasm.optype[opidx] == Seg )//为段积存器,暂时不支持
		{
			/*MessageBox(NULL,"[segment] 对不起,暂时不支持一些操作数.","错误",MB_OK);
			return FALSE;*/
			CompileUndeclared(&mCodeNode.disasm);
			return TRUE;
		}
	}
	VMTable* table = GetVMTableForAlready(mCodeNode.disasm.vm_name);
	if( !table )//如果没有收录,则把这句代码放到现实场景中执行.并将当前指令改成指向现实场景的地方
	{
		//执行.....跳转
		CompileUndeclared(&mCodeNode.disasm);
		return TRUE;
	}

	//VM指令中嵌入真实CPU指令
	if(mCodeNode.IsCallBeSideType)
	{
		//本来即为转到真实CPU执行
	}
	if(mCodeNode.IsCallFromType)
	{
		//被call过来的地址，重新进入虚拟机
		AddRealCodeToVM(&mCodeNode,m_VMCode);
	}
	if(mCodeNode.IsJmcBeSideType||mCodeNode.IsJmcDynamicType)
	{
		//真实环境中执行,IsJmcDynamicType可能会出问题，就是可能这个动态地址在虚拟机代码地址中
		CompileUndeclared(&mCodeNode.disasm);
		return TRUE;
	}

	for(int opidx = 2; opidx >= 0; opidx--)
	{
		switch(mCodeNode.disasm.optype[opidx])
		{
		case Imm://立即数
			{
				AddDPushIMM(opidx,&mCodeNode,m_VMCode);
			}
			break;
		case Reg://寄存器
			{
				AddDPushREG(opidx,&mCodeNode,m_VMCode);
			}
			break;
		case Mem://内存数
			{
				AddDPushMem(opidx,&mCodeNode,m_VMCode);
			}
			break;
		}
	}

	AddVMHandler(&mCodeNode,m_VMCode);//添加真正执行代码的vm指令
	//如果不是跳转指令
	if( !strstr(table->strInstruction,"LOOP") && table->strInstruction[0] != 'J' && table->strInstruction[0] != 'j' &&
		!strstr(table->strInstruction,"CALL") )
	{
			for(int opidx = 0; opidx < 2; opidx++)
			{
				//弹出由辅助指令压入的值
				if( opidx == 0 || table->Reg2Esp )//如果是第1个寄存器或者要求保存第2个寄存器
				{
					switch(mCodeNode.disasm.optype[opidx])
					{
					case Imm://立即数
					case Mem://内存数
						{
							AddDFree(opidx,&mCodeNode,m_VMCode);
						}
						break;
					case Reg://寄存器
						{
							AddDPopReg(opidx,&mCodeNode,m_VMCode);
						}
						break;
					}
				}
				else//不是第1个寄存器且不保存第2个寄存器
				{
					AddDFree(opidx,&mCodeNode,m_VMCode);
				}
			}
	}
	if( mCodeNode.disasm.reg[0] == RT_Esp )
		AddDRestoreEsp(0,&mCodeNode,m_VMCode);//将VM的ESP的值恢复到EBP
	else
		AddDSaveEsp(0,&mCodeNode,m_VMCode);//将EBP的值保存到VM的ESP

	return TRUE;
}
// 编译未声明的指令
void CVMFactory::CompileUndeclared(t_disasm *disasm)
{
	CompileToRealCode(disasm);
	CompileReEnterStubCode(disasm);
	CompileVMEnterStubCode();
}

// 编译退出并跳转到真实环境执行的代码
void CVMFactory::CompileToRealCode(t_disasm *disasm)
{
	VCodeNode* vcodenode = new VCodeNode();
	vcodenode->InAddress = disasm->ip;
	vcodenode->OperandNum = 1;
	vcodenode->immconst[0] = m_EnterStub->GetCurrentVirtualAddress();
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"VTOREAL");//添加真正执行的VM指令
	CompileVMCode(vcodenode,m_VMCode);
	vmlist.push_back(vcodenode);
}

// 编译从代码中进入虚拟机的汇编代码片段
void CVMFactory::CompileEnterStubCode(char* baseaddr,DWORD VirtualAddress,int len)
{
	char entercode[100] = {0};
	int enterlen = 0;
	char asmtext[TEXTLEN] = {0};
	sprintf_s(asmtext,TEXTLEN,"%spush %x\n",asmtext,m_VMCode->GetCurrentVirtualAddress());//进入的VMCODE片段
	sprintf_s(asmtext,TEXTLEN,"%sjmp  %x\n",asmtext,GetHandler("VStartVM")->VirtualAddress);

	if( !CompileCode(VirtualAddress,asmtext,entercode,&enterlen) )
	{
		MessageBox(0,"编译stub代码出现错误","错误",MB_OK);
		return;
	}
	memset(baseaddr,0xCC,len);//写成CC
	memcpy(baseaddr,entercode,enterlen);//进入VM的代码
}
// 编译重新进入虚拟机的汇编代码片段
DWORD CVMFactory::CompileReEnterStubCode(t_disasm *disasm)
{
	char code[100] = {0};
	int  codelen = 0;
	char entercode[100] = {0};
	int len = 0;
	char asmtext[TEXTLEN] = {0};
	int hexlen = 0;
	sprintf_s(asmtext,TEXTLEN,"%spush %x\n",asmtext,m_VMEnterStubCode->GetCurrentVirtualAddress());//VM重新进入的VMCODE片段
	sprintf_s(asmtext,TEXTLEN,"%sjmp  %x\n",asmtext,GetHandler("VStartVM")->VirtualAddress);

	if( disasm )
	{
		hexlen = disasm->codelen;
	}
	if( !CompileCode(m_EnterStub->GetCurrentVirtualAddress()+hexlen,asmtext,entercode,&len) )
	{
		MessageBox(0,"编译stub代码出现错误","错误",MB_OK);
		return 0;
	}
	if( disasm )
	{
		memcpy(&code[codelen],disasm->hexcode,disasm->codelen);
		codelen += disasm->codelen;
	}
	memcpy(&code[codelen],entercode,len);
	codelen += len;
	int start = m_EnterStub->WriteData((STu8*)code,codelen);

	return start;
}

// 编译重新进入虚拟机的VM代码片段
void CVMFactory::CompileVMEnterStubCode()
{
	list<VCodeNode*> revmlist;
	AddBeginHanlder(&revmlist,m_VMEnterStubCode);//添加第一句恢复堆栈的VM指令

	VCodeNode* vcodenode = new VCodeNode();
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"DPushImm32");
	vcodenode->OperandNum = 1;
	vcodenode->immconst[0] = m_VMCode->GetCurrentVirtualAddress();
	CompileVMCode(vcodenode,m_VMEnterStubCode);

	vcodenode = new VCodeNode();
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"VJMP_IMM32");
	vcodenode->OperandNum = 0;
	CompileVMCode(vcodenode,m_VMEnterStubCode);

	delete vcodenode;vcodenode = NULL;
}

// 通过汇编语句所在的虚拟地址找出VM语句所在的地址
DWORD CVMFactory::GetVMAddrFromVirtualAddress(DWORD VirtualAddress)
{
	list<VCodeNode*>::iterator itr;
	VCodeNode* code;
	if( !VirtualAddress )
		return 0;
	for( itr = vmlist.begin(); itr != vmlist.end(); itr++ )
	{
		code = *itr;
		if( code )
		{
			if( VirtualAddress == code->InAddress)
			{
				//找到VirtualAddress==code->InAddress的第一条指令虚拟地址
				return code->VMAddress;
			}
		}
	}
	return 0;
}
// 进入VM后执行的第一条恢复指令
void CVMFactory::AddBeginHanlder(list<VCodeNode*>* vlist,CVirtualMemory* sect)
{
	VCodeNode* vcodenode = new VCodeNode();
	vcodenode->InAddress = 0;
	vcodenode->OperandNum = 0;
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"VBEGIN");//添加真正执行的VM指令
	CompileVMCode(vcodenode,sect);
	vlist->push_back(vcodenode);
}
//添加handler到链表中
void CVMFactory::AddVMHandler(CodeNode *codenode,CVirtualMemory* sect)
{
	VCodeNode* vcodenode = new VCodeNode();
	vcodenode->InAddress = codenode->disasm.ip;
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,codenode->disasm.vm_name);//添加真正执行的VM指令
	if( /*strstr(codenode->disasm.vm_name,"VCALL")*/ codenode->IsCallType)//如果是CALL调用
	{
		vcodenode->OperandNum = 1;
		vcodenode->immconst[0] = CompileReEnterStubCode(NULL);//跳到CALL返回的地方
		AddVMHandlerEx(vcodenode,codenode,sect);
		CompileVMEnterStubCode();//跟上一句前后顺序不能变
	}
	else
	{
		vcodenode->OperandNum = 0;
		AddVMHandlerEx(vcodenode,codenode,sect);
	}
}
void CVMFactory::AddVMHandlerEx(VCodeNode* vcodenode,CodeNode *codenode,CVirtualMemory* sect)
{
	CompileVMCode(vcodenode,sect);
	vmlist.push_back(vcodenode);
}

// 辅助VM指令
void CVMFactory::AddDPushIMM(int idx,CodeNode *codenode,CVirtualMemory* sect)
{
	VCodeNode* vcodenode = new VCodeNode();
	vcodenode->InAddress = codenode->disasm.ip;
	vcodenode->OperandNum = 1;
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"DPushImm32");
	if( ( codenode->disasm.cmdtype & C_JMC ) == C_JMC || codenode->disasm.vm_name[1] == 'J' )
	{
		//MessageBox(0,"hi.上次不是没解决这里的问题么。","hi.",MB_OK);
		vcodenode->immconst[0] = codenode->disasm.jmpconst;
	}
	else
	{
		vcodenode->immconst[0] = codenode->disasm.immconst;
	}
	CompileVMCode(vcodenode,sect);
	vmlist.push_back(vcodenode);
}
void CVMFactory::AddDPushREG(int idx,CodeNode *codenode,CVirtualMemory* sect)
{
	//asm的regname偏移和RT_REG是一样的
	VCodeNode* vcodenode = new VCodeNode();
	vcodenode->InAddress = codenode->disasm.ip;
	vcodenode->OperandNum = 1;
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"DPushReg32");
	
	int regoffset = codenode->disasm.reg[idx];
	//push pop应该不会有8位的,一般不成立
	if( codenode->disasm.highbit[idx] )//如果是高位
		regoffset++;//取高位
	vcodenode->immconst[0] = InterpretHandler.GetRegisterOffset(regoffset);//寄存器偏移

	CompileVMCode(vcodenode,sect);
	vmlist.push_back(vcodenode);
}
void CVMFactory::AddDPushMem(int idx,CodeNode *codenode,CVirtualMemory* sect)
{
	VCodeNode* vcodenode = new VCodeNode();
	vcodenode->InAddress = codenode->disasm.ip;
	vcodenode->OperandNum = 1;
	vcodenode->immconst[0] = codenode->disasm.adrconst;
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"DPushImm32");
	CompileVMCode(vcodenode,sect);//压入MEM中的常数
	vmlist.push_back(vcodenode);

	vcodenode = new VCodeNode();
	vcodenode->InAddress = codenode->disasm.ip;
	vcodenode->OperandNum = 1;
	vcodenode->immconst[0] = codenode->disasm.regsscale;
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"DPushImm32");
	CompileVMCode(vcodenode,sect);//压入第2个寄存器的比例
	vmlist.push_back(vcodenode);

	vcodenode = new VCodeNode();
	vcodenode->InAddress = codenode->disasm.ip;
	vcodenode->OperandNum = 1;
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"DPushImm32");
	vcodenode->immconst[0] = InterpretHandler.GetRegisterOffset(codenode->disasm.addrreg2);
	CompileVMCode(vcodenode,sect);//第2寄存器偏移
	vmlist.push_back(vcodenode);

	vcodenode = new VCodeNode();
	vcodenode->InAddress = codenode->disasm.ip;
	vcodenode->OperandNum = 1;
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"DPushImm32");
	vcodenode->immconst[0] = InterpretHandler.GetRegisterOffset(codenode->disasm.addrreg1);
	CompileVMCode(vcodenode,sect);//第1寄存器偏移
	vmlist.push_back(vcodenode);
	
	vcodenode = new VCodeNode();
	vcodenode->InAddress = codenode->disasm.ip;
	vcodenode->OperandNum = 0;
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"DPushMem32");//这个handler会自动平栈再压操作数
	CompileVMCode(vcodenode,sect);
	vmlist.push_back(vcodenode);
}
void CVMFactory::AddDPopReg(int idx,CodeNode *codenode,CVirtualMemory* sect)
{
	VCodeNode* vcodenode = new VCodeNode();
	vcodenode->InAddress = codenode->disasm.ip;
	vcodenode->OperandNum = 1;
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"DPopReg32");//这个handler会自动平栈再压操作数

	int regoffset = codenode->disasm.reg[idx];
	//push pop应该不会有8位的,一般不成立
	if( codenode->disasm.highbit[idx] )//如果是高位
		regoffset++;//取高位
	vcodenode->immconst[0] = InterpretHandler.GetRegisterOffset(regoffset);//寄存器偏移

	CompileVMCode(vcodenode,sect);
	vmlist.push_back(vcodenode);
}
void CVMFactory::AddDFree(int idx,CodeNode *codenode,CVirtualMemory* sect)
{
	VCodeNode* vcodenode = new VCodeNode();
	vcodenode->InAddress = codenode->disasm.ip;
	vcodenode->OperandNum = 0;
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"DFree");//这个handler会自动平栈再压操作数
	CompileVMCode(vcodenode,sect);
	vmlist.push_back(vcodenode);
}
void CVMFactory::AddRealCodeToVM(CodeNode *codenode,CVirtualMemory* sect)
{
	VCodeNode* vcodenode = new VCodeNode();
	vcodenode->InAddress = codenode->disasm.ip;
	vcodenode->OperandNum = 1;
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"DRealCode");		//没有实际对应的hander
	vcodenode->immconst[0] = CompileReEnterStubCode(NULL);//跳到CALL返回的地方
	
	DWORD aleadyAddr = FALSE;
	if( vcodenode->VMAddress )
	{
		aleadyAddr = TRUE;//已经有地址了
	}
	else
	{
		vcodenode->VMAddress = sect->GetCurrentVirtualAddress();
	}

	vcodenode->HexCode[0] = 0xB8;
	vcodenode->HexLen = 1;
	for(int i = 0;i < vcodenode->OperandNum;i++)
	{
		*(DWORD*)&vcodenode->HexCode[i+1] = (DWORD)vcodenode->immconst[i];
		vcodenode->HexLen+=4;
	}
	vcodenode->HexCode[vcodenode->HexLen++]=0xFF;
	vcodenode->HexCode[vcodenode->HexLen++]=0xE0;
	if( aleadyAddr )
	{
		sect->WriteData(vcodenode->VMAddress,(STu8*)vcodenode->HexCode,vcodenode->HexLen);
	}
	else
	{
		sect->WriteData((STu8*)vcodenode->HexCode,vcodenode->HexLen);
	}
	vmlist.push_back(vcodenode);
	CompileVMEnterStubCode();
}
//保存堆栈
void CVMFactory::AddDSaveEsp(int idx,CodeNode *codenode,CVirtualMemory* sect)
{
	VCodeNode* vcodenode = new VCodeNode();
	vcodenode->InAddress = codenode->disasm.ip;
	vcodenode->OperandNum = 0;
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"VSAVEESP");//这个handler会自动平栈再压操作数
	CompileVMCode(vcodenode,sect);
	vmlist.push_back(vcodenode);
}
//恢复堆栈
void CVMFactory::AddDRestoreEsp(int idx,CodeNode *codenode,CVirtualMemory* sect)
{
	VCodeNode* vcodenode = new VCodeNode();
	vcodenode->InAddress = codenode->disasm.ip;
	vcodenode->OperandNum = 0;
	strcpy_s(vcodenode->VMInstrName,VMNAMELEN,"VRESTOREESP");//这个handler会自动平栈再压操作数
	CompileVMCode(vcodenode,sect);
	vmlist.push_back(vcodenode);
}
// 编译
void CVMFactory::CompileVMCode(VCodeNode* vcodenode,CVirtualMemory* sect)
{
	DWORD aleadyAddr = FALSE;
	if( vcodenode->VMAddress )
	{
		aleadyAddr = TRUE;//已经有地址了
	}
	else
	{
		vcodenode->VMAddress = sect->GetCurrentVirtualAddress();
	}
	BYTE handleidx = (BYTE)GetIdxFromVMName(vcodenode->VMInstrName);
	vcodenode->HexCode[0] = handleidx;
	vcodenode->HexLen = 1;
	for(int i = 0;i < vcodenode->OperandNum;i++)
	{
		*(DWORD*)&vcodenode->HexCode[i+1] = (DWORD)vcodenode->immconst[i];
		vcodenode->HexLen+=4;
	}
	if( aleadyAddr )//已经有地址了则直接覆盖
	{
		sect->WriteData(vcodenode->VMAddress,(STu8*)vcodenode->HexCode,vcodenode->HexLen);
	}
	else
	{
		sect->WriteData((STu8*)vcodenode->HexCode,vcodenode->HexLen);
	}
}
