﻿#pragma once
#include "vmdisasm.h"

class CInterpretHandler
{
public:
	CInterpretHandler(void);
public:
	~CInterpretHandler(void);
private:
	// 寄存器数组索引
	int			m_RegisterIdx[STACKLEN];
public:
	// 初始化
	BOOL Init();
public:
	// 获得寄存器的偏移
	int GetRegisterOffset(int RegType);
	// 获得段前缀
	char* GetSegStr(int Segment);
	// 根据结构声称ASM字符串
	BOOL	InterpretASMStr(VMTable* table,char* asmtext,int len);
private:
	//设置参数
	void SetArg(VMTable* table,char* asmtext,int len);
	//恢复参数
	void RestoreArg(VMTable* table,char* asmtext,int len);
	//恢复标志
	void RestoreFlag(char* asmtext,int len);
	//保存标志
	void SaveFlag(char* asmtext,int len);
private:
	// 首先执行的指令
	BOOL	InterpretvBegin(VMTable* table,char* asmtext,int len);
	// 跳转到真实指令
	BOOL	InterpretvtoReal(VMTable* table,char* asmtext,int len);
	// *********************堆栈类********************************* //
	// 解释push
	BOOL	InterpretPush(VMTable* table,char* asmtext,int len);
	// 解释pop
	BOOL	InterpretPop(VMTable* table,char* asmtext,int len);
	// 解释pushfd
	BOOL	InterpretPushfd(VMTable* table,char* asmtext,int len);
	// 解释popfd
	BOOL	InterpretPopfd(VMTable* table,char* asmtext,int len);
	// 解释pushad
	BOOL	InterpretPushad(VMTable* table,char* asmtext,int len);
	// 解释popad
	BOOL	InterpretPopad(VMTable* table,char* asmtext,int len);
	// 解释enter
	BOOL	InterpretEnter(VMTable* table,char* asmtext,int len);
	// 解释leave
	BOOL	InterpretLeave(VMTable* table,char* asmtext,int len);
	// *********************流程类********************************* //
	// 解释jmp
	BOOL	InterpretJMP(VMTable* table,char* asmtext,int len);
	// 解释jcxz\jecxz
	BOOL	InterpretJCXZ(VMTable* table,char* asmtext,int len);
	// 解释jcc
	BOOL	InterpretJCC(VMTable* table,char* asmtext,int len);
	// 解释loope
	BOOL InterpretLoope(VMTable* table,char* asmtext,int len);

	// 解释返回
	BOOL InterpretRetn(VMTable* table,char* asmtext,int len);
	// 解释子调用
	BOOL InterpretCall(VMTable* table,char* asmtext,int len);

	// 普通指令
	BOOL CommonInstruction(VMTable* table,char* asmtext,int len);
	// 解释保护堆栈Handler
	BOOL InterpretSaveEsp(VMTable* table,char* asmtext,int len);
	// 解释恢复堆栈Handler
	BOOL InterpretRestoreEsp(VMTable* table,char* asmtext,int len);
};
  