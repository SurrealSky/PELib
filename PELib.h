#include<Windows.h>
#include<stdio.h>

#include<MemoryPool/MemMgr.h>
using namespace SurrealMemMgr;

#ifdef _DEBUG
#pragma comment(lib, "CommonLib\\MemoryPool\\bind\\MemMgr.lib")
#else
#pragma comment(lib, "CommonLib\\MemoryPool\\bin\\MemMgr.lib")
#endif

#include<DbgHelp.h>
#pragma comment(lib, "dbghelp.lib")
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#include"CompressLib\aplib.h"
#pragma comment(lib,"CompressLib\\aplib.lib")

//?????ض?????
//#define DebugMode