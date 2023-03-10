
#include<vector>
////////////////////////////////////////////////////////////////////////////////////
//新段各部分空间的长度

#define JumpTableLen		(HANDLERMAXLEN*4)
//#define CodeEngineLen		(4096*4)					//空间存放引擎代码
//#define EnterStubAddrLen	(4096)						//重新进入VM的Stub，长度1024字节
//#define VMEnterCodeLen		(4096*2)					//空间存放重新进入的vmcode
//
//#define VMCodeLen			(10240*2)					//2K的空间存放VMCode
#define ASMTEXTLEN			1024						//汇编文本长度
////////////////////////////////////////////////////////////////////////////////////

//8086指令字符串长度
#define X86NAMELEN					32
//Handler命令字符串长度
#define VMNAMELEN					32
//Handler的最大Handler长度
#define CODEMAXLEN					512
//最上面存放寄存器,后来的一些就当vm堆栈用了
#define STACKLEN					0x200
//寄存器最大个数
#define REGCOUNT					15
//命令Handler最大个数
#define HANDLERMAXLEN				0xFF
//VMTABEL表的个数
#define VMTABLEMAXLEN				0x400
//核心伪指令个数
#define COREHANDLERLEN				10

//没有用到寄存器
#define NONE	-1

//寄存器
enum RegType
{
	RT_Eax,
	RT_Ecx,
	RT_Edx,
	RT_Ebx,
	RT_Esp,
	RT_Ebp,
	RT_Esi,
	RT_Edi,
	RT_CS,
	RT_DS,
	RT_ES,
	RT_FS,
	RT_GS,
	RT_SS,

	RT_EFlag,//必须是最后一个(为什么?我忘了)
	//
	RT_AH = 20,
	RT_CH,
	RT_DH,
	RT_BH,
};

enum optype
{
	NONETYPE,
	IMMTYPE,
	REGTYPE,
	MEMTYPE,
	CSTYPE,
	DSTYPE,
	ESTYPE,
	SSTYPE,
	FSTYPE,
	GSTYPE,
};

//用来生成handler的汇编代码的结构
struct VMTable
{
	char	VMInstrName[VMNAMELEN];		//VM命令名称
	char	strInstruction[16];			//相对的汇编指令
	int		OperandNum;					//操作数个数
	int		Segment;					//段前缀
	int		optype[2];					//操作类型(寄存器,立即数,内存数)
	int		bitnum[2];					//位数

	int		NeedReg[4];					//执行命令前要使用的寄存器
	int		SaveReg[4];					//执行命令后要保存的指令
	BOOL	Reg2Esp;					//第2个寄存器是否恢复,一般为0不恢复
};
//存放handler的汇编代码,VirtualAddress存放排序后在内存中的地址
struct VHandler
{
	char	VMInstrName[VMNAMELEN];			//VM命令名称
	DWORD	VirtualAddress;				//虚拟地址
	char    AssembleCode[CODEMAXLEN];	//汇编代码
	int     CodeLen;					//函数长度
	VHandler()
	{
		memset(this,0,sizeof(VHandler));
	}
};

//函数定义
typedef void (*HandlerFunc)();
//核心的一些手工VM函数名称和对应的函数
struct VM_DName
{
	char		vm_dname[VMNAMELEN];
	HandlerFunc	FuncAddr;
};

extern VM_DName	vm_dname[COREHANDLERLEN];

//描述一些标准Handler的行为表
extern VMTable	vmtable[VMTABLEMAXLEN];
//寄存器对应表
extern const char *vregname[3][14];
extern const char ArgReg[3][4];

struct VM_RandomTable
{
	char	VMInstrName[VMNAMELEN];			//VM命令名称
	int		idx;							//对应的索引
};

struct VM_Immconst
{
	int _isVMAddress;		//0代表虚拟机外地址,1代表虚拟机内地址
	int _immconst;
};

//伪指令宏链表(即字节码的伪代码)
struct VCodeNode 
{
	DWORD	InAddress;					//原来所在的地址
	DWORD	VMAddress;					//VM指令所在的地址
	char	VMInstrName[VMNAMELEN];		//VM命令名称
	BYTE	HexCode[32];				//字节码
	int		HexLen;						//字节码长度
	int		OperandNum;					//操作数个数

	int		immconst[2];				//立即数(寄存器,立即数,内存数)
	//VM_Immconst immconst[2];
	int		bitnum[2];					//位数
	VCodeNode()
	{
		InAddress = 0;
		VMAddress = 0;
		memset(VMInstrName,0,VMNAMELEN);
		memset(HexCode,0,32);
		HexLen = 0;
		OperandNum = 0;
		immconst[0] = immconst[1] = bitnum[0] = bitnum[1] = 0;
	}
};

// 为一个索引数组随机排序.
//void	RandListIdx(std::vector<int> &idx,int cout);

void	RandListIdx(int *idx,int cout);