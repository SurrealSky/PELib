
// PEMakeDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "PEMake.h"
#include "PEMakeDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CPEMakeDlg 对话框




CPEMakeDlg::CPEMakeDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CPEMakeDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPEMakeDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_MFCEDITBROWSE1, tbFilePath);
}

BEGIN_MESSAGE_MAP(CPEMakeDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CPEMakeDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CPEMakeDlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// CPEMakeDlg 消息处理程序

BOOL CPEMakeDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	tbFilePath.SetWindowTextA("D:\\work\\program\\PELib\\protecttmp\\temp.exe");
	CheckDlgButton(IDC_RADIO1, TRUE);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CPEMakeDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CPEMakeDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CPEMakeDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//保护
void CPEMakeDlg::OnBnClickedButton1()
{
	//需要等待线程等待完成
	if (mPEMake.isAnalysised())
	{
		mPEMake.PEUnload();
	}
	CString m_Path;
	tbFilePath.GetWindowText(m_Path);
	if (m_Path.GetLength() == 0)
	{
		::MessageBox(this->m_hWnd, "请选择要分析的文件", "警告", MB_OK);
		return;
	}
	//加载文件
	if (!mPEMake.PELoadFile(m_Path.GetBuffer(0), "r"))     //只读方式打开文件
	{
		::MessageBox(this->m_hWnd, "文件加载失败", "警告", MB_OK);
		return;
	}

	if (!mPEMake.CheckPESig())
	{
		::MessageBox(this->m_hWnd, "PE文件错误", "警告", MB_OK);
		return;
	}

	if (mPEMake.Analysis())
	{
		mPEMake.SetAnalysised(true);
	}
	else
	{
		mPEMake.SetAnalysised(false);
		return;
	}

	bool bRet = false;

	std::string savePath = mPEMake.mPeCtx.path;
	int pos = savePath.find_last_of('.');
	
	if (IsDlgButtonChecked(IDC_RADIO1))
	{
		bRet = mPEMake.Protect1A();
		savePath.insert(pos + 1, "patch.");
	}
	else if (IsDlgButtonChecked(IDC_RADIO2))
	{
		bRet = mPEMake.Protect2A();
		savePath.insert(pos + 1, "encrypt.");
	}
	else if (IsDlgButtonChecked(IDC_RADIO3))
	{
		bRet = mPEMake.Protect3A();
		savePath.insert(pos + 1, "yoda.");
	}
	else if (IsDlgButtonChecked(IDC_RADIO4))
	{
		bRet = mPEMake.Protect4A();
		savePath.insert(pos + 1, "vm.");
	}
	if(bRet)
	{
		CFileDialog dlg(FALSE, "exe", savePath.c_str(), OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, "TXT Files(*.exe)|*.exe|All Files(*.*)|*.*");
		///TRUE为OPEN对话框，FALSE为SAVE AS对话框  
		if (dlg.DoModal() == IDOK)
		{
			CFile mFile(dlg.GetPathName(), CFile::modeCreate | CFile::modeReadWrite);
			mFile.Write(mPEMake.mPeCtx.pVirMem, mPEMake.mPeCtx.size);
			mFile.Close();
			AfxMessageBox("另存成功");
			return;
		}
		else
			return;
	}
	AfxMessageBox("保护失败");
}

//退出
void CPEMakeDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	this->OnOK();
}
