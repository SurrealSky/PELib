;------------------------
; 该程序演示了一个登录窗口的补丁程序
; 免重定位信息，无数据段，无导入表
; 戚利
; 2010.6.28
;------------------------
    .386
    .model flat,stdcall
    option casemap:none

include    c:\masm32\include\windows.inc
include    c:\masm32\include\user32.inc
;includelib user32.lib
include    c:\masm32\include\kernel32.inc
;includelib kernel32.lib


;代码段
    .code
jmp start

szCaption          db  '欢迎您！',0
szText             db  '您是合法用户，请使用该软件！',0
szCaptionMain      db  '系统登录',0

start:
    ;取当前函数的堆栈栈顶值
    mov eax,dword ptr [esp]
    push eax
    call @F   ; 免去重定位
@@:
    pop ebx
    sub ebx,offset @B
    pop eax
    ;获取kernel32.dll的基地址
    invoke _getKernelBase,eax
    mov [ebx+offset hKernel32Base],eax

    ;从基地址出发搜索GetProcAddress函数的首址
    mov eax,offset szGetProcAddress
    add eax,ebx
    mov ecx,[ebx+offset hKernel32Base]
    invoke _getApi,ecx,eax
    mov [ebx+offset _GetProcAddress],eax   ;为函数引用赋值 GetProcAddress

    ;使用GetProcAddress函数的首址，传入两个参数调用GetProcAddress函数，获得LoadLibraryA的首址
    mov eax,offset szLoadLibraryA
    add eax,ebx
    
    push eax
    push [ebx+offset hKernel32Base]
    mov edx,[ebx+offset _GetProcAddress]
    call edx
    mov [ebx+offset _LoadLibraryA],eax

    invoke _getDllBase      ;获取所有用到的dll的基地址，kernel32除外
    invoke _getFuns         ;获取所有用到的函数的入口地址，GetProcAddress和LoadLibraryA除外
    invoke _WinMain,ebx

    jmpToStart   db 0E9h,0F0h,0FFh,0FFh,0FFh
    ret
    end start
