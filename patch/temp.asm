;------------------------
; �ó�����ʾ��һ����¼���ڵĲ�������
; ���ض�λ��Ϣ�������ݶΣ��޵����
; ����
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


;�����
    .code
jmp start

szCaption          db  '��ӭ����',0
szText             db  '���ǺϷ��û�����ʹ�ø������',0
szCaptionMain      db  'ϵͳ��¼',0

start:
    ;ȡ��ǰ�����Ķ�ջջ��ֵ
    mov eax,dword ptr [esp]
    push eax
    call @F   ; ��ȥ�ض�λ
@@:
    pop ebx
    sub ebx,offset @B
    pop eax
    ;��ȡkernel32.dll�Ļ���ַ
    invoke _getKernelBase,eax
    mov [ebx+offset hKernel32Base],eax

    ;�ӻ���ַ��������GetProcAddress��������ַ
    mov eax,offset szGetProcAddress
    add eax,ebx
    mov ecx,[ebx+offset hKernel32Base]
    invoke _getApi,ecx,eax
    mov [ebx+offset _GetProcAddress],eax   ;Ϊ�������ø�ֵ GetProcAddress

    ;ʹ��GetProcAddress��������ַ������������������GetProcAddress���������LoadLibraryA����ַ
    mov eax,offset szLoadLibraryA
    add eax,ebx
    
    push eax
    push [ebx+offset hKernel32Base]
    mov edx,[ebx+offset _GetProcAddress]
    call edx
    mov [ebx+offset _LoadLibraryA],eax

    invoke _getDllBase      ;��ȡ�����õ���dll�Ļ���ַ��kernel32����
    invoke _getFuns         ;��ȡ�����õ��ĺ�������ڵ�ַ��GetProcAddress��LoadLibraryA����
    invoke _WinMain,ebx

    jmpToStart   db 0E9h,0F0h,0FFh,0FFh,0FFh
    ret
    end start
