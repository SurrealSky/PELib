; #########################################################################

      .386
      .model flat, stdcall
      option casemap :none   ; case sensitive

; #########################################################################

      include c:\masm32\include\windows.inc
      include c:\masm32\include\user32.inc
      include c:\masm32\include\kernel32.inc

      includelib c:\masm32\lib\user32.lib
      includelib c:\masm32\lib\kernel32.lib

; #########################################################################

    .data
    szDlgTitle    db "Minimum MASM",0
    szMsg         db "  --- Assembler Pure and Simple ---  ",0
    
    .code
start:
    push MB_OK
    push offset szDlgTitle
    push offset szMsg
    push 0
    call MessageBox

    push 0
    call ExitProcess

    ; invoke MessageBox,0,ADDR szMsg,ADDR szDlgTitle,MB_OK
    ; invoke ExitProcess,0

end start