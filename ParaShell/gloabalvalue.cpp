#include <windows.h>
#include "globalvalue.h"

// 进程实例句柄
HINSTANCE g_hInst;

// 显示窗口缓冲区
TCHAR* g_pMessageBuffer = NULL;

// 进度条句柄
HWND g_hProgress = NULL;