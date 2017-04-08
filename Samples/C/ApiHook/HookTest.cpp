/*
 * Copyright (C) 2010-2015 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved. Contact: http://www.nektra.com
 *
 *
 * This file is part of Deviare In-Proc
 *
 *
 * Commercial License Usage
 * ------------------------
 * Licensees holding valid commercial Deviare In-Proc licenses may use this
 * file in accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and Nektra.  For licensing terms and
 * conditions see http://www.nektra.com/licensing/.  For further information
 * use the contact form at http://www.nektra.com/contact/.
 *
 *
 * GNU General Public License Usage
 * --------------------------------
 * Alternatively, this file may be used under the terms of the GNU
 * General Public License version 3.0 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.  Please review the following information to
 * ensure the GNU General Public License version 3.0 requirements will be
 * met: http://www.gnu.org/copyleft/gpl.html.
 *
 **/

// #define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include "..\..\..\Include\NktHookLib.h"

#define DISALLOW_REENTRANCY

//-----------------------------------------------------------

#if _MSC_VER >= 1910
  #define X_LIBPATH "2017"
#elif _MSC_VER >= 1900
  #define X_LIBPATH "2015"
#elif _MSC_VER >= 1800
  #define X_LIBPATH "2013"
#elif _MSC_VER >= 1700
  #define X_LIBPATH "2012"
#elif  _MSC_VER >= 1600
  #define X_LIBPATH "2010"
#else
  #define X_LIBPATH "2008"
#endif

#if defined _M_IX86
  #ifdef _DEBUG
    #pragma comment (lib, "..\\..\\..\\..\\Libs\\" X_LIBPATH "\\NktHookLib_Debug.lib")
  #else //_DEBUG
    #pragma comment (lib, "..\\..\\..\\..\\Libs\\" X_LIBPATH "\\NktHookLib.lib")
  #endif //_DEBUG
#elif defined _M_X64
  #ifdef _DEBUG
    #pragma comment (lib, "..\\..\\..\\..\\Libs\\" X_LIBPATH "\\NktHookLib64_Debug.lib")
  #else //_DEBUG
    #pragma comment (lib, "..\\..\\..\\..\\Libs\\" X_LIBPATH "\\NktHookLib64.lib")
  #endif //_DEBUG
#else
  #error Unsupported platform
#endif

#if 0

#include <stdio.h>

HRESULT(STDMETHODCALLTYPE *RealInvokeFn)(
	DISPID     dispIdMember,
	REFIID     riid,
	LCID       lcid,
	WORD       wFlags,
	DISPPARAMS *pDispParams,
	VARIANT    *pVarResult,
	EXCEPINFO  *pExcepInfo,
	UINT       *puArgErr
	);

HRESULT STDMETHODCALLTYPE HookedInvokeFunction(
	DISPID     dispIdMember,
	REFIID     riid,
	LCID       lcid,
	WORD       wFlags,
	DISPPARAMS *pDispParams,
	VARIANT    *pVarResult,
	EXCEPINFO  *pExcepInfo,
	UINT       *puArgErr
)
{
	printf("Hooked invoke %d\n", dispIdMember);
	return RealInvokeFn(dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);
}

static CNktHookLib cHookMgr;

static void
hookIDispatch(void)
{
	::MessageBoxW(NULL, L"About to hook IDispatch", L"TestDll", MB_OK);
	// FIXME: does this work nicely so early in the startup ?
	CoInitialize(NULL);

	CLSID clsid;
	LPCOLESTR progID = L"Excel.Application";

	HRESULT hr = CLSIDFromProgID(progID, &clsid);
	if (FAILED(hr))
	{
		printf("Can't find prog-id\n");
		return;
	}
	IDispatch *pApp = NULL;
	hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER /* out of proc*/, IID_PPV_ARGS(&pApp));
	if (FAILED(hr))
	{
		printf("Failed to create instance\n");
	}
	if (pApp == NULL)
	{
		printf("No IDispatch interface\n");
	}

	SIZE_T ignoreHookId;
	cHookMgr.Hook(&ignoreHookId, (LPVOID *)&RealInvokeFn, (LPVOID)42 /*pApp->Invoke*/, (LPVOID)HookedInvokeFunction,
		NKTHOOKLIB_DisallowReentrancy);

	// Leak the COM object - why not.
	::MessageBoxW(NULL, L"Done hooking IDispatch", L"TestDll", MB_OK);
}

extern "C" BOOL APIENTRY DllMain(__in HMODULE hModule, __in DWORD ulReasonForCall, __in LPVOID lpReserved)
{
	switch (ulReasonForCall)
	{
	case DLL_PROCESS_ATTACH:
		hookIDispatch();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

extern "C" DWORD __stdcall InitializeDll()
{
	if (::MessageBoxW(NULL, L"In InitializeDll. Press 'OK' to continue or 'Cancel' to return an error.", L"TestDll",
		MB_OKCANCEL) != IDOK)
	{
		return ERROR_CANCELLED;
	}
	return ERROR_SUCCESS;
}

#else
//-----------------------------------------------------------

typedef int (WINAPI *lpfnMessageBoxW)(__in_opt HWND hWnd, __in_opt LPCWSTR lpText, __in_opt LPCWSTR lpCaption, __in UINT uType);
static int WINAPI Hooked_MessageBoxW(__in_opt HWND hWnd, __in_opt LPCWSTR lpText, __in_opt LPCWSTR lpCaption, __in UINT uType);

static struct {
  SIZE_T nHookId;
  lpfnMessageBoxW fnMessageBoxW;
} sMessageBoxW_Hook = { 0, NULL };

//-----------------------------------------------------------

int WinMainCRTStartup()
//int WINAPI WinMain(__in HINSTANCE hInstance, __in_opt HINSTANCE hPrevInstance, __in_opt LPTSTR lpCmdLine, __in int nShowCmd)
{
  CNktHookLib cHookMgr;
  HINSTANCE hUser32Dll;
  LPVOID fnOrigMessageBoxW;
  DWORD dwOsErr;

  cHookMgr.SetEnableDebugOutput(TRUE);

  hUser32Dll = NktHookLibHelpers::GetModuleBaseAddress(L"user32.dll");
  if (hUser32Dll == NULL) {
    ::MessageBoxW(0, L"Error: Cannot get handle of user32.dll", L"HookTest", MB_OK|MB_ICONERROR);
    return 0;
  }
  fnOrigMessageBoxW = NktHookLibHelpers::GetProcedureAddress(hUser32Dll, "MessageBoxW");
  if (fnOrigMessageBoxW == NULL) {
    ::MessageBoxW(0, L"Error: Cannot get address of MessageBoxW", L"HookTest", MB_OK|MB_ICONERROR);
    return 0;
  }

  dwOsErr = cHookMgr.Hook(&(sMessageBoxW_Hook.nHookId), (LPVOID*)&(sMessageBoxW_Hook.fnMessageBoxW),
                          fnOrigMessageBoxW, Hooked_MessageBoxW,
#ifdef DISALLOW_REENTRANCY
                          NKTHOOKLIB_DisallowReentrancy
#else //DISALLOW_REENTRANCY
                          0
#endif //DISALLOW_REENTRANCY
                          );

  ::MessageBoxW(0, L"This should be hooked", L"HookTest", MB_OK);
  //dwOsErr = cHookMgr.EnableHook(dwHookId_MessageBoxW, FALSE);
  dwOsErr = cHookMgr.Unhook(sMessageBoxW_Hook.nHookId);

  ::MessageBoxW(0, L"This should NOT be hooked", L"HookTest", MB_OK);

  return 0;
}

static int WINAPI Hooked_MessageBoxW(__in_opt HWND hWnd, __in_opt LPCWSTR lpText, __in_opt LPCWSTR lpCaption, __in UINT uType)
{
#ifdef DISALLOW_REENTRANCY
  //NOTE: When a hook is created with DISALLOW_REENTRANCY, then we can call the original function directly.
  //      The stub will detected the call comes from the same thread and redirect it to the original function.
  return ::MessageBoxW(hWnd, lpText, L"HOOKED!!!", uType);
#else //DISALLOW_REENTRANCY
  //NOTE: If the hook is NOT created with the DISALLOW_REENTRANCY flag, then we must call the returned function pointer.
  return sMessageBoxW_Hook.fnMessageBoxW(hWnd, lpText, L"HOOKED!!!", uType);
#endif //DISALLOW_REENTRANCY
}

//NOTE: The code below was added because we are linking without default VC runtime libraries in order to show
//      that NktHookLib does not depend on the VC runtime nor Kernel dlls.
//      Visual C's default setting is to create a SAFESEH compatible image executable. NktHookLib is compiled using
//      safeseh too.
//      Normally you application will be linked against the VC runtime libraries. If so, do not add the code below.
#if defined(_M_IX86)
  #ifdef __cplusplus
  extern "C" {
  #endif //__cplusplus
  extern PVOID __safe_se_handler_table[];
  extern BYTE  __safe_se_handler_count;

  IMAGE_LOAD_CONFIG_DIRECTORY32 _load_config_used = {
      sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32),
      0,    0,    0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,
      0,
      (DWORD)__safe_se_handler_table,
      (DWORD) &__safe_se_handler_count
  };
  #ifdef __cplusplus
  }
  #endif //__cplusplus
#endif //_M_IX86

#endif // 0