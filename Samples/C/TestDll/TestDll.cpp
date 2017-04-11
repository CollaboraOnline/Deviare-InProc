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

#include "TestDll.h"
#include "..\..\..\Include\NktHookLib.h"

#if 0

HRESULT (STDMETHODCALLTYPE *RealInvokeFn)(
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
	wchar_t message[100];
	NktHookLibHelpers::swprintf_s(message, sizeof(message)/sizeof(message[0]), L"Hooked invoke %d", dispIdMember);
	::MessageBoxW(NULL, message, L"TestDll", MB_OK);
	return RealInvokeFn(dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);
}

#endif

static CNktHookLib cHookMgr;

#if 0

static void
hookIDispatch(void)
{
	HRESULT hr;

	::MessageBoxW(NULL, L"About to newly hook IDispatch", L"TestDll", MB_OK);
	// FIXME: does this work nicely so early in the startup ?
	hr = CoInitialize(NULL);
	if (FAILED(hr))
	{
		::MessageBoxW(NULL, L"CoInitialize failed", L"TestDll", MB_ICONERROR|MB_OK);
		return;
	}

	CLSID clsid;
	LPCOLESTR progID = L"Excel.Application";

	hr = CLSIDFromProgID(progID, &clsid);
	if (FAILED(hr))
	{
		::MessageBoxW(NULL, L"Can't find CLSID for Excel.Aplication", L"TestDll", MB_ICONERROR|MB_OK);
		return;
	}
	IDispatch *pApp = NULL;
	hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER /* out of proc*/, IID_PPV_ARGS(&pApp));
	if (FAILED(hr))
	{
		::MessageBoxW(NULL, L"Failed to create Excel instance", L"TestDll", MB_ICONERROR|MB_OK);
	}
	if (pApp == NULL)
	{
		::MessageBoxW(NULL, L"No IDispatch interface", L"TestDll", MB_ICONERROR|MB_OK);
	}
	::MessageBoxW(NULL, L"got IDispatch", L"TestDll", MB_OK);

	SIZE_T ignoreHookId;
	cHookMgr.Hook(&ignoreHookId, (LPVOID *)&RealInvokeFn, (LPVOID)42 /*pApp->Invoke*/, (LPVOID)HookedInvokeFunction,
		          NKTHOOKLIB_DisallowReentrancy);

	// Leak the COM object - why not.
	::MessageBoxW(NULL, L"Done hooking IDispatch", L"TestDll", MB_OK);
}

#endif

typedef HRESULT (WINAPI *lpfnCoCreateInstance)(_In_  REFCLSID  rclsid,
					       _In_  LPUNKNOWN pUnkOuter,
					       _In_  DWORD     dwClsContext,
					       _In_  REFIID    riid,
					       _Out_ LPVOID    *ppv);

static HRESULT WINAPI Hooked_CoCreateInstance(_In_  REFCLSID  rclsid,
					      _In_  LPUNKNOWN pUnkOuter,
					      _In_  DWORD     dwClsContext,
					      _In_  REFIID    riid,
					      _Out_ LPVOID    *ppv);

static struct {
  SIZE_T nHookId;
  lpfnCoCreateInstance fnCoCreateInstance;
} sCoCreateInstance_Hook = { 0, NULL };

typedef HRESULT (WINAPI *lpfnCoCreateInstanceEx)(_In_    REFCLSID     rclsid,
						 _In_    IUnknown     *punkOuter,
						 _In_    DWORD        dwClsCtx,
						 _In_    COSERVERINFO *pServerInfo,
						 _In_    DWORD        dwCount,
						 _Inout_ MULTI_QI     *pResults);

static HRESULT WINAPI Hooked_CoCreateInstanceEx(_In_    REFCLSID     rclsid,
						_In_    IUnknown     *punkOuter,
						_In_    DWORD        dwClsCtx,
						_In_    COSERVERINFO *pServerInfo,
						_In_    DWORD        dwCount,
						_Inout_ MULTI_QI     *pResults);

static struct {
  SIZE_T nHookId;
  lpfnCoCreateInstanceEx fnCoCreateInstanceEx;
} sCoCreateInstanceEx_Hook = { 0, NULL };

typedef HRESULT (WINAPI *lpfnCoGetClassObject)(_In_     REFCLSID     rclsid,
					       _In_     DWORD        dwClsContext,
					       _In_opt_ COSERVERINFO *pServerInfo,
					       _In_     REFIID       riid,
					       _Out_    LPVOID       *ppv);

static HRESULT WINAPI Hooked_CoGetClassObject(_In_     REFCLSID     rclsid,
					      _In_     DWORD        dwClsContext,
					      _In_opt_ COSERVERINFO *pServerInfo,
					      _In_     REFIID       riid,
					      _Out_    LPVOID       *ppv);


static struct {
  SIZE_T nHookId;
  lpfnCoGetClassObject fnCoGetClassObject;
} sCoGetClassObject_Hook = { 0, NULL };

static void
hookCoCreateInstance(void)
{
	HINSTANCE hOle32Dll;
	LPVOID fnOrigCoCreateInstance;
	DWORD dwOsErr;

	hOle32Dll = NktHookLibHelpers::GetModuleBaseAddress(L"ole32.dll");
	if (hOle32Dll == NULL)
	{
		::MessageBoxW(NULL, L"Cannot get handle of ole32.dll", L"TestDll", MB_ICONERROR|MB_OK);
		return;
	}

	// fnOrigCoCreateInstance = NktHookLibHelpers::GetProcedureAddress(hOle32Dll, "CoCreateInstance");
	fnOrigCoCreateInstance = ::GetProcAddress(hOle32Dll, "CoCreateInstance");
	if (fnOrigCoCreateInstance == NULL)
	{
		::MessageBoxW(NULL, L"Cannot get address of CoCreateInstance", L"TestDll", MB_ICONERROR|MB_OK);
		return;
	}

	dwOsErr = cHookMgr.Hook(&(sCoCreateInstance_Hook.nHookId),
				(LPVOID *)&(sCoCreateInstance_Hook.fnCoCreateInstance),
				fnOrigCoCreateInstance,
				Hooked_CoCreateInstance,
				NKTHOOKLIB_DisallowReentrancy);

	LPVOID fnOrigCoCreateInstanceEx;
	// fnOrigCoCreateInstanceEx = NktHookLibHelpers::GetProcedureAddress(hOle32Dll, "CoCreateInstanceEx");
	fnOrigCoCreateInstanceEx = ::GetProcAddress(hOle32Dll, "CoCreateInstanceEx");
	if (fnOrigCoCreateInstanceEx == NULL)
	{
		::MessageBoxW(NULL, L"Cannot get address of CoCreateInstanceEx", L"TestDll", MB_ICONERROR|MB_OK);
		return;
	}

	dwOsErr = cHookMgr.Hook(&(sCoCreateInstanceEx_Hook.nHookId),
				(LPVOID *)&(sCoCreateInstanceEx_Hook.fnCoCreateInstanceEx),
				fnOrigCoCreateInstanceEx,
				Hooked_CoCreateInstanceEx,
				NKTHOOKLIB_DisallowReentrancy);

	LPVOID fnOrigCoGetClassObject;
	// fnOrigCoGetClassObject = NktHookLibHelpers::GetProcedureAddress(hOle32Dll, "CoGetClassObject");
	fnOrigCoGetClassObject = ::GetProcAddress(hOle32Dll, "CoGetClassObject");
	if (fnOrigCoGetClassObject == NULL)
	{
		::MessageBoxW(NULL, L"Cannot get address of CoGetClassObject", L"TestDll", MB_ICONERROR|MB_OK);
		return;
	}

	dwOsErr = cHookMgr.Hook(&(sCoGetClassObject_Hook.nHookId),
				(LPVOID *)&(sCoGetClassObject_Hook.fnCoGetClassObject),
				fnOrigCoGetClassObject,
				Hooked_CoGetClassObject,
				NKTHOOKLIB_DisallowReentrancy);
}

static HRESULT WINAPI Hooked_CoCreateInstance(_In_  REFCLSID  rclsid,
					      _In_  LPUNKNOWN pUnkOuter,
					      _In_  DWORD     dwClsContext,
					      _In_  REFIID    riid,
					      _Out_ LPVOID    *ppv)
{
  LPOLESTR szRclsIDAsString;
  HRESULT hr;

  CLSID aExcel;
  hr = ::CLSIDFromProgID(L"Excel.Application", &aExcel);

  const bool bIsExcel = !FAILED(hr) && memcmp(&rclsid, &aExcel, sizeof(aExcel)) == 0;

  wchar_t message[100];
  hr = ::StringFromCLSID(rclsid, &szRclsIDAsString);
  if (!FAILED(hr))
  {
    LPOLESTR szRclsIDAsProgID;
    hr = ::ProgIDFromCLSID(rclsid, &szRclsIDAsProgID);
    NktHookLibHelpers::swprintf_s(message, sizeof(message)/sizeof(message[0]), 
				  L"CoCreateInstance(%s) (%s)%s", 
				  szRclsIDAsString,
				  (!FAILED(hr) ? szRclsIDAsProgID : L"unknown"),
				  (bIsExcel ? L" (Is Excel!)" : L""));
    CoTaskMemFree(szRclsIDAsString);
    if (!FAILED(hr))
      CoTaskMemFree(szRclsIDAsProgID);
  }
  else
  {
    NktHookLibHelpers::swprintf_s(message, sizeof(message)/sizeof(message[0]), 
				  L"CoCreateInstance on bogus CLSID?%s", 
				  (bIsExcel ? L" (Is Excel!)" : L""));
  }
  ::MessageBoxW(NULL, message, L"TestDll", MB_OK);
  
  HRESULT result = sCoCreateInstance_Hook.fnCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
  if (!bIsExcel)
    return result;

  return result;
}

static HRESULT WINAPI Hooked_CoCreateInstanceEx(_In_     REFCLSID     rclsid,
						_In_     IUnknown     *pUnkOuter,
						_In_     DWORD        dwClsContext,
						_In_     COSERVERINFO *pServerInfo,
						_In_     DWORD        dwCount,
						_Inout_  MULTI_QI     *pResults)
{
  LPOLESTR szRclsIDAsString;
  HRESULT hr;

  CLSID aExcel;
  hr = ::CLSIDFromProgID(L"Excel.Application", &aExcel);

  const bool bIsExcel = !FAILED(hr) && memcmp(&rclsid, &aExcel, sizeof(aExcel)) == 0;

  wchar_t message[100];
  hr = ::StringFromCLSID(rclsid, &szRclsIDAsString);
  if (!FAILED(hr))
  {
    LPOLESTR szRclsIDAsProgID;
    hr = ::ProgIDFromCLSID(rclsid, &szRclsIDAsProgID);
    NktHookLibHelpers::swprintf_s(message, sizeof(message)/sizeof(message[0]), 
				  L"CoCreateInstanceEx(%s) (%s)%s", 
				  szRclsIDAsString,
				  (!FAILED(hr) ? szRclsIDAsProgID : L"unknown"),
				  (bIsExcel ? L" (Is Excel!)" : L""));
    CoTaskMemFree(szRclsIDAsString);
    if (!FAILED(hr))
      CoTaskMemFree(szRclsIDAsProgID);
  }
  else
  {
    NktHookLibHelpers::swprintf_s(message, sizeof(message)/sizeof(message[0]), 
				  L"CoCreateInstanceEx on bogus CLSID?%s", 
				  (bIsExcel ? L" (Is Excel!)" : L""));
  }
  ::MessageBoxW(NULL, message, L"TestDll", MB_OK);

  HRESULT result = sCoCreateInstanceEx_Hook.fnCoCreateInstanceEx(rclsid, pUnkOuter, dwClsContext, pServerInfo, dwCount, pResults);
  if (!bIsExcel)
    return result;

  return result;
}

static HRESULT WINAPI Hooked_CoGetClassObject(_In_     REFCLSID     rclsid,
					      _In_     DWORD        dwClsContext,
					      _In_opt_ COSERVERINFO *pServerInfo,
					      _In_     REFIID       riid,
					      _Out_    LPVOID       *ppv)
{
  LPOLESTR szRclsIDAsString;
  HRESULT hr;

  CLSID aExcel;
  hr = ::CLSIDFromProgID(L"Excel.Application", &aExcel);

  const bool bIsExcel = !FAILED(hr) && memcmp(&rclsid, &aExcel, sizeof(aExcel)) == 0;

  wchar_t message[100];
  hr = ::StringFromCLSID(rclsid, &szRclsIDAsString);
  if (!FAILED(hr))
  {
    LPOLESTR szRclsIDAsProgID;
    hr = ::ProgIDFromCLSID(rclsid, &szRclsIDAsProgID);
    NktHookLibHelpers::swprintf_s(message, sizeof(message)/sizeof(message[0]), 
				  L"CoGetClassObject(%s) (%s)%s", 
				  szRclsIDAsString,
				  (!FAILED(hr) ? szRclsIDAsProgID : L"unknown"),
				  (bIsExcel ? L" (Is Excel!)" : L""));
    CoTaskMemFree(szRclsIDAsString);
    if (!FAILED(hr))
      CoTaskMemFree(szRclsIDAsProgID);
  }
  else
  {
    NktHookLibHelpers::swprintf_s(message, sizeof(message)/sizeof(message[0]), 
				  L"CoGetClassObject on bogus CLSID?%s", 
				  (bIsExcel ? L" (Is Excel!)" : L""));
  }
  ::MessageBoxW(NULL, message, L"TestDll", MB_OK);

  HRESULT result =  sCoGetClassObject_Hook.fnCoGetClassObject(rclsid, dwClsContext, pServerInfo, riid, ppv);

  return result;
}

extern "C" BOOL APIENTRY DllMain(__in HMODULE hModule, __in DWORD ulReasonForCall, __in LPVOID lpReserved)
{
  switch (ulReasonForCall)
  {
    case DLL_PROCESS_ATTACH:
      hookCoCreateInstance();
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
