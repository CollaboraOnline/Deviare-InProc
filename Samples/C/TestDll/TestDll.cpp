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

#define ARRAYLEN(a) (sizeof(a)/sizeof(*a))

static CNktHookLib cHookMgr;

static void Print(char *string)
{
  HANDLE stdOut = GetStdHandle(STD_OUTPUT_HANDLE);
  if (stdOut != NULL && stdOut != INVALID_HANDLE_VALUE)
  {
    DWORD written;
    ::WriteFile(stdOut, string, ::lstrlenA(string), &written, NULL);
  }
}

static void Print(wchar_t *string)
{
  int buflen = 4 * ::lstrlenW(string);
  char *buffer = new char[buflen];
  buflen = ::WideCharToMultiByte(CP_UTF8, 0, string, ::lstrlenW(string), buffer, buflen, NULL, NULL);
  HANDLE stdOut = GetStdHandle(STD_OUTPUT_HANDLE);
  if (stdOut != NULL && stdOut != INVALID_HANDLE_VALUE)
  {
    DWORD written;
    ::WriteFile(stdOut, buffer, buflen, &written, NULL);
  }
  delete[] buffer;
}

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
DumpCoCreateStyleCall(wchar_t *api, REFCLSID rclsid)
{
  LPOLESTR szRclsIDAsString;
  HRESULT hr;

  wchar_t message[100];
  hr = ::StringFromCLSID(rclsid, &szRclsIDAsString);
  if (!FAILED(hr))
  {
    LPOLESTR szRclsIDAsProgID;
    hr = ::ProgIDFromCLSID(rclsid, &szRclsIDAsProgID);
    NktHookLibHelpers::swprintf_s(message, ARRAYLEN(message),
				  L"%s(%s) (%s)\n",
				  api,
				  szRclsIDAsString,
				  (!FAILED(hr) ? szRclsIDAsProgID : L"unknown"));
    CoTaskMemFree(szRclsIDAsString);
    if (!FAILED(hr))
      CoTaskMemFree(szRclsIDAsProgID);
  }
  else
  {
    NktHookLibHelpers::swprintf_s(message, ARRAYLEN(message),
				  L"%s on bogus CLSID?\n",
				  api);
  }
  Print(message);
}

// From <oaidl.h>: The C style interface for IDispatch:

typedef struct
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(
	__RPC__in IDispatch * This,
	/* [in] */ __RPC__in REFIID riid,
	/* [annotation][iid_is][out] */
	_COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(
	__RPC__in IDispatch * This);

    ULONG ( STDMETHODCALLTYPE *Release )(
	__RPC__in IDispatch * This);

    HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )(
	__RPC__in IDispatch * This,
	/* [out] */ __RPC__out UINT *pctinfo);

    HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )(
	__RPC__in IDispatch * This,
	/* [in] */ UINT iTInfo,
	/* [in] */ LCID lcid,
	/* [out] */ __RPC__deref_out_opt ITypeInfo **ppTInfo);

    HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )(
	__RPC__in IDispatch * This,
	/* [in] */ __RPC__in REFIID riid,
	/* [size_is][in] */ __RPC__in_ecount_full(cNames) LPOLESTR *rgszNames,
	/* [range][in] */ __RPC__in_range(0,16384) UINT cNames,
	/* [in] */ LCID lcid,
	/* [size_is][out] */ __RPC__out_ecount_full(cNames) DISPID *rgDispId);

    /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )(
	IDispatch * This,
	/* [annotation][in] */
	_In_  DISPID dispIdMember,
	/* [annotation][in] */
	_In_  REFIID riid,
	/* [annotation][in] */
	_In_  LCID lcid,
	/* [annotation][in] */
	_In_  WORD wFlags,
	/* [annotation][out][in] */
	_In_  DISPPARAMS *pDispParams,
	/* [annotation][out] */
	_Out_opt_  VARIANT *pVarResult,
	/* [annotation][out] */
	_Out_opt_  EXCEPINFO *pExcepInfo,
	/* [annotation][out] */
	_Out_opt_  UINT *puArgErr);

    END_INTERFACE
} IDispatchVtbl;

typedef HRESULT (WINAPI *lpfnInvoke)(IDispatch *This,
				     _In_  DISPID dispIdMember,
				     _In_  REFIID riid,
				     _In_  LCID lcid,
				     _In_  WORD wFlags,
				     _In_  DISPPARAMS *pDispParams,
				     _Out_opt_  VARIANT *pVarResult,
				     _Out_opt_  EXCEPINFO *pExcepInfo,
				     _Out_opt_  UINT *puArgErr);

static struct {
  SIZE_T nHookId;
  lpfnInvoke fnInvoke;
} sInvoke_Hook = { 0, NULL };

static HRESULT WINAPI Hooked_Invoke(IDispatch *This,
				    _In_  DISPID dispIdMember,
				    _In_  REFIID riid,
				    _In_  LCID lcid,
				    _In_  WORD wFlags,
				    _In_  DISPPARAMS *pDispParams,
				    _Out_opt_  VARIANT *pVarResult,
				    _Out_opt_  EXCEPINFO *pExcepInfo,
				    _Out_opt_  UINT *puArgErr)
{
  char message[100];
  NktHookLibHelpers::sprintf_s(message, ARRAYLEN(message),
			       "Hooked_Invoke This=%x\n",
			       This);
  Print(message);

  HRESULT result = sInvoke_Hook.fnInvoke(This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr);

  return result;
}

static void
DoIDispatchMagic(IDispatch *pdisp)
{
  ITypeInfo *pTInfo;

  HRESULT hr = pdisp->GetTypeInfo(0, MAKELCID(MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), SORT_DEFAULT), &pTInfo);
  if (FAILED(hr))
  {
    Print("GetTypeInfo failed\n");
    return;
  }

#if 0
  // Test: Dump out function members
  UINT index = 0;
  FUNCDESC *pFuncDesc;
  while (SUCCEEDED(pTInfo->GetFuncDesc(index++, &pFuncDesc)))
  {
    wchar_t message[100];

    BSTR name = SysAllocString(L"                                                       ");
    UINT numNames;
    if (!SUCCEEDED(pTInfo->GetNames(pFuncDesc->memid, &name, 1, &numNames)))
      Print("  GetNames failed\n");

    NktHookLibHelpers::swprintf_s(message, ARRAYLEN(message),
				  L"  Member %lx: %s kind: %d invoke: %d\n",
				  pFuncDesc->memid,
				  name,
				  pFuncDesc->funckind,
				  pFuncDesc->invkind);
    Print(message);

    pTInfo->ReleaseFuncDesc(pFuncDesc);
  }
#endif

  // Hook the Invoke
  LPVOID fnOrigInvoke = (*(IDispatchVtbl**)pdisp)->Invoke;
  DWORD dwOsErr = cHookMgr.Hook(&(sInvoke_Hook.nHookId),
				(LPVOID *) &(sInvoke_Hook.fnInvoke),
				fnOrigInvoke,
				Hooked_Invoke,
				0);
  char message[100];
  NktHookLibHelpers::sprintf_s(message, ARRAYLEN(message),
			       "Hooked IDIspatch of %x (old: %x)\n",
			       pdisp,
			       sInvoke_Hook.fnInvoke);
  Print(message);
}

static void
hookCoCreateInstance(void)
{
  ::MessageBoxW(NULL, L"Hey Ho", L"TestDll", MB_OK);

	HINSTANCE hOle32Dll;
	DWORD dwOsErr;

	hOle32Dll = NktHookLibHelpers::GetModuleBaseAddress(L"ole32.dll");
	if (hOle32Dll == NULL)
	{
		Print("Cannot get handle of ole32.dll\n");
		return;
	}

	LPVOID fnOrigCoCreateInstance = ::GetProcAddress(hOle32Dll, "CoCreateInstance");
	if (fnOrigCoCreateInstance == NULL)
	{
		Print("Cannot get address of CoCreateInstance\n");
		return;
	}

	dwOsErr = cHookMgr.Hook(&(sCoCreateInstance_Hook.nHookId),
				(LPVOID *)&(sCoCreateInstance_Hook.fnCoCreateInstance),
				fnOrigCoCreateInstance,
				Hooked_CoCreateInstance,
				NKTHOOKLIB_DisallowReentrancy);

	LPVOID fnOrigCoCreateInstanceEx = ::GetProcAddress(hOle32Dll, "CoCreateInstanceEx");
	if (fnOrigCoCreateInstanceEx == NULL)
	{
		Print("Cannot get address of CoCreateInstanceEx\n");
		return;
	}

	dwOsErr = cHookMgr.Hook(&(sCoCreateInstanceEx_Hook.nHookId),
				(LPVOID *)&(sCoCreateInstanceEx_Hook.fnCoCreateInstanceEx),
				fnOrigCoCreateInstanceEx,
				Hooked_CoCreateInstanceEx,
				NKTHOOKLIB_DisallowReentrancy);

	LPVOID fnOrigCoGetClassObject = ::GetProcAddress(hOle32Dll, "CoGetClassObject");
	if (fnOrigCoGetClassObject == NULL)
	{
		Print("Cannot get address of CoGetClassObject\n");
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
  DumpCoCreateStyleCall(L"CoCreateInstance", rclsid);

  HRESULT result = sCoCreateInstance_Hook.fnCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);

  if (SUCCEEDED(result))
  {
    char message[100];
    NktHookLibHelpers::sprintf_s(message, ARRAYLEN(message),
				 "  result:%x\n",
				 *ppv);
    Print(message);
  }
  else
    Print("  failed\n");

  return result;
}

static HRESULT WINAPI Hooked_CoCreateInstanceEx(_In_     REFCLSID     rclsid,
						_In_     IUnknown     *pUnkOuter,
						_In_     DWORD        dwClsContext,
						_In_     COSERVERINFO *pServerInfo,
						_In_     DWORD        dwCount,
						_Inout_  MULTI_QI     *pResults)
{
  DumpCoCreateStyleCall(L"CoCreateInstanceEx", rclsid);

  HRESULT result = sCoCreateInstanceEx_Hook.fnCoCreateInstanceEx(rclsid, pUnkOuter, dwClsContext, pServerInfo, dwCount, pResults);

  if (SUCCEEDED(result))
  {
    Print("  results:\n");
    for (int i = 0; i < dwCount; i++)
    {
      LPOLESTR szIidAsString;
      wchar_t message[100];
      HRESULT hr = ::StringFromIID(*pResults[i].pIID, &szIidAsString);
      NktHookLibHelpers::swprintf_s(message, ARRAYLEN(message),
				    L"    %s: %x%s\n",
				    szIidAsString,
				    pResults[i].pItf,
				    (FAILED(pResults[i].hr) ? L" (failed)" : L""));
      Print(message);
    }
  }
  else
    Print("  failed\n");

  return result;
}

static void
hookClassFactory(LPVOID pv)
{
  IClassFactory *pfactory = (IClassFactory *) pv;

  IDispatch *pdisp;
  HRESULT hr = pfactory->CreateInstance(NULL, IID_IDispatch, (LPVOID *) &pdisp);

  if (SUCCEEDED(hr))
  {
    char message[100];
    NktHookLibHelpers::sprintf_s(message, ARRAYLEN(message),
				 "  hookClassFactory: pdisp=%x\n",
				 pdisp);
    Print(message);
    DoIDispatchMagic(pdisp);
  }
}

static HRESULT WINAPI Hooked_CoGetClassObject(_In_     REFCLSID     rclsid,
					      _In_     DWORD        dwClsContext,
					      _In_opt_ COSERVERINFO *pServerInfo,
					      _In_     REFIID       riid,
					      _Out_    LPVOID       *ppv)
{
  DumpCoCreateStyleCall(L"CoGetClassObject", rclsid);

  LPOLESTR szRiidAsString;
  wchar_t message[100];
  HRESULT hr = ::StringFromIID(riid, &szRiidAsString);
  if (SUCCEEDED(hr))
  {
    NktHookLibHelpers::swprintf_s(message, ARRAYLEN(message),
				  L"  riid=%s\n",
				  szRiidAsString);
    CoTaskMemFree(szRiidAsString);
  }
  else
  {
    NktHookLibHelpers::swprintf_s(message, ARRAYLEN(message),
				  L"%s on bogus REFIID?\n");
  }
  Print(message);

  HRESULT result = sCoGetClassObject_Hook.fnCoGetClassObject(rclsid, dwClsContext, pServerInfo, riid, ppv);

  if (SUCCEEDED(result))
  {
    NktHookLibHelpers::swprintf_s(message, ARRAYLEN(message),
				  L"  result:%x\n",
				  *ppv);
    Print(message);
  }
  else
  {
    Print("  failed\n");
    return result;
  }

  if (IsEqualGUID(riid, IID_IClassFactory))
    hookClassFactory(*ppv);

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
