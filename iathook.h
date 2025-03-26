// iathook.h

/*
 * iathook v1.03
 * https://github.com/anzz1/iathook
 */

#ifndef __IATHOOK_H
#define __IATHOOK_H

#include <windows.h>

#if !defined(__forceinline) && ( defined(__GNUC__) || defined(__MINGW__) || defined (__clang__) )
#define __forceinline inline __attribute__((always_inline))
#endif

__forceinline static int __strcmp(const char* s1, const char* s2) {
  while (*s1 == *s2) { 
    if (*s1 == 0) return 0;
    s1++; s2++;
  }
  return (*s1 > *s2) ? 1 : -1;
}

__forceinline static int __stricmp(const char* s1, const char* s2) {
  char c1, c2;
  do {
    if (*s1 == 0 && *s2 == 0) return 0;
    c1 = (*s1>64 && *s1<91) ? (*s1+32):*s1; // A-Z -> a-z
    c2 = (*s2>64 && *s2<91) ? (*s2+32):*s2; // A-Z -> a-z
    s1++; s2++;
  } while (c1 == c2);
  return (*s1 > *s2) ? 1 : -1;
}

#ifdef __cplusplus
namespace Iat_hook
{
#endif // __cplusplus
  void** find_iat_func(HMODULE hModule, const char* szFuncName, const char* szModName, const DWORD dwOrdinal) {
    PIMAGE_DOS_HEADER img_dos_headers;
    PIMAGE_NT_HEADERS img_nt_headers;
    PIMAGE_DATA_DIRECTORY img_dir_imports;
    PIMAGE_IMPORT_DESCRIPTOR img_imports_desc;
    PIMAGE_IMPORT_DESCRIPTOR iid;
    size_t img_imports_desc_end;

    if (!hModule)
      hModule = GetModuleHandleA(0);

    img_dos_headers = (PIMAGE_DOS_HEADER)hModule;
    if (img_dos_headers->e_magic != IMAGE_DOS_SIGNATURE)
      return 0;
    img_nt_headers = (PIMAGE_NT_HEADERS)((size_t)img_dos_headers + img_dos_headers->e_lfanew);
    if (img_nt_headers->Signature != IMAGE_NT_SIGNATURE)
      return 0;
    if (img_nt_headers->FileHeader.SizeOfOptionalHeader < 96) // OptionalHeader.NumberOfRvaAndSizes
      return 0;
    if (img_nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC || img_nt_headers->OptionalHeader.NumberOfRvaAndSizes < 2)
      return 0;

    img_dir_imports = (PIMAGE_DATA_DIRECTORY)(&(img_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]));
    img_imports_desc = (PIMAGE_IMPORT_DESCRIPTOR)((size_t)img_dos_headers + img_dir_imports->VirtualAddress);
    img_imports_desc_end = (size_t)(img_imports_desc + img_dir_imports->Size);

    for (iid = img_imports_desc; (size_t)iid < img_imports_desc_end && iid->Name != 0 && iid->FirstThunk != 0; iid++) {
      size_t func_idx;
      char* mod_name = (char*)((size_t*)(iid->Name + (size_t)hModule));
      if (szModName != 0 && *szModName != 0) {
        if (__stricmp(szModName, mod_name))
          continue;
      }
      for (func_idx = 0; *(func_idx + (void**)(iid->FirstThunk + (size_t)hModule)) != 0; func_idx++) {
        if (iid->OriginalFirstThunk) {
          size_t func_oft = (size_t)(*(func_idx + (size_t*)(iid->OriginalFirstThunk + (size_t)hModule)));
          if (IMAGE_SNAP_BY_ORDINAL(func_oft)) {
            if (szModName != 0 && *szModName != 0 && dwOrdinal != 0 && (dwOrdinal == IMAGE_ORDINAL(func_oft)))
              return func_idx + (void**)(iid->FirstThunk + (size_t)hModule);
          } else if (szFuncName != 0 && *szFuncName != 0) {
            char* func_name = (char*)(func_oft + (size_t)hModule + 2);
            if (!__strcmp(szFuncName, func_name))
              return func_idx + (void**)(iid->FirstThunk + (size_t)hModule);
          }
        } else {
          HMODULE mod_handle = GetModuleHandleA(mod_name);
          if (mod_handle) {
            void* func_ptr = 0;
            if (szFuncName != 0 && *szFuncName != 0) {
              func_ptr = GetProcAddress(mod_handle, szFuncName);
              if (func_ptr && func_ptr == *(func_idx + (void**)(iid->FirstThunk + (size_t)hModule)))
                return func_idx + (void**)(iid->FirstThunk + (size_t)hModule);
            }
            if (szModName != 0 && *szModName != 0 && dwOrdinal != 0) {
              func_ptr = GetProcAddress(mod_handle, MAKEINTRESOURCEA(dwOrdinal));
              if (func_ptr && func_ptr == *(func_idx + (void**)(iid->FirstThunk + (size_t)hModule)))
                return func_idx + (void**)(iid->FirstThunk + (size_t)hModule);
            }
          }
        }
      }
    }
    return 0;
  }

  void* detour_iat_func(HMODULE hModule, const char* szFuncName, void* pNewFunction, const char* szModName, const DWORD dwOrdinal, BOOL pin) {
    void* pOrigFunction;
    DWORD old_rights, new_rights = PAGE_READWRITE;
    void** func_ptr = find_iat_func(hModule, szFuncName, szModName, dwOrdinal);
    if (!func_ptr || *func_ptr == 0 || *func_ptr == pNewFunction)
      return 0;

    if (!VirtualProtect(func_ptr, sizeof(void*), new_rights, &old_rights))
      return 0;

    pOrigFunction = *func_ptr;
    *func_ptr = pNewFunction;

    VirtualProtect(func_ptr, sizeof(void*), old_rights, &new_rights);

    if (pin) {
      HMODULE hm;
      GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, (LPCSTR)pOrigFunction, &hm);
    }

    return pOrigFunction;
  }
#ifdef __cplusplus
};
#endif // __cplusplus
#endif // __IATHOOK_H

