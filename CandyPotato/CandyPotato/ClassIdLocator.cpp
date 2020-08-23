#include "ClassIdLocator.h"
#include <algorithm>
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <cctype>

using namespace std;

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

const BOOL DEBUG = FALSE;

Filter::Filter() {
    this->reg_dword = std::pair<LPCWSTR, DWORD>();
    this->reg_sz = std::pair<LPCWSTR, LPCWSTR>();
};
void Filter::SetREG_SZ(LPCWSTR k, LPCWSTR v) {
    this->reg_sz.first = k;
    this->reg_sz.second = v;
}
void Filter::SetREG_DWORD(LPCWSTR k, DWORD v) {
    this->reg_dword.first = k;
    this->reg_dword.second = v;
}
std::pair<LPCWSTR, DWORD> Filter::GetDWORD() {
    return this->reg_dword;
};
std::pair<LPCWSTR, LPCWSTR> Filter::GetREG_SZ() {
    return this->reg_sz;
};

ClassIdLocator::ClassIdLocator() {
    // Manual Start
    this->setStartType(0x3);
}

void ClassIdLocator::setStartType(DWORD startType) {
    this->startType = startType;
}

DWORD ClassIdLocator::getStartType() {
    return this->startType;
}

void Destroy() {}

std::vector<hotpot> ClassIdLocator::CollectAllCLSIDs() {

    std::vector<hotpot> hotpots = std::vector<hotpot>();

    std::vector<std::pair<std::wstring, std::wstring>> cls2appidList = ListCLSIDsWithAppID();

    if (cls2appidList.empty()) {
        printf("%s\n", "[-] Error: No suitable CLSID found");
    }

    std::vector<std::pair<std::wstring, std::wstring>> app2svcList = ListAPPIDsWithServiceName();

    if (app2svcList.empty()) {
        printf("%s\n", "[-] Error: No suitable AppID found");
    }

    std::vector<std::pair<std::wstring, std::wstring>> svc2acc = ListServiceWithAccountAndAutoStart();

    if (svc2acc.empty()) {
        printf("%s\n", "[-] Error: No suitable Service found");
    }
    bool found;
    for (unsigned int i = 0; i < cls2appidList.size(); i++) {
        found = FALSE;
        for (unsigned int j = 0; j < app2svcList.size(); j++) {
            for (unsigned int k = 0; k < svc2acc.size(); k++) {
                if (svc2acc.at(k).first == app2svcList.at(j).second && cls2appidList.at(i).second == app2svcList.at(j).first) {
                    hotpot h = hotpot();
                    h.clsid = cls2appidList.at(i).first;
                    h.appid = app2svcList.at(j).first;
                    h.service = app2svcList.at(j).second;
                    h.account = svc2acc.at(k).second;
                    hotpots.push_back(h);
                    if (DEBUG) {
                        _tprintf(TEXT("(%d) %s:%s:%s:%s\n"), i + 1, cls2appidList.at(i).first.c_str(), app2svcList.at(j).first.c_str(), app2svcList.at(j).second.c_str(), svc2acc.at(k).second.c_str());
                    }
                    found = TRUE;
                    break;
                }
                if (found) {
                    break;
                }
            }
        }
    }

    return hotpots;
}

std::vector<std::pair<std::wstring, std::wstring>> ClassIdLocator::FilterKeyWithValue(HKEY hKey, LPCWSTR filterValue, LPCWSTR filterData) {
    std::vector<std::pair<std::wstring, std::wstring>> keyNames = std::vector<std::pair<std::wstring, std::wstring>>(); // vector for subkeys

    TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
    DWORD    cbName;                   // size of name string 
    TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
    DWORD    cchClassName = MAX_PATH;  // size of class string 
    DWORD    cSubKeys = 0;               // number of subkeys 
    DWORD    cbMaxSubKey;              // longest subkey size 
    DWORD    cchMaxClass;              // longest class string 
    DWORD    cValues;              // number of values for key 
    DWORD    cchMaxValue;          // longest value name 
    DWORD    cbMaxValueData;       // longest value data 
    DWORD    cbSecurityDescriptor; // size of security descriptor 
    FILETIME ftLastWriteTime;      // last write time 

    DWORD i, retCode;

    TCHAR  achValue[MAX_VALUE_NAME];
    DWORD cchValue = MAX_VALUE_NAME;

    // Get the class name and the value count. 
    retCode = RegQueryInfoKey(
        hKey,                    // key handle 
        achClass,                // buffer for class name 
        &cchClassName,           // size of class string 
        NULL,                    // reserved 
        &cSubKeys,               // number of subkeys 
        &cbMaxSubKey,            // longest subkey size 
        &cchMaxClass,            // longest class string 
        &cValues,                // number of values for this key 
        &cchMaxValue,            // longest value name 
        &cbMaxValueData,         // longest value data 
        &cbSecurityDescriptor,   // security descriptor 
        &ftLastWriteTime);       // last write time 
    if (cSubKeys)
    {
        //printf("\nNumber of subkeys: %d\n", cSubKeys);

        for (i = 0; i < cSubKeys; i++)
        {
            std::pair<std::wstring, std::wstring> key2value = std::pair<std::wstring, std::wstring>();
            cbName = MAX_KEY_LENGTH;
            retCode = RegEnumKeyEx(hKey, i,
                achKey,
                &cbName,
                NULL,
                NULL,
                NULL,
                &ftLastWriteTime);
            if (retCode == ERROR_SUCCESS)
            {

                wchar_t keyValueData[255];
                DWORD BufferSize = sizeof(keyValueData);
                LONG retCode2 = RegGetValue(hKey, achKey, filterValue, RRF_RT_REG_SZ, NULL, keyValueData, &BufferSize);
                if (retCode2 == ERROR_SUCCESS)
                {
                    if (filterData == NULL || wstring(keyValueData) == filterData) {
                        key2value.first = achKey;
                        key2value.second = keyValueData;
                        keyNames.push_back(key2value);
                    }
                }
            }
        }
    }
    return keyNames;
}

std::vector<std::pair<std::wstring, std::wstring>> ClassIdLocator::FilterKeysWithValues(HKEY hKey, Filter filter) {
    std::vector<std::pair<std::wstring, std::wstring>> keyNames = std::vector<std::pair<std::wstring, std::wstring>>(); // vector for subkeys

    TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
    DWORD    cbName;                   // size of name string 
    TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
    DWORD    cchClassName = MAX_PATH;  // size of class string 
    DWORD    cSubKeys = 0;               // number of subkeys 
    DWORD    cbMaxSubKey;              // longest subkey size 
    DWORD    cchMaxClass;              // longest class string 
    DWORD    cValues;              // number of values for key 
    DWORD    cchMaxValue;          // longest value name 
    DWORD    cbMaxValueData;       // longest value data 
    DWORD    cbSecurityDescriptor; // size of security descriptor 
    FILETIME ftLastWriteTime;      // last write time 

    DWORD i, retCode;

    TCHAR  achValue[MAX_VALUE_NAME];
    DWORD cchValue = MAX_VALUE_NAME;

    // Get the class name and the value count. 
    retCode = RegQueryInfoKey(
        hKey,                    // key handle 
        achClass,                // buffer for class name 
        &cchClassName,           // size of class string 
        NULL,                    // reserved 
        &cSubKeys,               // number of subkeys 
        &cbMaxSubKey,            // longest subkey size 
        &cchMaxClass,            // longest class string 
        &cValues,                // number of values for this key 
        &cchMaxValue,            // longest value name 
        &cbMaxValueData,         // longest value data 
        &cbSecurityDescriptor,   // security descriptor 
        &ftLastWriteTime);       // last write time 
    if (cSubKeys)
    {
        //printf("\nNumber of subkeys: %d\n", cSubKeys);

        for (i = 0; i < cSubKeys; i++)
        {
            std::pair<std::wstring, std::wstring> key2value = std::pair<std::wstring, std::wstring>();
            cbName = MAX_KEY_LENGTH;
            retCode = RegEnumKeyEx(hKey, i,
                achKey,
                &cbName,
                NULL,
                NULL,
                NULL,
                &ftLastWriteTime);
            if (retCode == ERROR_SUCCESS)
            {

                wchar_t REG_SZ_ValueData[255];
                DWORD REG_DWORD_ValueData{};
                DWORD BufferSize = sizeof(REG_SZ_ValueData);
                
                LONG reg_sz_retCode = RegGetValue(hKey, achKey, filter.GetREG_SZ().first, RRF_RT_REG_SZ, NULL, REG_SZ_ValueData, &BufferSize);
                LONG reg_dword_retCode = RegGetValue(hKey, achKey, filter.GetDWORD().first, RRF_RT_REG_DWORD, NULL, &REG_DWORD_ValueData, &BufferSize);

                if (reg_sz_retCode == ERROR_SUCCESS && reg_dword_retCode == ERROR_SUCCESS)
                {
                    if (filter.GetREG_SZ().second == NULL || Utils::case_insensitive_match(wstring(REG_SZ_ValueData),filter.GetREG_SZ().second)) {
                        if (filter.GetDWORD().second != NULL && REG_DWORD_ValueData == filter.GetDWORD().second){
                            if(DEBUG)
                                _tprintf(TEXT("%s: %d\n"), wstring(achKey).c_str(), REG_DWORD_ValueData);
                            key2value.first = achKey;
                            key2value.second = REG_SZ_ValueData;
                            keyNames.push_back(key2value);
                        }
                    }
                }
            }
        }
    }
    return keyNames;
}

std::vector<std::pair<std::wstring, std::wstring>> ClassIdLocator::ListCLSIDsWithAppID() {
    std::vector<std::pair<std::wstring, std::wstring>>  res = std::vector<std::pair<std::wstring, std::wstring>>();
    HKEY hTestKey;

    TCHAR    achKey[MAX_KEY_LENGTH];
    DWORD    cSubKeys = 0;

    if (RegOpenKeyEx(HKEY_CLASSES_ROOT,
        TEXT("CLSID\\"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {
        res = FilterKeyWithValue(hTestKey, L"AppID", NULL);
    }
    return res;
}

std::vector<std::pair<std::wstring, std::wstring>> ClassIdLocator::ListAPPIDsWithServiceName() {
    std::vector<std::pair<std::wstring, std::wstring>>  res = std::vector<std::pair<std::wstring, std::wstring>>();
    HKEY hTestKey;

    TCHAR    achKey[MAX_KEY_LENGTH];
    DWORD    cSubKeys = 0;

    if (RegOpenKeyEx(HKEY_CLASSES_ROOT,
        TEXT("APPID\\"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {
        res = FilterKeyWithValue(hTestKey, L"LocalService", NULL);//L"LocalSystem");
    }
    return res;
}


std::vector<std::pair<std::wstring, std::wstring>> ClassIdLocator::ListServiceWithAccount() {
    std::vector<std::pair<std::wstring, std::wstring>>  res = std::vector<std::pair<std::wstring, std::wstring>>();
    HKEY hTestKey;

    TCHAR    achKey[MAX_KEY_LENGTH];
    DWORD    cSubKeys = 0;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SYSTEM\\CurrentControlSet\\Services\\"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {
        res = FilterKeyWithValue(hTestKey, L"ObjectName", L"LocalSystem");
    }
    return res;
}

std::vector<std::pair<std::wstring, std::wstring>> ClassIdLocator::ListServiceWithAccountAndAutoStart() {
    std::vector<std::pair<std::wstring, std::wstring>>  res = std::vector<std::pair<std::wstring, std::wstring>>();
    Filter filter = Filter();
    filter.SetREG_DWORD(L"Start", this->getStartType());
    filter.SetREG_SZ(L"ObjectName", L"LocalSystem");

    HKEY hTestKey;

    TCHAR    achKey[MAX_KEY_LENGTH];
    DWORD    cSubKeys = 0;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        TEXT("SYSTEM\\CurrentControlSet\\Services\\"),
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
        )
    {
        res = FilterKeysWithValues(hTestKey, filter);
    }
    return res;
}
/*
int __cdecl _tmain()
{
    ClassIdLocator c = ClassIdLocator();
    c.CollectAllCLSIDs();
}
*/