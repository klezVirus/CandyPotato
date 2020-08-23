#pragma once
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <algorithm>

struct hotpot {
	std::wstring clsid;
	std::wstring appid;
	std::wstring service;
	std::wstring account;
	DWORD start;
};

enum class REG_TYPE { DWORD, LPCWSTR };

struct rawfilter {
	LPCWSTR keyvalue;
	REG_TYPE keytype;

};

static class Utils {
public:
	static int case_insensitive_match(std::wstring s1, std::wstring s2) {
		//convert s1 and s2 into lower case strings
		transform(s1.begin(), s1.end(), s1.begin(), ::tolower);
		transform(s2.begin(), s2.end(), s2.begin(), ::tolower);
		if (s1.compare(s2) == 0)
			return 1; //The strings are same
		return 0; //not matched
	}
};

class Filter
{
private:
	std::pair<LPCWSTR, DWORD> reg_dword;
	std::pair<LPCWSTR, LPCWSTR> reg_sz;

public:
	Filter(void);
	void SetREG_SZ(LPCWSTR, LPCWSTR);
	void SetREG_DWORD(LPCWSTR, DWORD);
	std::pair<LPCWSTR, DWORD> GetDWORD();
	std::pair<LPCWSTR, LPCWSTR> GetREG_SZ();
};

class ClassIdLocator
{
private:
	DWORD startType;

public:
	ClassIdLocator();
	void setStartType(DWORD startType);
	DWORD getStartType();
	std::vector<hotpot> CollectAllCLSIDs(void);
	std::vector<std::pair<std::wstring, std::wstring>> ListCLSIDsWithAppID(void);
	std::vector<std::pair<std::wstring, std::wstring>> ListAPPIDsWithServiceName(void);
	std::vector<std::pair<std::wstring, std::wstring>> ListServiceWithAccount(void);
	std::vector<std::pair<std::wstring, std::wstring>> ListServiceWithAccountAndAutoStart(void);
	std::vector<std::pair<std::wstring, std::wstring>> FilterKeyWithValue(HKEY, LPCWSTR, LPCWSTR);
	std::vector<std::pair<std::wstring, std::wstring>> FilterKeysWithValues(HKEY, Filter);
	void Destroy(void);
};

