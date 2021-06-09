#include "stdafx.h"

INT main(INT argc, LPCSTR* argv, const wchar_t* pArgv[]) {
	if (argc < 2) {
		printf("* Usage: %ws [Shellcode file path] txf [Hollow the DLL via a TxF handle (optional)]\r\n", pArgv[0]);
	}
	else {
		bool bTxF = false;

		if (argc >= 3 && _wcsicmp(pArgv[2], L"txf") == 0) {
			bTxF = true;
		}

		if (argc < 4) {
			printf("usage: hollowmap <PROCESS> <TARGETMODULE> <DLL>\n");
			return 1;
		}

		if (!Comm::Setup()) {
			return 1;
		}

		Comm::Process process(StrToWStr(argv[1]));
		if (!process.Valid()) {
			errorf("process not found\n");
			return 1;
		}

		auto entry = Map::ExtendMap(process, StrToWStr(argv[3]), StrToWStr(argv[2]));
		if (!entry) {
			return 1;
		}

		printf("\n[-] entry point: %p\n", entry);

		if (!Hijack::HijackViaHook(process, entry, L"user32.dll", "PeekMessageW")) {
			return 1;
		}

		return 0;
	}
}