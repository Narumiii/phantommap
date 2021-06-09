#include "stdafx.h"

// CBA to make this cleaner
namespace Map {

	bool HollowDLL(uint8_t** ppMapBuf, uint64_t* pqwMapBufSize, const uint8_t* pCodeBuf, uint32_t dwReqBufSize, uint8_t** ppMappedCode, bool bTxF) {
		WIN32_FIND_DATAW Wfd = { 0 };
		wchar_t SearchFilePath[MAX_PATH] = { 0 };
		HANDLE hFind;
		bool bMapped = false;

		//
		// Locate a DLL in the architecture appropriate system folder which has a sufficient image size to hollow for allocation.
		//

		GetSystemDirectoryW(SearchFilePath, MAX_PATH);
		wcscat_s(SearchFilePath, MAX_PATH, L"\\*.dll");

		if ((hFind = FindFirstFileW(SearchFilePath, &Wfd)) != INVALID_HANDLE_VALUE) {
			do {
				if (GetModuleHandleW(Wfd.cFileName) == nullptr) {
					HANDLE hFile = INVALID_HANDLE_VALUE, hTransaction = INVALID_HANDLE_VALUE;
					wchar_t FilePath[MAX_PATH];
					NTSTATUS NtStatus;
					uint8_t* pFileBuf = nullptr;

					GetSystemDirectoryW(FilePath, MAX_PATH);
					wcscat_s(FilePath, MAX_PATH, L"\\");
					wcscat_s(FilePath, MAX_PATH, Wfd.cFileName);

					//
					// Read the DLL to memory and check its headers to identify its image size.
					//

					if (bTxF) {
						OBJECT_ATTRIBUTES ObjAttr = { sizeof(OBJECT_ATTRIBUTES) };

						NtStatus = NtCreateTransaction(&hTransaction,
							TRANSACTION_ALL_ACCESS,
							&ObjAttr,
							nullptr,
							nullptr,
							0,
							0,
							0,
							nullptr,
							nullptr);

						if (NT_SUCCESS(NtStatus)) {
							hFile = CreateFileTransactedW(FilePath,
								GENERIC_WRITE | GENERIC_READ,
								0,
								nullptr,
								OPEN_EXISTING,
								FILE_ATTRIBUTE_NORMAL,
								nullptr,
								hTransaction,
								nullptr,
								nullptr);
						}
						else {
							printf("- Failed to create transaction (error 0x%x)\r\n", NtStatus);
						}
					}
					else {
						hFile = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
					}

					if (hFile != INVALID_HANDLE_VALUE) {
						uint32_t dwFileSize = GetFileSize(hFile, nullptr);
						uint32_t dwBytesRead = 0;

						pFileBuf = new uint8_t[dwFileSize];

						if (ReadFile(hFile, pFileBuf, dwFileSize, (PDWORD)&dwBytesRead, nullptr)) {
							SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);

							IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pFileBuf;
							IMAGE_NT_HEADERS* pNtHdrs = (IMAGE_NT_HEADERS*)(pFileBuf + pDosHdr->e_lfanew);
							IMAGE_SECTION_HEADER* pSectHdrs = (IMAGE_SECTION_HEADER*)((uint8_t*)&pNtHdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));

							if (pNtHdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
								if (dwReqBufSize < pNtHdrs->OptionalHeader.SizeOfImage && (_stricmp((char*)pSectHdrs->Name, ".text") == 0 && dwReqBufSize < pSectHdrs->Misc.VirtualSize)) {
									//
									// Found a DLL with sufficient image size: map an image view of it for hollowing.
									//

									printf("* %ws - image size: %d - .text size: %d\r\n", Wfd.cFileName, pNtHdrs->OptionalHeader.SizeOfImage, pSectHdrs->Misc.VirtualSize);

									bool bTxF_Valid = false;
									uint32_t dwCodeRva = 0;

									if (bTxF) {
										//
										// For TxF, make the modifications to the file contents now prior to mapping.
										//

										uint32_t dwBytesWritten = 0;

										//
										// Wipe the data directories that conflict with the code section
										//

										for (uint32_t dwX = 0; dwX < pNtHdrs->OptionalHeader.NumberOfRvaAndSizes; dwX++) {
											if (pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress >= pSectHdrs->VirtualAddress && pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress < (pSectHdrs->VirtualAddress + pSectHdrs->Misc.VirtualSize)) {
												pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress = 0;
												pNtHdrs->OptionalHeader.DataDirectory[dwX].Size = 0;
											}
										}

										//
										// Find a range free of relocations large enough to accomodate the code.
										//

										bool bRangeFound = false;
										uint8_t* pRelocBuf = (uint8_t*)GetPAFromRVA(pFileBuf, pNtHdrs, pSectHdrs, pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

										if (pRelocBuf != nullptr) {
											for (dwCodeRva = 0; !bRangeFound && dwCodeRva < pSectHdrs->Misc.VirtualSize; dwCodeRva += dwReqBufSize) {
												if (!CheckRelocRange(pRelocBuf, pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size, pSectHdrs->VirtualAddress + dwCodeRva, pSectHdrs->VirtualAddress + dwCodeRva + dwReqBufSize)) {
													bRangeFound = true;
													break;
												}
											}

											if (bRangeFound) {
												printf("+ Found a blank region with code section to accomodate payload at 0x%08x\r\n", dwCodeRva);
											}
											else {
												printf("- Failed to identify a blank region large enough to accomodate payload\r\n");
											}

											memcpy(pFileBuf + pSectHdrs->PointerToRawData + dwCodeRva, pCodeBuf, dwReqBufSize);

											if (WriteFile(hFile, pFileBuf, dwFileSize, (PDWORD)&dwBytesWritten, nullptr)) {
												printf("+ Successfully modified TxF file content.\r\n");
												bTxF_Valid = true;
											}
										}
										else {
											printf("- No relocation directory present.\r\n");
										}
									}

									if (!bTxF || bTxF_Valid) {
										HANDLE hSection = nullptr;
										NtStatus = NtCreateSection(&hSection, SECTION_ALL_ACCESS, nullptr, nullptr, PAGE_READONLY, SEC_IMAGE, hFile);

										if (NT_SUCCESS(NtStatus)) {
											*pqwMapBufSize = 0; // The map view is an in and out parameter, if it isn't zero the map may have its size overwritten
											NtStatus = NtMapViewOfSection(hSection, GetCurrentProcess(), (void**)ppMapBuf, 0, 0, nullptr, (PSIZE_T)pqwMapBufSize, 1, 0, PAGE_READONLY); // AllocationType of MEM_COMMIT|MEM_RESERVE is not needed for SEC_IMAGE.

											if (NT_SUCCESS(NtStatus)) {
												if (*pqwMapBufSize >= pNtHdrs->OptionalHeader.SizeOfImage) { // Verify that the mapped size is of sufficient size. There are quirks to image mapping that can result in the image size not matching the mapped size.
													printf("* %ws - mapped size: %I64u\r\n", Wfd.cFileName, *pqwMapBufSize);
													*ppMappedCode = *ppMapBuf + pSectHdrs->VirtualAddress + dwCodeRva;

													if (!bTxF) {
														uint32_t dwOldProtect = 0;

														if (VirtualProtect(*ppMappedCode, dwReqBufSize, PAGE_READWRITE, (PDWORD)&dwOldProtect)) {
															memcpy(*ppMappedCode, pCodeBuf, dwReqBufSize);

															if (VirtualProtect(*ppMappedCode, dwReqBufSize, dwOldProtect, (PDWORD)&dwOldProtect)) {
																bMapped = true;
															}
														}
													}
													else {
														bMapped = true;
													}
												}
											}
											else {
												printf("- Failed to create mapping of section (error 0x%08x)", NtStatus);
											}
										}
										else {
											printf("- Failed to create section (error 0x%x)\r\n", NtStatus);
										}
									}
									else {
										printf("- TxF initialization failed.\r\n");
									}
								}
							}
						}

						if (pFileBuf != nullptr) {
							delete[] pFileBuf;
						}

						if (hFile != INVALID_HANDLE_VALUE) {
							CloseHandle(hFile);
						}

						if (hTransaction != INVALID_HANDLE_VALUE) {
							CloseHandle(hTransaction);
						}
					}
					else {
						printf("- Failed to open handle to %ws (error %d)\r\n", FilePath, GetLastError());
					}
				}
			} while (!bMapped && FindNextFileW(hFind, &Wfd));

			FindClose(hFind);
		}

		return bMapped;
	}

		PIMAGE_SECTION_HEADER TranslateRawSection(PIMAGE_NT_HEADERS nt, DWORD rva) {
			auto section = IMAGE_FIRST_SECTION(nt);
			for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
				if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
					return section;
				}
			}

			return NULL;
		}


		PVOID TranslateRaw(PBYTE base, PIMAGE_NT_HEADERS nt, DWORD rva) {
			auto section = TranslateRawSection(nt, rva);
			if (!section) {
				return NULL;
			}

			return base + section->PointerToRawData + (rva - section->VirtualAddress);
		}

		BOOLEAN ResolveImports(Comm::Process & process, PBYTE base, PIMAGE_NT_HEADERS nt) {
			auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			if (!rva) {
				return TRUE;
			}

			auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(TranslateRaw(base, nt, rva));
			if (!importDescriptor) {
				return TRUE;
			}

			for (; importDescriptor->FirstThunk; ++importDescriptor) {
				auto moduleName = reinterpret_cast<PCHAR>(TranslateRaw(base, nt, importDescriptor->Name));
				if (!moduleName) {
					break;
				}

				auto module = LoadLibraryA(moduleName);
				if (!module) {
					errorf("failed to load module: %s\n", moduleName);
					return FALSE;
				}

				PBYTE processModuleBase = NULL;
				DWORD processModuleSize = 0;
				if (process.Module(StrToWStr(moduleName), &processModuleBase, &processModuleSize) != ERROR_SUCCESS) {
					errorf("target process does not have %s loaded\n", moduleName);
					return FALSE;
				}

				for (auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(TranslateRaw(base, nt, importDescriptor->FirstThunk)); thunk->u1.AddressOfData; ++thunk) {
					auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(TranslateRaw(base, nt, static_cast<DWORD>(thunk->u1.AddressOfData)));
					thunk->u1.Function = reinterpret_cast<UINT_PTR>(processModuleBase + (reinterpret_cast<PBYTE>(GetProcAddress(module, importByName->Name)) - reinterpret_cast<PBYTE>(module)));
				}
			}

			return TRUE;
		}

		VOID ResolveRelocations(PBYTE base, PIMAGE_NT_HEADERS nt, PBYTE mapped) {
			auto& baseRelocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			if (!baseRelocDir.VirtualAddress) {
				return;
			}

			auto reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(TranslateRaw(base, nt, baseRelocDir.VirtualAddress));
			if (!reloc) {
				return;
			}

			for (auto currentSize = 0UL; currentSize < baseRelocDir.Size; ) {
				auto relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				auto relocData = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(reloc) + sizeof(IMAGE_BASE_RELOCATION));
				auto relocBase = reinterpret_cast<PBYTE>(TranslateRaw(base, nt, reloc->VirtualAddress));

				for (auto i = 0UL; i < relocCount; ++i, ++relocData) {
					auto data = *relocData;
					auto type = data >> 12;
					auto offset = data & 0xFFF;

					if (type == IMAGE_REL_BASED_DIR64) {
						*reinterpret_cast<PBYTE*>(relocBase + offset) += (mapped - reinterpret_cast<PBYTE>(nt->OptionalHeader.ImageBase));
					}
				}

				currentSize += reloc->SizeOfBlock;
				reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(relocData);
			}
		}

		BOOLEAN MapHeaders(Comm::Process & process, PBYTE base, PIMAGE_NT_HEADERS nt, PBYTE mapped) {
			return process.Write(mapped, base, sizeof(nt->Signature) + sizeof(nt->FileHeader) + nt->FileHeader.SizeOfOptionalHeader) == ERROR_SUCCESS;
		}

		BOOLEAN MapSections(Comm::Process & process, PBYTE base, PIMAGE_NT_HEADERS nt, PBYTE mapped) {
			auto section = IMAGE_FIRST_SECTION(nt);
			for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
				auto sectionSize = min(section->SizeOfRawData, section->Misc.VirtualSize);
				if (!sectionSize) {
					continue;
				}

				auto mappedSection = mapped + section->VirtualAddress;
				if (process.Write(mappedSection, base + section->PointerToRawData, sectionSize) != ERROR_SUCCESS) {
					errorf("failed to map section %s at %p (%x)\n", section->Name, mappedSection, sectionSize);
					return FALSE;
				}
			}

			return TRUE;
		}

		PBYTE ExtendModule(Comm::Process & process, PIMAGE_NT_HEADERS nt, LPCWSTR module) {
			PBYTE moduleBase = NULL;
			DWORD moduleSize = 0;

			printf("[-] extending %ws\n", module);

			auto status = process.Module(module, &moduleBase, &moduleSize);
			if (status != ERROR_SUCCESS || !moduleBase) {
				errorf("failed to find module %ws (%X)\n", module, status);
				return NULL;
			}

			status = process.Extend(module, nt->OptionalHeader.SizeOfImage);
			if (status != ERROR_SUCCESS) {
				errorf("module %ws does not having enough free trailing memory (%X)\n", module, status);
				return NULL;
			}

			printf("[+] extended %ws to %x\n", module, moduleSize + nt->OptionalHeader.SizeOfImage);
			return moduleBase + moduleSize;
		}

		PVOID ExtendMap(Comm::Process & process, PBYTE base, LPCWSTR module) {
			auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
			if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
				errorf("invalid DOS signature\n");
				return NULL;
			}

			auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
			if (nt->Signature != IMAGE_NT_SIGNATURE) {
				errorf("invalid NT signature\n");
				return NULL;
			}

			nt->Signature = dos->e_magic = 0;

			auto mapped = ExtendModule(process, nt, module);
			if (!mapped) {
				return NULL;
			}

			printf("[+] mapped base: %p\n", mapped);

			if (!ResolveImports(process, base, nt)) {
				return NULL;
			}

			ResolveRelocations(base, nt, mapped);

			if (!MapHeaders(process, base, nt, mapped)) {
				errorf("failed to map headers\n");
				return NULL;
			}

			if (!MapSections(process, base, nt, mapped)) {
				return NULL;
			}

			return mapped + nt->OptionalHeader.AddressOfEntryPoint;
		}

		PVOID ExtendMap(Comm::Process & process, LPCWSTR filePath, LPCWSTR module) {
			std::ifstream file(filePath, std::ios::ate | std::ios::binary);
			if (!file) {
				errorf("failed to open file: \"%ws\"\n", filePath);
				return NULL;
			}

			auto size = file.tellg();
			auto buffer = new BYTE[size];

			file.seekg(0, std::ios::beg);
			file.read(reinterpret_cast<PCHAR>(buffer), size);
			file.close();

			auto entryPoint = ExtendMap(process, buffer, module);

			delete[] buffer;

			return entryPoint;
		}

		bool CheckRelocRange(uint8_t* pRelocBuf, uint32_t dwRelocBufSize, uint32_t dwStartRVA, uint32_t dwEndRVA) {
			IMAGE_BASE_RELOCATION* pCurrentRelocBlock;
			uint32_t dwRelocBufOffset, dwX;
			bool bWithinRange = false;

			for (pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)pRelocBuf, dwX = 0, dwRelocBufOffset = 0; pCurrentRelocBlock->SizeOfBlock; dwX++) {
				uint32_t dwNumBlocks = ((pCurrentRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t));
				uint16_t* pwCurrentRelocEntry = (uint16_t*)((uint8_t*)pCurrentRelocBlock + sizeof(IMAGE_BASE_RELOCATION));

				for (uint32_t dwY = 0; dwY < dwNumBlocks; dwY++, pwCurrentRelocEntry++) {
#ifdef _WIN64
#define RELOC_FLAG_ARCH_AGNOSTIC IMAGE_REL_BASED_DIR64
#else
#define RELOC_FLAG_ARCH_AGNOSTIC IMAGE_REL_BASED_HIGHLOW
#endif
					if (((*pwCurrentRelocEntry >> 12) & RELOC_FLAG_ARCH_AGNOSTIC) == RELOC_FLAG_ARCH_AGNOSTIC) {
						uint32_t dwRelocEntryRefLocRva = (pCurrentRelocBlock->VirtualAddress + (*pwCurrentRelocEntry & 0x0FFF));

						if (dwRelocEntryRefLocRva >= dwStartRVA && dwRelocEntryRefLocRva < dwEndRVA) {
							bWithinRange = true;
						}
					}
				}

				dwRelocBufOffset += pCurrentRelocBlock->SizeOfBlock;
				pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)((uint8_t*)pCurrentRelocBlock + pCurrentRelocBlock->SizeOfBlock);
			}

			return bWithinRange;
		}
	}