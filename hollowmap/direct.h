#pragma once
#include <windows.h>
#include <cstdint>
#include <cstddef>

extern "C" NTSTATUS __protect_virtual_memory(
	HANDLE p_handle,
	void** base_addr,
	std::size_t * bytes_to_protect,
	std::uint32_t new_protect,
	std::uint32_t * old_protect
);

extern "C" NTSTATUS __write_virtual_memory(
	HANDLE p_handle,
	void* base_addr,
	void* buffer,
	std::size_t size,
	std::size_t * bytes_written
);

extern "C" NTSTATUS __read_virtual_memory(
	HANDLE p_handle,
	void* base_addr,
	void* buffer,
	std::size_t size,
	std::size_t * bytes_written
);

extern "C" NTSTATUS __alloc_virtual_memory(
	HANDLE p_handle,
	void** base_addr,
	std::uint32_t zero_bits,
	std::size_t * size,
	std::uint32_t alloc_type,
	std::uint32_t protect
);

namespace direct
{
	__forceinline bool protect_virtual_memory(
		HANDLE p_handle,
		void* base_addr,
		std::size_t size,
		std::uint32_t protect,
		std::uint32_t* old_protect
	)
	{
		return ERROR_SUCCESS == ::__protect_virtual_memory(p_handle, &base_addr, &size, protect, old_protect);
	}

	__forceinline bool write_virtual_memory(
		HANDLE p_handle,
		void* base_addr,
		void* buffer,
		std::size_t size
	)
	{
		std::size_t bytes_written;
		return ERROR_SUCCESS == __write_virtual_memory(p_handle, base_addr, buffer, size, &bytes_written);
	}

	__forceinline bool read_virtual_memory(
		HANDLE p_handle,
		void* addr,
		void* buffer,
		std::size_t size
	)
	{
		std::size_t bytes_written;
		return ERROR_SUCCESS == ::__read_virtual_memory(p_handle, addr, buffer, size, &bytes_written);
	}

	__forceinline void* alloc_virtual_memory(
		HANDLE p_handle,
		std::size_t size,
		std::uint32_t protect
	)
	{
		void* base_addr = NULL;
		::__alloc_virtual_memory(
			p_handle,
			&base_addr,
			NULL,
			&size,
			MEM_COMMIT | MEM_RESERVE,
			protect
		);
		return base_addr;
	}
}