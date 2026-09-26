#pragma once
#include <Windows.h>
#include <Winternl.h>
#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>
#include "SkCrypt.h"

#pragma comment(lib, "ntdll.lib")
using nt_load_driver_t = NTSTATUS(__fastcall*)(PUNICODE_STRING);
using nt_unload_driver_t = NTSTATUS(__fastcall*)(PUNICODE_STRING);

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

namespace driver
{
	namespace util
	{
		inline bool delete_service_entry(const std::string& service_name)
		{
			HKEY reg_handle;
			static const std::string reg_key(E("System\\CurrentControlSet\\Services\\"));

			auto result = RegOpenKeyA(
				HKEY_LOCAL_MACHINE,
				reg_key.c_str(),
				&reg_handle
			);

			return ERROR_SUCCESS == RegDeleteKeyA(reg_handle, service_name.data()) && ERROR_SUCCESS == RegCloseKey(reg_handle);;
		}

inline bool create_service_entry(const std::string& drv_path, const std::string& service_name)
		{
			HKEY reg_handle;
			std::string reg_key(E("System\\CurrentControlSet\\Services\\"));
			reg_key += service_name;

			DWORD result = RegCreateKeyA(
				HKEY_LOCAL_MACHINE,
				reg_key.c_str(),
				&reg_handle
			);

			if (result != ERROR_SUCCESS)
			{
				std::cout << " [Loadup] RegCreateKey failed: " << result << " (key: " << reg_key << ")" << std::endl;
				return false;
			}

			//
			// set type to 1 (kernel)
			//
			constexpr std::uint8_t type_value = 1;
			result = RegSetValueExA(
				reg_handle,
				E("Type"),
				NULL,
				REG_DWORD,
				&type_value,
				4u
			);

			if (result != ERROR_SUCCESS)
				return false;

			//
			// set error control to 3
			//
			constexpr std::uint8_t error_control_value = 3;
			result = RegSetValueExA(
				reg_handle,
				E("ErrorControl"),
				NULL,
				REG_DWORD,
				&error_control_value,
				4u
			);

			if (result != ERROR_SUCCESS)
				return false;

			//
			// set start to 3
			//
			constexpr std::uint8_t start_value = 3;
			result = RegSetValueExA(
				reg_handle,
				E("Start"),
				NULL,
				REG_DWORD,
				&start_value,
				4u
			);

			if (result != ERROR_SUCCESS)
				return false;

			//
			// set image path to the driver on disk
			//
			result = RegSetValueExA(
				reg_handle,
				E("ImagePath"),
				NULL,
				REG_SZ,
				(std::uint8_t*)drv_path.c_str(),
				drv_path.size()
			);

			if (result != ERROR_SUCCESS)
				return false;

			return ERROR_SUCCESS == RegCloseKey(reg_handle);
		}

inline bool enable_privilege(const std::string& privilege_name)
		{
			HANDLE token_handle = nullptr;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle))
			{
				std::cout << " [Loadup] OpenProcessToken failed: " << GetLastError() << std::endl;
				return false;
			}

			LUID luid{};
			if (!LookupPrivilegeValueA(nullptr, privilege_name.data(), &luid))
			{
				std::cout << " [Loadup] LookupPrivilegeValueA failed: " << GetLastError() << std::endl;
				return false;
			}

			TOKEN_PRIVILEGES token_state{};
			token_state.PrivilegeCount = 1;
			token_state.Privileges[0].Luid = luid;
			token_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (!AdjustTokenPrivileges(token_handle, FALSE, &token_state, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
			{
				std::cout << " [Loadup] AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
				return false;
			}

			std::cout << " [Loadup] Privilege " << privilege_name << " enabled successfully" << std::endl;

			CloseHandle(token_handle);
			return true;
		}

		inline std::string get_service_image_path(const std::string& service_name)
		{
			HKEY reg_handle;
			DWORD bytes_read;
			char image_path[0xFF];
			static const std::string reg_key(E("System\\CurrentControlSet\\Services\\"));

			auto result = RegOpenKeyA(
				HKEY_LOCAL_MACHINE,
				reg_key.c_str(),
				&reg_handle
			);

			result = RegGetValueA(
				reg_handle,
				service_name.c_str(),
				"ImagePath",
				REG_SZ,
				NULL,
				image_path,
				&bytes_read
			);

			RegCloseKey(reg_handle);
			return std::string(image_path);
		}
	}

	inline NTSTATUS load(const std::string& drv_path, const std::string& service_name)
	{
		if (!util::enable_privilege(std::string(E("SeLoadDriverPrivilege"))))
		{
			std::cout << " [Loadup] Failed to enable SeLoadDriverPrivilege" << std::endl;
			return STATUS_ABANDONED_WAIT_0;
		}

		std::string drv_path_full = "\\??\\" + std::filesystem::absolute(std::filesystem::path(drv_path)).string();
		std::cout << " [Loadup] Creating service entry for: " << drv_path_full << std::endl;
		if (!util::create_service_entry(drv_path_full, service_name))
		{
			std::cout << " [Loadup] create_service_entry failed for: " << service_name << std::endl;
			return STATUS_ABANDONED_WAIT_0;
		}

		std::string reg_path(E("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"));
		reg_path += service_name;

		static const auto lp_nt_load_drv =
			::GetProcAddress(
				GetModuleHandleA(E("ntdll.dll")),
				E("NtLoadDriver")
			);

		if (lp_nt_load_drv)
		{
			ANSI_STRING driver_rep_path_cstr;
			UNICODE_STRING driver_reg_path_unicode;

			RtlInitAnsiString(&driver_rep_path_cstr, reg_path.c_str());
			RtlAnsiStringToUnicodeString(&driver_reg_path_unicode, &driver_rep_path_cstr, true);

			std::cout << " [Loadup] NtLoadDriver called for: " << service_name << std::endl;
			NTSTATUS status = reinterpret_cast<nt_load_driver_t>(lp_nt_load_drv)(&driver_reg_path_unicode);
			std::cout << " [Loadup] NtLoadDriver returned: 0x" << std::hex << std::uppercase << status << std::dec << std::endl;

			RtlFreeUnicodeString(&driver_reg_path_unicode);

			if (status != STATUS_SUCCESS)
			{
				std::cout << " [Loadup] Attempting to delete service: " << service_name << std::endl;
				util::delete_service_entry(service_name);
			}

			return status;
		}

		return STATUS_ABANDONED_WAIT_0;
	}

	inline std::tuple<NTSTATUS, std::string> load(const std::vector<std::uint8_t>& drv_buffer)
	{
		static const auto random_file_name = [](std::size_t length) -> std::string
			{
				static const auto randchar = []() -> char
					{
						const char charset[] =
							"0123456789"
							"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
							"abcdefghijklmnopqrstuvwxyz";
						const std::size_t max_index = (sizeof(charset) - 1);
						return charset[rand() % max_index];
					};
				std::string str(length, 0);
				std::generate_n(str.begin(), length, randchar);
				return str;
			};

		const auto service_name = random_file_name(16);
		const auto file_path = std::filesystem::temp_directory_path().string() + random_file_name(16);
		std::ofstream output_file(file_path.c_str(), std::ios::binary);

		output_file.write((char*)drv_buffer.data(), drv_buffer.size());
		output_file.close();

		return { load(file_path, service_name), service_name };
	}

	inline std::tuple<NTSTATUS, std::string> load(const std::uint8_t* buffer, const std::size_t size)
	{
		std::vector<std::uint8_t> image(buffer, buffer + size);
		return load(image);
	}

	inline bool unload(const std::string& service_name)
	{
		std::string reg_path(E("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"));
		reg_path += service_name;

		static const auto lp_nt_unload_drv =
			::GetProcAddress(
				GetModuleHandleA(E("ntdll.dll")),
				E("NtUnloadDriver")
			);

		if (lp_nt_unload_drv)
		{
			ANSI_STRING driver_rep_path_cstr;
			UNICODE_STRING driver_reg_path_unicode;

			RtlInitAnsiString(&driver_rep_path_cstr, reg_path.c_str());
			RtlAnsiStringToUnicodeString(&driver_reg_path_unicode, &driver_rep_path_cstr, true);

			const bool unload_drv = !reinterpret_cast<nt_unload_driver_t>(lp_nt_unload_drv)(&driver_reg_path_unicode);
			const auto image_path = std::filesystem::temp_directory_path().string() + service_name;
			const bool delete_reg = util::delete_service_entry(service_name);
			try
			{
				const bool delete_drv = std::filesystem::remove(image_path);
			}
			catch (std::exception& e) {}
			return unload_drv && delete_reg;
		}
		return false;
	}
}