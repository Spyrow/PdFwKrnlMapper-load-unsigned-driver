	#include <iostream>
#include "Bypass.h"

namespace Bypass
{
	bool Init()
	{
		SeValidateImageDataOffset	= KernelUtils::GetSeValidateImageDataOffset();
		SeValidateImageHeaderOffset = KernelUtils::GetSeValidateImageHeaderOffset();
		RetOffset					= KernelUtils::GetReturnOffset();
		NtoskrnlBaseAddress			= KernelUtils::GetNtoskrnlBase();
		PatchgaurdValueOffset		= KernelUtils::GetPatchGaurdValueOffset();
		PatchgaurdOffset			= KernelUtils::GetPatchGaurdOffset();

		if (SeValidateImageDataOffset == 0 || SeValidateImageHeaderOffset == 0 || RetOffset == 0 || NtoskrnlBaseAddress == 0)
			return false;

		return true;
	}

	bool DisableDSE()
	{
		ULONG64 ReturnAddressOffset = NtoskrnlBaseAddress + RetOffset;

		BOOL Status = Vuln::WriteVirtualMemory(VulnurableDriverHandle, NtoskrnlBaseAddress + SeValidateImageHeaderOffset, &ReturnAddressOffset, sizeof(ReturnAddressOffset));
		if (!Status)
			return false;

		Status = Vuln::WriteVirtualMemory(VulnurableDriverHandle, NtoskrnlBaseAddress + SeValidateImageDataOffset, &ReturnAddressOffset, sizeof(ReturnAddressOffset));
		if (!Status)
			return false;

		return Status;
	}

	bool DisablePG() 
	{
		ULONG64 ReturnAddressOffset			= NtoskrnlBaseAddress + RetOffset;
		ULONG64 PatchGaurdValueAddress		= NtoskrnlBaseAddress + PatchgaurdValueOffset;

		BOOL Status = Vuln::WriteVirtualMemory(VulnurableDriverHandle, NtoskrnlBaseAddress + PatchgaurdOffset, &PatchGaurdValueAddress, 8);
		return Status;
	}

	bool LoadVulnurableDriver(std::string PdFwKrnlPath, std::string PdFwKrnlServiceName)
	{
		std::cout << " [*] Loading Vulnurable Driver (PdFwKrnl.sys)..." << std::endl;
		NTSTATUS vulnStatus = driver::load(PdFwKrnlPath, PdFwKrnlServiceName);
		std::cout << " [*] PdFwKrnl.sys load status: 0x" << std::hex << std::uppercase << vulnStatus << std::dec << std::endl;

		if (vulnStatus != STATUS_SUCCESS)
			return false;

		std::cout << " [*] PdFwKrnl loaded successfully." << std::endl;
		VulnurableDriverHandle = CreateFileA(("\\.\\" + PdFwKrnlServiceName).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (VulnurableDriverHandle == INVALID_HANDLE_VALUE || !VulnurableDriverHandle)
			return false;

		return true;
	}

	BypassStatus LoadCheatDriver(std::string DriverPath, std::string DriverServiceName, std::string PdFwKrnlPath, std::string PdFwKrnlServiceName)
	{
		bool Status = LoadVulnurableDriver(PdFwKrnlPath, PdFwKrnlServiceName);
		if (!Status)
			return FAILED_LOADINGVULN;

		std::cout << " [*] Disabling PatchGuard..." << std::endl;
		Status = DisablePG();
		if (!Status)
			return FAILED_DISABLEPG;
		std::cout << " [*] PatchGuard disabled." << std::endl;

		std::cout << " [*] Disabling DSE..." << std::endl;
		Status = DisableDSE();
		if (!Status)
			return FAILED_DISABLEDSE;
		std::cout << " [*] DSE disabled." << std::endl;

		std::string DrvPath = DriverPath;
		std::cout << " [*] Loading main driver: " << DrvPath << std::endl;
		NTSTATUS drvStatus = driver::load(DrvPath, DriverServiceName);
		std::cout << " [*] Driver load status: 0x" << std::hex << std::uppercase << drvStatus << std::dec << std::endl;

		if (drvStatus == 0xC000010E)
		{
			std::cout << " [*] Driver already loaded (0xC000010E), attempting unload..." << std::endl;
			driver::unload(DriverServiceName);
		}

		drvStatus = driver::load(DrvPath, DriverServiceName);
		std::cout << " [*] Driver second load attempt status: 0x" << std::hex << std::uppercase << drvStatus << std::dec << std::endl;

		if (drvStatus != STATUS_SUCCESS)
			return FAILED_LOADINGCHEATDRV;

		driver::unload(PdFwKrnlServiceName);
		return SUCCESS;
	}

	std::string BypassStatusToString(BypassStatus Status)
	{
		std::string StatusString;

		switch (Status)
		{
			case FAILED_LOADINGVULN:
			{
				StatusString = "Failed loading Vulnurable Driver";
				break;
			}

			case FAILED_DISABLEPG:
			{
				StatusString = "Failed Disabling Patchgaurd";
				break;
			}

			case FAILED_DISABLEDSE:
			{
				StatusString = "Failed Disabling DSE";
				break;
			}

			case FAILED_LOADINGCHEATDRV:
			{
				StatusString = "Failed Loading Main Driver";
				break;
			}

			case SUCCESS:
			{
				StatusString = "Success";
				break;
			}

			defualt:
			{
				StatusString = "Unkown Status, assuming success";
				break;
			}
		}

		return StatusString;
	}
}

