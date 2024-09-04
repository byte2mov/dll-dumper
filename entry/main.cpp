#include "../includes.h"

/*
   READ ME !!!


   all rights reserved by the original author. This code is provided as is and without any warranty.
   original author : zer0day.one / seemo / flyingcat / byte2mov

   first of all i do not sell this, it is just simple dumper that will work in alot of p2cs.

   how to use this code:

   first of all lets begin with how injectors generally work for pay2cheats:

   generally these injectors usually use either CreateRemoteThread 
   or CreateProcess with the PROCESS_CREATE_THREAD flag if they are for games without anticheats.

   however more advanced injectors for games that use anticheats use kernel drivers and allocate memory regions in the target process that are writable and executable.

   we are going to focus on something that works for both.

   generally most modern injectors are not dropping their module / payload onto disk.
   rather they grab their module from a server, auth or store it bytes and then load the memory into their inject function and do whatever they want.

   example would be the following

   void inject_function(BYTE* dll){
        
        // access nt headers or whatever

        allocate_memory(dll);


   }

   now we know what to generally expect, ofcourse this method may depend on many factors as many injectors utilize server mappers that render the dll
   file useless without a valid PE.

   now what we can do here is to try and find this function in a debugger or IDA and hook it.

   we will use face injector as a our testing example.


   first of all we will get the offset for their inject function, you can find this in a few ways.

   you can look for where virtualalloc is being called and xref or if we are lucky they have an output that says "injecting"

   that will make finding the function easy.

   now for example lets say the offset is 0x00401234 and we found it in the ida

   we will just use minhook to hook the function.

   then we will access the ntheaders our self and check for the size and then dump the bytes according to that.


   first we define the type of the function we want to hook. ( inject_function ).

   then we will define the variable that will hold the original pointer of our function ( original_inject ).
   
   then we make function hook which will be ( hk_inject ).

   then we initialize minhook and set the hook
   */


class dumping {
public:

    PIMAGE_NT_HEADERS dll_nt_headers;
    PVOID image;
    size_t dll_size;
	uintptr_t dll_base_address;
    uintptr_t loader_base_address;
    uintptr_t function_address;
};
static dumping* dumper = new dumping();

typedef __int64(__fastcall* inject_function)(BYTE* a1);


static inject_function original_inject = nullptr;


static __int64 __fastcall hk_inject(BYTE* a1) {

	// first of all we need to get the ntheaders of our dll

	dumper->image = a1;

	// get ntheaders

	dumper->dll_nt_headers = RtlImageNtHeader(dumper->image);

	// check if IMAGE_NT_SIGNATURE is valid

	if (dumper->dll_nt_headers->Signature != IMAGE_NT_SIGNATURE) {
		instance->logger("invalid pe signature");
		return original_inject(a1);
	}	
	instance->logger("pe signature is valid");

	// get the size of our dll
	dumper->dll_size = dumper->dll_nt_headers->OptionalHeader.SizeOfImage;

	instance->logger("size of dll -> " + std::to_string(dumper->dll_size));

	// get the base address of our dll
	dumper->dll_base_address = dumper->dll_nt_headers->OptionalHeader.ImageBase;

	instance->logger("base address of dll -> " + std::to_string(dumper->dll_base_address));

	// we aren't using the base address but you can use it if you have a need for it or possibly a more complex way of writing dll.

	// write the dll to disk now using fstream

	std::ofstream file("dumped_module.dll", std::ios::binary);
	if (!file.is_open()) {
		instance->logger("failed to open file for writing");
		return original_inject(a1);
	}

	instance->logger("created file for writing successfully");

	file.write((char*)dumper->image, dumper->dll_size);

	file.close();

	instance->logger("wrote dll to disk successfully");

	return original_inject(a1);
}

auto initialize() -> bool {

    // setting up minhook

	MH_STATUS init = MH_Initialize();
	if (init != MH_OK) {
        instance->logger("failed to initialize minhook, error -> " + std::string(MH_StatusToString(init)));
		return false;
	}

	instance->logger("initialized minhook successfully");

	// creating hook for inject 

	dumper->loader_base_address = (uintptr_t)GetModuleHandle(nullptr);

	dumper->function_address = dumper->loader_base_address + 0x1; // replace 0x1 with the offset of your inject function

	instance->logger("loader base address -> " + std::to_string(dumper->loader_base_address));

    MH_STATUS create = MH_CreateHook(original_inject, hk_inject, (LPVOID*)&original_inject);
	if (create != MH_OK) {
		instance->logger("failed to create hook, error -> " + std::string(MH_StatusToString(create)));
		MH_Uninitialize();
		return false;
	}

	instance->logger("created hook successfully");

	// enabling hook for inject
	MH_STATUS enable = MH_EnableHook(original_inject);
    if (enable != MH_OK) {
		instance->logger("failed to enable hook, error -> " + std::string(MH_StatusToString(enable)));
		MH_DisableHook(original_inject);
		MH_Uninitialize();
		return false;
	}

	instance->logger("enabled hook successfully");
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		return initialize();
        break;
    }
    return TRUE;
}

