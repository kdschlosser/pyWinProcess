# -*- coding: utf-8 -*-
#
# This file is part of EventGhost.
# Copyright © 2005-2016 EventGhost Project <http://www.eventghost.net/>
#
# EventGhost is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 2 of the License, or (at your option)
# any later version.
#
# EventGhost is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with EventGhost. If not, see <http://www.gnu.org/licenses/>.

import os
import ctypes

from ctypes.wintypes import (
    HANDLE,
    ULONG,
    LPCSTR,
    DWORD,
    WORD,
    BOOL,
    BYTE,
    WCHAR,
    LONG
)

POINTER = ctypes.POINTER
PVOID = ctypes.c_void_p
LPVOID = ctypes.c_void_p
LPDWORD = POINTER(DWORD)
PDWORD = POINTER(DWORD)
LPBYTE = POINTER(BYTE)
PULONG = POINTER(ULONG)
LPTSTR = LPCSTR
LPCTSTR = LPTSTR
HMODULE = HANDLE
UCHAR = ctypes.c_ubyte
SIZE_T = ctypes.c_size_t
TCHAR = WCHAR
NULL = None

if ctypes.sizeof(ctypes.c_void_p) == 8:
    ULONG_PTR = ctypes.c_ulonglong
else:
    ULONG_PTR = ctypes.c_ulong


TH32CS_INHERIT = 0x80000000


TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004

TH32CS_SNAPALL = (
    TH32CS_SNAPHEAPLIST |
    TH32CS_SNAPMODULE |
    TH32CS_SNAPPROCESS |
    TH32CS_SNAPTHREAD
)


STILL_ACTIVE = 0x00000103

PROCESS_QUERY_INFORMATION = 0x00000400
PROCESS_CREATE_PROCESS = 0x00000080
PROCESS_CREATE_THREAD = 0x00000002
PROCESS_DUP_HANDLE = 0x00000040
PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
PROCESS_SET_INFORMATION = 0x00000200
PROCESS_SET_QUOTA = 0x00000100
PROCESS_SUSPEND_RESUME = 0x00000800
PROCESS_TERMINATE = 0x00000001
PROCESS_VM_OPERATION = 0x00000008
PROCESS_VM_READ = 0x00000010
PROCESS_VM_WRITE = 0x00000020
PROCESS_SYNCHRONIZE = 0x00100000


PROCESS_ALL_ACCESS = (
    PROCESS_QUERY_INFORMATION |
    PROCESS_CREATE_PROCESS |
    PROCESS_CREATE_THREAD |
    PROCESS_DUP_HANDLE |
    PROCESS_QUERY_LIMITED_INFORMATION |
    PROCESS_SET_INFORMATION |
    PROCESS_SET_QUOTA |
    PROCESS_SUSPEND_RESUME |
    PROCESS_TERMINATE |
    PROCESS_VM_OPERATION |
    PROCESS_VM_READ |
    PROCESS_VM_WRITE |
    PROCESS_SYNCHRONIZE
)

MAX_PATH = 0x00000104
MAX_MODULE_NAME32 = 0x000000FF
PROCESS_NAME_NATIVE = 0x00000001

ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
HIGH_PRIORITY_CLASS = 0x00000080
IDLE_PRIORITY_CLASS = 0x00000040
NORMAL_PRIORITY_CLASS = 0x00000020
PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000
PROCESS_MODE_BACKGROUND_END = 0x00200000
REALTIME_PRIORITY_CLASS = 0x00000100

STARTF_FORCEONFEEDBACK = 0x00000040
STARTF_FORCEOFFFEEDBACK = 0x00000080
STARTF_PREVENTPINNING = 0x00002000
STARTF_RUNFULLSCREEN = 0x00000020
STARTF_TITLEISAPPID = 0x00001000
STARTF_TITLEISLINKNAME = 0x00000800
STARTF_UNTRUSTEDSOURCE = 0x00008000
STARTF_USECOUNTCHARS = 0x00000008
STARTF_USEFILLATTRIBUTE = 0x00000010
STARTF_USEHOTKEY = 0x00000200
STARTF_USEPOSITION = 0x00000004
STARTF_USESHOWWINDOW = 0x00000001
STARTF_USESIZE = 0x00000002
STARTF_USESTDHANDLES = 0x00000100

CREATE_BREAKAWAY_FROM_JOB = 0x01000000
CREATE_DEFAULT_ERROR_MODE = 0x04000000
CREATE_NEW_CONSOLE = 0x00000010
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
CREATE_PROTECTED_PROCESS = 0x00040000
CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000
CREATE_SECURE_PROCESS = 0x00400000
CREATE_SEPARATE_WOW_VDM = 0x00000800
CREATE_SHARED_WOW_VDM = 0x00001000
CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400
DEBUG_ONLY_THIS_PROCESS = 0x00000002
DEBUG_PROCESS = 0x00000001
DETACHED_PROCESS = 0x00000008
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
INHERIT_PARENT_AFFINITY = 0x00010000


# kernel32 API
kernel32 = ctypes.windll.kernel32
# Windows process API
psapi = ctypes.windll.psapi

KILL_INPUT = input


# noinspection PyPep8Naming
class _PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('cb', DWORD),
        ('CommitTotal', SIZE_T),
        ('CommitLimit', SIZE_T),
        ('CommitPeak', SIZE_T),
        ('PhysicalTotal', SIZE_T),
        ('PhysicalAvailable', SIZE_T),
        ('SystemCache', SIZE_T),
        ('KernelTotal', SIZE_T),
        ('KernelPaged', SIZE_T),
        ('KernelNonpaged', SIZE_T),
        ('PageSize', SIZE_T),
        ('HandleCount', DWORD),
        ('ProcessCount', DWORD),
        ('ThreadCount', DWORD)
    ]


PERFORMANCE_INFORMATION = _PERFORMANCE_INFORMATION
PPERFORMANCE_INFORMATION = POINTER(PERFORMANCE_INFORMATION)


# noinspection PyPep8Naming
class _PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ('cb', DWORD),
        ('PageFaultCount', DWORD),
        ('PeakWorkingSetSize', SIZE_T),
        ('WorkingSetSize', SIZE_T),
        ('QuotaPeakPagedPoolUsage', SIZE_T),
        ('QuotaPagedPoolUsage', SIZE_T),
        ('QuotaPeakNonPagedPoolUsage', SIZE_T),
        ('QuotaNonPagedPoolUsage', SIZE_T),
        ('PagefileUsage', SIZE_T),
        ('PeakPagefileUsage', SIZE_T),
        ('PrivateUsage', SIZE_T)
    ]


PROCESS_MEMORY_COUNTERS_EX = _PROCESS_MEMORY_COUNTERS_EX
PPROCESS_MEMORY_COUNTERS_EX = POINTER(PROCESS_MEMORY_COUNTERS_EX)


# noinspection PyPep8Naming
class _STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ('cb', DWORD),
        ('lpReserved', LPTSTR),
        ('lpDesktop', LPTSTR),
        ('lpTitle', LPTSTR),
        ('dwX', DWORD),
        ('dwY', DWORD),
        ('dwXSize', DWORD),
        ('dwYSize', DWORD),
        ('dwXCountChars', DWORD),
        ('dwYCountChars', DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags', DWORD),
        ('wShowWindow', WORD),
        ('cbReserved2', WORD),
        ('lpReserved2', LPBYTE),
        ('hStdInput', HANDLE),
        ('hStdOutput', HANDLE),
        ('hStdError', HANDLE)
    ]


STARTUPINFO = _STARTUPINFO
LPSTARTUPINFO = POINTER(STARTUPINFO)


# noinspection PyPep8Naming
class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess', HANDLE),
        ('hThread', HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId', DWORD)
    ]


PROCESS_INFORMATION = _PROCESS_INFORMATION
LPPROCESS_INFORMATION = POINTER(PROCESS_INFORMATION)


# noinspection PyPep8Naming,PyCallingNonCallable,PyTypeChecker
class tagPROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', DWORD),
        ('cntUsage', DWORD),
        ('th32ProcessID', DWORD),
        ('th32DefaultHeapID', ULONG_PTR),
        ('th32ModuleID', DWORD),
        ('cntThreads', DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase', LONG),
        ('dwFlags', DWORD),
        ('szExeFile', TCHAR * MAX_PATH)
    ]

    def __init__(self):
        ctypes.Structure.__init__(self)
        self.dwSize = ctypes.sizeof(self)


PROCESSENTRY32 = tagPROCESSENTRY32
PPROCESSENTRY32 = POINTER(PROCESSENTRY32)


# noinspection PyPep8Naming,PyCallingNonCallable,PyTypeChecker
class tagMODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', DWORD),
        ('th32ModuleID', DWORD),
        ('th32ProcessID', DWORD),
        ('GlblcntUsage', ULONG_PTR),
        ('ProccntUsage', DWORD),
        ('modBaseAddr', POINTER(BYTE)),
        ('modBaseSize', DWORD),
        ('hModule', HMODULE),
        ('szModule', TCHAR * (MAX_MODULE_NAME32 + 1)),
        ('szExePath', TCHAR * MAX_PATH)
    ]

    def __init__(self):
        ctypes.Structure.__init__(self)
        self.dwSize = ctypes.sizeof(self)


MODULEENTRY32 = tagMODULEENTRY32
PMODULEENTRY32 = POINTER(MODULEENTRY32)


_OpenProcess = kernel32.OpenProcess
_OpenProcess.restype = HANDLE

_TerminateProcess = kernel32.TerminateProcess
_TerminateProcess.restype = BOOL

_CloseHandle = kernel32.CloseHandle
_CloseHandle.restype = BOOL

_EnumProcesses = psapi.EnumProcesses
_EnumProcesses.restype = BOOL

_GetProcessImageFileName = psapi.GetProcessImageFileNameW
_GetProcessImageFileName.restype = DWORD

_GetProcessId = kernel32.GetProcessId
_GetProcessId.restype = DWORD

_QueryFullProcessImageName = kernel32.QueryFullProcessImageNameW
_QueryFullProcessImageName.restype = BOOL

_EnumProcessModules = psapi.EnumProcessModules
_EnumProcessModules.restype = BOOL

_GetModuleBaseName = psapi.GetModuleBaseNameW
_GetModuleBaseName.restype = DWORD

_GetProcessMemoryInfo = psapi.GetProcessMemoryInfo
_GetProcessMemoryInfo.restype = BOOL

_GetPerformanceInfo = psapi.GetPerformanceInfo
_GetPerformanceInfo.restype = BOOL

_CreateProcess = kernel32.CreateProcessW
_CreateProcess.restype = BOOL

_GetStartupInfo = kernel32.GetStartupInfoW

ExitProcess = kernel32.ExitProcess

_GetExitCodeProcess = kernel32.GetExitCodeProcess
_GetExitCodeProcess.restype = BOOL

_CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
_CreateToolhelp32Snapshot.restype = HANDLE

_Process32First = kernel32.Process32FirstW
_Process32First.restype = BOOL

_Process32Next = kernel32.Process32NextW
_Process32Next.restype = BOOL

_Module32First = kernel32.Module32FirstW
_Module32First.restype = BOOL

_Module32Next = kernel32.Module32NextW
_Module32Next.restype = BOOL

_GetLastError = kernel32.GetLastError
_GetLastError.restype = DWORD


# noinspection PyPep8Naming
def GetStartupInfo():
    lpStartupInfo = STARTUPINFO()
    lpStartupInfo.cb = ctypes.sizeof(lpStartupInfo)

    _GetStartupInfo(ctypes.byref(lpStartupInfo))
    return lpStartupInfo


# noinspection PyPep8Naming
class Process(object):

    def __init__(self, dwProcessId):
        self.is_open = False
        self.hProcess = NULL
        self.dwProcessId = dwProcessId
        self.bInheritHandle = BOOL(False)
        self.dwDesiredAccess = DWORD(
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_READ |
            PROCESS_TERMINATE
        )

    @property
    def child_processes(self):
        if self.parent_process is None:
            return []
        
        dwFlags = DWORD(TH32CS_SNAPPROCESS)
        th32ProcessID = DWORD(0)
        hSnapshot = _CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
        lppe = PROCESSENTRY32()

        res = _Process32First(hSnapshot, ctypes.byref(lppe))
        ids = []

        while res:
            if lppe.th32ParentProcessID == self.pid:
                ids += [lppe.th32ProcessID]
            lppe = PROCESSENTRY32()
            res = _Process32Next(hSnapshot, ctypes.byref(lppe))

        return list(Process(pid) for pid in ids)

    @property
    def parent_process(self):
        dwFlags = DWORD(TH32CS_SNAPPROCESS)
        th32ProcessID = DWORD(0)
        hSnapshot = _CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
        lppe = PROCESSENTRY32()

        res = _Process32First(hSnapshot, ctypes.byref(lppe))
        while res:
            if lppe.th32ProcessID == self.pid:
                if lppe.th32ParentProcessID:
                    return Process(lppe.th32ParentProcessID)

            lppe = PROCESSENTRY32()
            res = _Process32Next(hSnapshot, ctypes.byref(lppe))

    def __get_snapshot(self):
        dwFlags = DWORD(TH32CS_SNAPPROCESS)
        th32ProcessID = DWORD(0)
        hSnapshot = _CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
        lppe = PROCESSENTRY32()

        res = _Process32First(hSnapshot, ctypes.byref(lppe))
        while res:
            if lppe.th32ProcessID == self.pid:
                dwFlags = DWORD(TH32CS_SNAPMODULE)
                th32ProcessID = lppe.th32ProcessID
                hSnapshot = _CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
                lpme = MODULEENTRY32()
                res = _Module32First(hSnapshot, ctypes.byref(lpme))

                if res:
                    return lpme.szExePath
                else:
                    return lppe.szExeFile

            lppe = PROCESSENTRY32()
            res = _Process32Next(hSnapshot, ctypes.byref(lppe))

    def set_inherit_handle(self, bInheritHandle=BOOL(False)):
        if not isinstance(bInheritHandle, BOOL):
            bInheritHandle = BOOL(bInheritHandle)

        self.bInheritHandle = bInheritHandle

    def set_desired_access(
        self,
        dwDesiredAccess=DWORD(
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_READ |
            PROCESS_TERMINATE
        ),
        *args
    ):
        if not isinstance(dwDesiredAccess, DWORD):
            for arg in args:
                dwDesiredAccess |= arg

            dwDesiredAccess = DWORD(dwDesiredAccess)

        self.dwDesiredAccess = dwDesiredAccess

    def open(self):
        if self.hProcess is not NULL:
            _CloseHandle(self.hProcess)

        self.is_open = True
        self.hProcess = _OpenProcess(
            self.dwDesiredAccess,
            self.bInheritHandle,
            self.dwProcessId
        )
        return self.hProcess

    @property
    def path(self):
        if self.hProcess is not NULL:
            lpImageFileName = ctypes.create_unicode_buffer(MAX_PATH)
            _GetProcessImageFileName(self.hProcess, lpImageFileName, MAX_PATH)
            return os.path.dirname(lpImageFileName.value)
        elif self.is_open:
            if self.pid == 0:
                return 'System Idle Process'
            path = self.__get_snapshot()
            if path is None:
                return 'ACCESS DENIED'
            else:
                res = os.path.dirname(path)
                if res:
                    return res

                return path

    @property
    def executable(self):
        if self.hProcess is not NULL:
            lpImageFileName = ctypes.create_unicode_buffer(MAX_PATH)
            _GetProcessImageFileName(self.hProcess, lpImageFileName, MAX_PATH)
            return os.path.basename(lpImageFileName.value)
        elif self.is_open:
            if self.pid == 0:
                return 'System Idle Process'

            path = self.__get_snapshot()
            if path is None:
                return 'ACCESS DENIED'
            else:
                res = os.path.basename(path)
                if res:
                    return res
                return path

    @property
    def full_image_name(self):
        if self.hProcess is not NULL:
            lpdwSize = DWORD(MAX_PATH)
            lpExeName = ctypes.create_unicode_buffer(MAX_PATH)
            _QueryFullProcessImageName(
                self.hProcess,
                0,
                ctypes.byref(lpExeName),
                ctypes.byref(lpdwSize)
            )
            if not lpExeName.value:
                return os.path.join(self.path, self.executable)
            return lpExeName.value
        elif self.is_open:
            if self.pid == 0:
                return 'System Idle Process'
            path = self.__get_snapshot()
            if path is None:
                return 'ACCESS DENIED'
            else:
                return path

    @property
    def exit_code(self):
        if self.hProcess is not NULL:
            lpExitCode = DWORD()
            _GetExitCodeProcess(self.hProcess, ctypes.byref(lpExitCode))
            if lpExitCode != STILL_ACTIVE:
                return lpExitCode

    @property
    def memory_counters(self):
        if self.hProcess is not NULL:
            ppsmemCounters = PROCESS_MEMORY_COUNTERS_EX()
            ppsmemCounters.cb = ctypes.sizeof(ppsmemCounters)

            _GetProcessMemoryInfo(
                self.hProcess,
                ctypes.byref(ppsmemCounters),
                ctypes.sizeof(ppsmemCounters)
            )

            return ppsmemCounters

    @property
    def pid(self):
        return self.dwProcessId

    def close(self):
        self.is_open = False
        if self.hProcess is not NULL:
            _CloseHandle(self.hProcess)
            self.hProcess = NULL

    def kill(self):
        if self.hProcess is not NULL:
            if KILL_INPUT is not None:
                answer = KILL_INPUT(
                    'Terminate Process {0}:{1} (y/n)'.format(
                        self.executable,
                        self.pid
                    )
                )
                if answer.lower() == 'y':
                    _TerminateProcess(self.hProcess, 1)
            else:
                _TerminateProcess(self.hProcess, 1)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @staticmethod
    def create(filename, *args, **kwargs):
        if 'lpProcessAttributes' in kwargs:
            lpProcessAttributes = kwargs.pop('lpProcessAttributes')
        else:
            lpProcessAttributes = NULL
        if 'lpThreadAttributes' in kwargs:
            lpThreadAttributes = kwargs.pop('lpThreadAttributes')
        else:
            lpThreadAttributes = NULL

        if 'bInheritHandles' in kwargs:
            bInheritHandles = kwargs.pop('bInheritHandles')
        else:
            bInheritHandles = False

        if 'dwCreationFlags' in kwargs:
            dwCreationFlags = kwargs.pop('dwCreationFlags')
        else:
            dwCreationFlags = DETACHED_PROCESS
        if 'lpEnvironment' in kwargs:
            lpEnvironment = kwargs.pop('lpEnvironment')
        else:
            lpEnvironment = NULL
        if 'lpCurrentDirectory' in kwargs:
            lpCurrentDirectory = kwargs.pop('lpCurrentDirectory')
        else:
            lpCurrentDirectory = ctypes.create_unicode_buffer(
                os.path.dirname(filename)
            )
        if 'lpProcessInformation' in kwargs:
            lpProcessInformation = kwargs.pop('lpProcessInformation')
        else:
            lpProcessInformation = PROCESS_INFORMATION()

        if 'lpStartupInfo' in kwargs:
            lpStartupInfo = kwargs.pop('lpStartupInfo')
        else:
            lpStartupInfo = STARTUPINFO()
            lpStartupInfo.cb = ctypes.sizeof(lpStartupInfo)
            lpStartupInfo.lpReserved = NULL
            lpStartupInfo.lpDesktop = NULL
            lpStartupInfo.lpTitle = NULL
            lpStartupInfo.dwX = 0
            lpStartupInfo.dwY = 0
            lpStartupInfo.dwXSize = 0
            lpStartupInfo.dwYSize = 0
            lpStartupInfo.dwXCountChars = 0
            lpStartupInfo.dwYCountChars = 0
            lpStartupInfo.dwFillAttribute = 0
            lpStartupInfo.dwFlags = STARTF_FORCEOFFFEEDBACK
            lpStartupInfo.wShowWindow = 0
            lpStartupInfo.cbReserved2 = 0
            lpStartupInfo.lpReserved2 = NULL
            # lpStartupInfo.hStdInput
            # lpStartupInfo.hStdOutput
            # lpStartupInfo.hStdError

        def replace(s):
            return repr(str(s)).replace("'", '"').replace('\\\\', '\\')

        if args:
            lpApplicationName = NULL
            args = list(args)
            for i, arg in enumerate(args[:]):
                if arg.startswith('-'):
                    switch, value = arg.split(' ', 1)
                    args[i] = switch + ' ' + replace(value)
                else:
                    args[i] = replace(arg)

            lpCommandLine = ctypes.create_unicode_buffer(
                replace(filename) + ' ' + ' '.join(args)
            )

        else:
            lpCommandLine = NULL
            lpApplicationName = ctypes.create_unicode_buffer(
                str(filename).replace('\\\\', '\\')
            )

        if _CreateProcess(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            ctypes.byref(lpStartupInfo),
            ctypes.byref(lpProcessInformation)
        ):

            _CloseHandle(lpProcessInformation.hThread)
            _CloseHandle(lpProcessInformation.hProcess)
            pid = lpProcessInformation.dwProcessId
            process = Process(pid)
            process.open()
            return process


# noinspection PyPep8Naming,PyCallingNonCallable,PyTypeChecker
class EnumProcesses(object):

    def __get_processes(self):
        i = 70
        while True:
            lpidProcess = (DWORD * i)()
            cb = ctypes.sizeof(lpidProcess)
            cbNeeded = DWORD()

            if _EnumProcesses(
                ctypes.byref(lpidProcess),
                cb,
                ctypes.byref(cbNeeded)
            ):
                if cbNeeded.value < cb:
                    break
                else:
                    i *= 2

        nReturned = int(cbNeeded.value / ctypes.sizeof(DWORD()))
        pidProcess = list(i for i in lpidProcess)[:nReturned]
        for pid in pidProcess:
            yield Process(pid)

    def __iter__(self):
        for item in self.__get_processes():
            yield item

    def __getitem__(self, item):
        res = []
        for process in self:
            process.open()
            if isinstance(item, int) and item == process.pid:
                process.close()
                return process
            elif (
                isinstance(item, str) and
                item.lower() == process.executable.lower()
            ):
                res += [process]

            process.close()

        if isinstance(item, int):
            raise IndexError('No process matching PID {0}'.format(item))

        if res:
            return res

        raise KeyError('No process matching name {0}'.format(item))

    def __len__(self):
        return len(list(self.__get_processes()))


# noinspection PyPep8Naming
def PerformanceInformation():
    pPerformanceInformation = PERFORMANCE_INFORMATION()
    pPerformanceInformation.cb = ctypes.sizeof(
        pPerformanceInformation)

    _GetPerformanceInfo(
        ctypes.byref(pPerformanceInformation),
        ctypes.sizeof(pPerformanceInformation)
    )
    return pPerformanceInformation


if __name__ == '__main__':
    process_enum = EnumProcesses()

    printed = []

    def iter_children(prnt, indent=''):

        with prnt as pr:
            print(indent + 'PID:', pr.pid, pr.executable, pr.path, pr.full_image_name)
            for child in pr.child_processes:
                iter_children(child, indent + '    ')

    for prcss in process_enum:
        with prcss as p:
            if p.parent_process is None:
                print('PID:', p.pid, p.executable, p.path, p.full_image_name)
            else:
                iter_children(p)

    print('Process count:', len(process_enum))
