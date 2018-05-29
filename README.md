pyWinProcess
============

This module is written in pure python and only requires the python
standard lib. It is compatible with Python 2 & 3
It allows for managing Microsoft Windows Tasks (processes).

I have done my very best to make this module as easy to use as possible.
If you only want a module to handle Windows processes without all of the "fluff" this is what you are looking for.
If there is something you want me to add please feel fre to submit an issue requesting me to add it.
I have become extremely familiar with how to make pure python Windows API interfaces.

This module allows you to perform the following.

  * Enumerate processes
  * Get the total number of running processes
  * Kill a process
  * Create a process
  * Get memory metrics (system and per process)
  * Get the exit code for a process
  * Exit the process that is running this module
  * Get a processes executable name
  * Get a processes path
  * Get a processes full image name
  * Get the startup information for the process running this module


######  *Enumerating Processes*
_________________________


It doesn't get much easier then this.
This code block is assumed

```import pyWinProcess

process_enum = pyWinProcess.EnumProcesses
```

all processes returned by EnumProcesses are in a closed state. you will have to `open()` them
to be able to perform any operations on them. I have also made use of `__enter__` and `__exit__`
so you can use them in `with` statements, this will handle opening and closing of the process.


  * Number of processes

      ```
      print('Process count:', len(process_enum))
      ```

  * Get process by PID

      ```
      pid = 12345
      process = process_enum[pid]
      ```

  * Get Process by executable name

    This is going to return a list. the reason why is there may be more then
    a single process with the same executable name. It does not matter the
    case of the executable it handles that internally.

    ```
    executable = 'notepad.exe'
    processes = process_enum[executable]
    ```

  And that sums up enumerating the processes. I told you it couldn't get any easier!

###### Process
________________

The objects returned from EnumProcesses are going to be pyWinProcess.Process objects.
These objects have to be opened and closed. I did not open the process before
returning it from EnumProcesses because I wanted to make sure that you remembered to
close them.

These are the properties available. These properties will return `None` if the
process has not been opened.
  * path

      The path to the executable. this is the directory only.

  * executable

      The executable name. This is only the executable name.

  * full_image_name

      Path and executable name.

  * exit_code

      This is the only property that can return a None value if the process is open.
      It will return a None if the process is still running (because there is no exit code).

  * memory_counters

      This property is going to return a pyWinProcess.PROCESS_MEMORY_COUNTERS_EX object.
      I will explain more in detail what this is further down.

  * pid

      Process ID

Methods.

  * set_inherit_handle

    This method must be called before you call `open()`.

    It has a single parameter that accepts `True` or `False`.
    If this value is `True`, processes created by this process
    will inherit the handle.
    Otherwise, the processes do not inherit this handle.

    The defaulted value is `False`.

  * set_desired_access

    This method must be called before you call `open()`.

    The access to the process object. This access right is checked
    against the security descriptor for the process.

    This parameter can accept one or more of the following constants.
    You can either use the bitwise | and pass them as a single parameter
    or you can pass each one as it's own parameter.

      * `pyWinProcess.PROCESS_ALL_ACCESS`
      * `pyWinProcess.PROCESS_QUERY_INFORMATION`
      * `pyWinProcess.PROCESS_CREATE_PROCESS`
      * `pyWinProcess.PROCESS_CREATE_THREAD`
      * `pyWinProcess.PROCESS_DUP_HANDLE`
      * `pyWinProcess.PROCESS_QUERY_LIMITED_INFORMATION`
      * `pyWinProcess.PROCESS_SET_INFORMATION`
      * `pyWinProcess.PROCESS_SET_QUOTA`
      * `pyWinProcess.PROCESS_SUSPEND_RESUME`
      * `pyWinProcess.PROCESS_TERMINATE`
      * `pyWinProcess.PROCESS_VM_OPERATION`
      * `pyWinProcess.PROCESS_VM_READ`
      * `pyWinProcess.PROCESS_VM_WRITE`
      * `pyWinProcess.PROCESS_SYNCHRONIZE`

    The default is `pyWinProcess.PROCESS_QUERY_INFORMATION`,
    `pyWinProcess.PROCESS_TERMINATE` and
    `pyWinProcess.PROCESS_VM_READ`
)

  * open

    Opens the process. This must be called to get any of the properties
    or to kill the process. This method returns the windows handle of
    the process. This was done so if you want to use the handle in
    conjunction with some other library it makes it simple to do so.

  * close

    This must be called when you are finished with the process.

  * kill

    The kill method has a sort of fail safe built in. This can be overridden
    by setting `pyWinProcess.KILL_INPUT` to `None` or setting it to any function/method
    that accepts a single parameter. the value that the kill command looks for if `KILL_INPUT`
    is not set to `None` is a `'y'` to kill the process.

  * create

    This method will be discussed further down.

###### Process Memory Counters
__________________________

The `memory_counters` property in the `Process` object returns an
instance of `pyWinProcess.PROCESS_MEMORY_COUNTERS_EX`
This instance has these available variables. The names of the variables
explains what the data is that the variable holds.

  * PageFaultCount
  * PeakWorkingSetSize
  * WorkingSetSize
  * QuotaPeakPagedPoolUsage
  * QuotaPagedPoolUsage
  * QuotaPeakNonPagedPoolUsage
  * QuotaNonPagedPoolUsage
  * PagefileUsage
  * PeakPagefileUsage
  * PrivateUsage

###### Performance Information
_______________________

Below is some example code of how to retrieve the performance data.

```
performance_data = pyWinProcess.PerformanceInformation()
attr_names = (
    'CommitTotal',
    'CommitLimit',
    'CommitPeak',
    'PhysicalTotal',
    'PhysicalAvailable',
    'SystemCache',
    'KernelTotal',
    'KernelPaged',
    'KernelNonpaged',
    'PageSize',
    'HandleCount',
    'ProcessCount',
    'ThreadCount'
)

for attr_name in attr_names:
    value = getattr(performance_data, attr_name)
    print(attr_name + ':', value)
```

The available variables are as follows.
  * CommitTotal
  * CommitLimit
  * CommitPeak
  * PhysicalTotal
  * PhysicalAvailable
  * SystemCache
  * KernelTotal
  * KernelPaged
  * KernelNonpaged
  * PageSize
  * HandleCount
  * ProcessCount
  * ThreadCount


###### Creating a Process
__________________________

This one is a complex bugger to cover. I will do my best to make it as
easy as possible.

To create a process you need to call the `create` method the the `Process`
class. This method is a static method and if the creation is successful it will
return an instance of the `Process` class.

There are quite a few parameters to cover. But I have really simplified
the whole creation mechanism. So if you need to create a process try the
pre programmed method first and see if it work for you.

I want to spit out a little hint that took me a very long while to
figure out. If you are going to use this module to create processes if
you do not want the new process to be a child of the process that is
creating it you need to create a helper script to do this. you will then
create a process that runs python with either a file name for the script
or a generated string of code as an argument. in that file or in that
generated code you will use this module to create that detached process.
You also MUST use the `pyWinProcess.ExitProcess(exit status code)`
function to terminate that helper script. Now what I do is since you
created that process in the helper script using this module it is going
to return a Process instance. if you pass the pid of that process instance
to the ExitProcess function you are able to get the pid by using the
exit_code property. Below is an example of this.

This is only needed to create a detached process (a process that is
not a child).

```
import pyWinProcess
import sys
import os

helper_template = '''import pyWinProcess

process = pyWinProcess.create('{file_name}')
pyWinProcess.ExitProcess(process.pid)
'''

notepad = os.path.join(os.path.expandvars('%WINDIR%'), 'notepad.exe'))
helper_script = helper_template.format(file_name=notepad)

process = pyWinProcess.create(sys.executable, '-c ' + helper_script)

with process as p:
    while p.exit_code is None:
        pass
    pid = p.exit_code

process = pyWinProcess.EnumProcesses()[pid]
with process as p:
    print(p.executable)
```

I know this is goofy. but I a not the one who wrote Windows LOL.

ok so back to the create method.

the create method has a single required parameter and that is the
executable path and filename. if you need to specify any arguments to
be passed when the process is created then you do them as positional
arguments in the create method after supplying the filename.

```
pyWinProcess.create(
    r'filepath\filename.exe',
    '-switch',
    '-switch_with_parameter parameter',
    '-switch_with_quoted_parameter "some parameter with spaces",
    '-switch_with_quoted_path "C:\\some path\\some file name"
)
```

The module figures out all the crap with the spaces, and quotes and
escaped characters for you so no need to worry about any of that.

In special use cases where you may want to specify different creation
parameters you are able to use these keywords. You must specify the
keyword these are not positional.

  * lpProcessAttributes

    Default value = `None`

  * lpThreadAttributes

    Default value = `None`

  * bInheritHandles

    Default value = `False`

  * dwCreationFlags

    Default value = `pyWinProcess.DETACHED_PROCESS`

  * lpEnvironment

    Default value = `None`

  * lpCurrentDirectory

    Default value = `os.path.dirname(filename that was passed to create)`

  * lpProcessInformation

    Default value = `pyWinProcess.PROCESS_INFORMATION()`

  * lpStartupInfo

    Default value = `pyWinProcess.STARTUPINFO()`

    `lpStartupInfo.lpReserved = None`

    `lpStartupInfo.lpDesktop = None`

    `lpStartupInfo.lpTitle = None`

    `lpStartupInfo.dwX = 0`

    `lpStartupInfo.dwY = 0`

    `lpStartupInfo.dwXSize = 0`

    `lpStartupInfo.dwYSize = 0`

    `lpStartupInfo.dwXCountChars = 0`

    `lpStartupInfo.dwYCountChars = 0`

    `lpStartupInfo.dwFillAttribute = 0`

    `lpStartupInfo.dwFlags = pyWinProcess.STARTF_FORCEOFFFEEDBACK`

    `lpStartupInfo.wShowWindow = 0`

    `lpStartupInfo.cbReserved2 = 0`

    `lpStartupInfo.lpReserved2 = None`


If you want to know more on these parameters i would suggest some light
reading of the CreateProcess function in the Windows API



