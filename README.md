# ghidra_driver_re
Tools for reverse engineering drivers in Ghidra


get_ioctls_from_consumers.py - gets all references to DeviceIoControl and what values are loaded into EDX before the call

get_ioctl_handler.py - decides if the driver uses WDF or WDM, then takes the appropriate steps to find the IOCTL handler

propagate.py - if you have your cursor on a function, the function's parameters will be renamed to match the call
