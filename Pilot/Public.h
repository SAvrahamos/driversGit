/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_Pilot,
    0xbc75be17,0xd17b,0x4e97,0x8d,0x12,0x0f,0x0b,0xee,0x84,0xb9,0xef);
// {bc75be17-d17b-4e97-8d12-0f0bee84b9ef}
