#include <fltKernel.h>
#include <ntstrsafe.h>
#include <ntdddisk.h>
#include <winternl.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")
#define SHA256_DIGEST_LENGTH 32

EXTERN_C_START

// Global variables
PFLT_FILTER gFilterHandle = NULL;

// Function prototypes
NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS PreOperationCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
NTSTATUS CalculateFileHash(PFLT_CALLBACK_DATA Data, PCHAR HashBuffer, ULONG HashBufferSize);

// Filter registration structure
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      PreOperationCallback,
      NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),         // Size
    FLT_REGISTRATION_VERSION,         // Version
    0,                                // Flags
    NULL,                             // Context
    Callbacks,                        // Operation callbacks
    FilterUnload,                     // FilterUnload
    NULL,                             // InstanceSetup
    NULL,                             // InstanceQueryTeardown
    NULL,                             // InstanceTeardownStart
    NULL,                             // InstanceTeardownComplete
    NULL,                             // GenerateFileName
    NULL,                             // NormalizeNameComponent
    NULL                              // NormalizeContextCleanup
};

// Driver entry point
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    NTSTATUS status;

    // Register the filter with the Filter Manager
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Start filtering I/O
    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    return STATUS_SUCCESS;
}

// Filter unload routine
NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    FltUnregisterFilter(gFilterHandle);
    return STATUS_SUCCESS;
}

// Pre-operation callback routine
FLT_PREOP_CALLBACK_STATUS PreOperationCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Check if the operation is a file creation
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        // Intercept file creation and perform integrity check
        CHAR hashBuffer[SHA256_DIGEST_LENGTH];
        NTSTATUS status = CalculateFileHash(Data, hashBuffer, SHA256_DIGEST_LENGTH);
        if (NT_SUCCESS(status)) {
            // Integrity check successful
            KdPrint(("Integrity check passed for file: %wZ\n", &Data->Iopb->TargetFileObject->FileName));
        }
        else {
            // Integrity check failed
            KdPrint(("Integrity check failed for file: %wZ\n", &Data->Iopb->TargetFileObject->FileName));
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Calculate SHA-256 hash of a file
NTSTATUS CalculateFileHash(PFLT_CALLBACK_DATA Data, PCHAR HashBuffer, ULONG HashBufferSize) {
    NTSTATUS status;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;
    OBJECT_ATTRIBUTES objectAttributes;
    LARGE_INTEGER fileSize;
    PUCHAR fileBuffer = NULL;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    ULONG bytesRead;

    // Initialize object attributes for the file
    InitializeObjectAttributes(&objectAttributes, &Data->Iopb->TargetFileObject->FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    // Open the file
    status = ZwOpenFile(&fileHandle, FILE_GENERIC_READ, &objectAttributes, &ioStatus, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Retrieve file size
    status = ZwQueryInformationFile(fileHandle, &ioStatus, &fileSize, sizeof(fileSize), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        ZwClose(fileHandle);
        return status;
    }

    // Allocate buffer for reading file contents
    fileBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, fileSize.LowPart, 'SHA');
    if (fileBuffer == NULL) {
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Read file contents into buffer
    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatus, fileBuffer, fileSize.LowPart, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePool(fileBuffer);
        ZwClose(fileHandle);
        return status;
    }

    // Initialize SHA-256 algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        ExFreePool(fileBuffer);
        ZwClose(fileHandle);
        return status;
    }

    // Create hash object
    status = BCryptCreateHash(hAlgorithm, &hHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        ExFreePool(fileBuffer);
        ZwClose(fileHandle);
        return status;
    }

    // Hash the file data
    status = BCryptHashData(hHash, fileBuffer, fileSize.LowPart, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        ExFreePool(fileBuffer);
        ZwClose(fileHandle);
        return status;
    }

    // Finalize hash
    status = BCryptFinishHash(hHash, (PUCHAR)HashBuffer, HashBufferSize, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        ExFreePool(fileBuffer);
        ZwClose(fileHandle);
        return status;
    }

    // Cleanup
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    ExFreePool(fileBuffer);
    ZwClose(fileHandle);

    return STATUS_SUCCESS;
}

EXTERN_C_END
