//! Minimal UEFI FFI type definitions.
//!
//! Hand-crafted to match UEFI 2.10 specification. No external crate.
//! Only the types needed for GetMemoryMap, AllocatePages, and ExitBootServices.

pub type EfiHandle = *mut core::ffi::c_void;
pub type EfiStatus = usize;

pub const EFI_SUCCESS: EfiStatus = 0;

// Memory types
pub const EFI_CONVENTIONAL_MEMORY: u32 = 7;

// AllocatePages types
pub const ALLOCATE_ANY_PAGES: u32 = 0;
pub const EFI_LOADER_DATA: u32 = 2;

#[repr(C)]
pub struct EfiTableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct EfiSystemTable {
    pub hdr: EfiTableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    _pad0: u32,
    pub console_in_handle: EfiHandle,
    pub con_in: *mut core::ffi::c_void,
    pub console_out_handle: EfiHandle,
    pub con_out: *mut core::ffi::c_void,
    pub standard_error_handle: EfiHandle,
    pub std_err: *mut core::ffi::c_void,
    pub runtime_services: *mut core::ffi::c_void,
    pub boot_services: *mut EfiBootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *mut core::ffi::c_void,
}

/// UEFI Boot Services table.
///
/// Function pointer layout matches UEFI 2.10 specification exactly.
/// Each slot is a function pointer (8 bytes on x86_64).
/// Unused slots are typed as `usize` placeholders.
///
/// Offsets (in function pointer slots after header):
///   0: RaiseTPL
///   1: RestoreTPL
///   2: AllocatePages      ← we use this
///   3: FreePages
///   4: GetMemoryMap        ← we use this
///   5: AllocatePool
///   6: FreePool
///   7-17: Event/Protocol services (11 slots)
///   18: LocateDevicePath
///   19: InstallConfigurationTable
///   20: LoadImage
///   21: StartImage
///   22: Exit
///   23: UnloadImage
///   24: ExitBootServices   ← we use this
#[repr(C)]
pub struct EfiBootServices {
    pub hdr: EfiTableHeader,
    // 0: RaiseTPL
    pub raise_tpl: usize,
    // 1: RestoreTPL
    pub restore_tpl: usize,
    // 2: AllocatePages
    pub allocate_pages: extern "efiapi" fn(
        alloc_type: u32,
        memory_type: u32,
        pages: usize,
        memory: *mut u64,
    ) -> EfiStatus,
    // 3: FreePages
    pub free_pages: usize,
    // 4: GetMemoryMap
    pub get_memory_map: extern "efiapi" fn(
        memory_map_size: *mut usize,
        memory_map: *mut u8,
        map_key: *mut usize,
        descriptor_size: *mut usize,
        descriptor_version: *mut u32,
    ) -> EfiStatus,
    // 5: AllocatePool
    pub allocate_pool: usize,
    // 6: FreePool
    pub free_pool: usize,
    // 7: CreateEvent
    pub create_event: usize,
    // 8: SetTimer
    pub set_timer: usize,
    // 9: WaitForEvent
    pub wait_for_event: usize,
    // 10: SignalEvent
    pub signal_event: usize,
    // 11: CloseEvent
    pub close_event: usize,
    // 12: CheckEvent
    pub check_event: usize,
    // 13: InstallProtocolInterface
    pub install_protocol_interface: usize,
    // 14: ReinstallProtocolInterface
    pub reinstall_protocol_interface: usize,
    // 15: UninstallProtocolInterface
    pub uninstall_protocol_interface: usize,
    // 16: HandleProtocol
    pub handle_protocol: usize,
    // 17: Reserved
    pub reserved: usize,
    // 18: RegisterProtocolNotify
    pub register_protocol_notify: usize,
    // 19: LocateHandle
    pub locate_handle: usize,
    // 20: LocateDevicePath
    pub locate_device_path: usize,
    // 21: InstallConfigurationTable
    pub install_configuration_table: usize,
    // 22: LoadImage
    pub load_image: usize,
    // 23: StartImage
    pub start_image: usize,
    // 24: Exit
    pub exit: usize,
    // 25: UnloadImage
    pub unload_image: usize,
    // 26: ExitBootServices
    pub exit_boot_services: extern "efiapi" fn(
        image_handle: EfiHandle,
        map_key: usize,
    ) -> EfiStatus,
}

/// UEFI memory map descriptor.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EfiMemoryDescriptor {
    pub type_: u32,
    _pad: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}
