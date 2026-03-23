//! Minimal UEFI FFI type definitions.
//!
//! Hand-crafted to match UEFI 2.10 specification. No external crate.
//! Only the types needed for GetMemoryMap, AllocatePages, ExitBootServices,
//! and LocateProtocol (for GOP).

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
///   0: RaiseTPL              7-12: Event services
///   1: RestoreTPL            13-17: Protocol handler services
///   2: AllocatePages         18-21: Image/config services
///   3: FreePages             22-26: Image/boot services
///   4: GetMemoryMap          27-29: Misc services
///   5: AllocatePool          30-31: Driver support
///   6: FreePool              32-36: Protocol services
///   24: ExitBootServices     37: LocateProtocol
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
    pub reserved2: usize,
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
    // 27: GetNextHighMonotonicCount
    pub get_next_high_monotonic_count: usize,
    // 28: Stall
    pub stall: usize,
    // 29: SetWatchdogTimer
    pub set_watchdog_timer: usize,
    // 30: ConnectController
    pub connect_controller: usize,
    // 31: DisconnectController
    pub disconnect_controller: usize,
    // 32: OpenProtocol
    pub open_protocol: usize,
    // 33: CloseProtocol
    pub close_protocol: usize,
    // 34: OpenProtocolInformation
    pub open_protocol_information: usize,
    // 35: ProtocolsPerHandle
    pub protocols_per_handle: usize,
    // 36: LocateHandleBuffer
    pub locate_handle_buffer: usize,
    // 37: LocateProtocol
    pub locate_protocol: extern "efiapi" fn(
        protocol: *const EfiGuid,
        registration: *const core::ffi::c_void,
        interface: *mut *mut core::ffi::c_void,
    ) -> EfiStatus,
}

// ─── EFI GUID ────────────────────────────────────────────────────────────────

#[repr(C)]
pub struct EfiGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// GUID for EFI_GRAPHICS_OUTPUT_PROTOCOL
pub const EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID: EfiGuid = EfiGuid {
    data1: 0x9042a9de,
    data2: 0x23dc,
    data3: 0x4a38,
    data4: [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
};

// ─── UEFI Graphics Output Protocol (GOP) ────────────────────────────────────

#[repr(C)]
pub struct EfiGraphicsOutputProtocol {
    pub query_mode: usize,
    pub set_mode: usize,
    pub blt: usize,
    pub mode: *const EfiGraphicsOutputMode,
}

#[repr(C)]
pub struct EfiGraphicsOutputMode {
    pub max_mode: u32,
    pub mode: u32,
    pub info: *const EfiGraphicsOutputModeInfo,
    pub size_of_info: usize,
    pub framebuffer_base: u64,
    pub framebuffer_size: usize,
}

#[repr(C)]
pub struct EfiGraphicsOutputModeInfo {
    pub version: u32,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub pixel_format: u32, // 0=RGBX, 1=BGRX, 2=BitMask, 3=BltOnly
    pub pixel_info: [u32; 4],
    pub pixels_per_scan_line: u32,
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
