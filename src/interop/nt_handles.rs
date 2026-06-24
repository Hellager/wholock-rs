use crate::{WholockResult, error::WholockError};
use std::{
    ffi::c_void,
    mem,
    os::raw::{c_ulong, c_ushort},
    ptr::addr_of,
    slice,
};
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
use windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS;

pub(crate) const SYSTEM_EXTENDED_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS =
    SYSTEM_INFORMATION_CLASS(0x40);
pub(crate) const PROCESS_ACCESS_RIGHTS_DUP_HANDLE: PROCESS_ACCESS_RIGHTS =
    PROCESS_ACCESS_RIGHTS(0x0040);
pub(crate) const PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION: PROCESS_ACCESS_RIGHTS =
    PROCESS_ACCESS_RIGHTS(0x0400);
#[repr(C)]
pub(crate) struct SystemHandleInformationEx {
    number_of_handles: usize,
    _reserved: usize,
    handles: [SystemHandleTableEntryInfoEx; 1],
}

#[repr(C)]
pub(crate) struct SystemHandleTableEntryInfoEx {
    #[allow(dead_code)]
    pub(crate) object: *mut c_void,
    pub(crate) unique_process_id: usize,
    pub(crate) handle_value: *mut c_void,
    #[allow(dead_code)]
    pub(crate) granted_access: c_ulong,
    #[allow(dead_code)]
    pub(crate) creator_back_trace_index: c_ushort,
    #[allow(dead_code)]
    pub(crate) object_type_index: c_ushort,
    #[allow(dead_code)]
    pub(crate) handle_attributes: c_ulong,
    pub(crate) _reserved: c_ulong,
}

#[repr(transparent)]
pub(crate) struct HandleEntry(pub(crate) SystemHandleTableEntryInfoEx);

impl HandleEntry {
    #[allow(dead_code)]
    fn object(&self) -> *mut c_void {
        self.0.object
    }
    pub fn unique_process_id(&self) -> usize {
        self.0.unique_process_id
    }
    fn handle_value(&self) -> *mut c_void {
        self.0.handle_value
    }
    pub(crate) fn handle_value_raw(&self) -> usize {
        self.0.handle_value as usize
    }
    #[allow(dead_code)]
    fn granted_access(&self) -> c_ulong {
        self.0.granted_access
    }
    #[allow(dead_code)]
    fn creator_back_trace_index(&self) -> c_ushort {
        self.0.creator_back_trace_index
    }
    #[allow(dead_code)]
    fn object_type_index(&self) -> c_ushort {
        self.0.object_type_index
    }
    #[allow(dead_code)]
    fn handle_attributes(&self) -> c_ulong {
        self.0.handle_attributes
    }
}

pub(crate) fn query_system_information_buffer(
    information_class: SYSTEM_INFORMATION_CLASS,
) -> WholockResult<Vec<u8>> {
    let mut buffer: Vec<u8> = vec![];
    loop {
        let mut return_length = 0;
        // SAFETY: `buffer.as_mut_ptr()` is either null for the initial zero-sized
        // probe or points to `buffer.len()` writable bytes. `return_length` is a
        // valid out-parameter for NtQuerySystemInformation.
        let result = unsafe {
            NtQuerySystemInformation(
                information_class,
                buffer.as_mut_ptr().cast(),
                buffer.len() as c_ulong,
                &mut return_length,
            )
        };
        let return_length = return_length as usize;

        if result.is_ok() {
            return Ok(buffer);
        } else if result.is_err() {
            if return_length > buffer.len() {
                buffer.clear();
                buffer.reserve_exact(return_length);
                buffer.resize(return_length, 0);
            } else {
                return Err(WholockError::system_info(
                    "Failed to query system information".to_string(),
                ));
            }
        }
    }
}

pub(crate) fn get_handle_table(buffer: &[u8]) -> WholockResult<&[HandleEntry]> {
    let header_size = 2 * mem::size_of::<usize>();
    if buffer.len() < header_size {
        return Err(WholockError::system_info(format!(
            "System handle information buffer is too small: {} bytes",
            buffer.len()
        )));
    }

    let info_ptr: *const SystemHandleInformationEx = buffer.as_ptr().cast();
    // SAFETY: `buffer` comes from NtQuerySystemInformation for
    // SystemExtendedHandleInformation and is large enough to contain the fixed
    // header. `addr_of!` avoids creating intermediate references to packed or
    // unaligned fields in the returned byte buffer.
    let table_ptr: *const HandleEntry = unsafe { addr_of!((*info_ptr).handles).cast() };
    // SAFETY: Same buffer contract as above; read_unaligned is used because the
    // byte buffer does not provide Rust alignment guarantees for the NT header.
    let len = unsafe { addr_of!((*info_ptr).number_of_handles).read_unaligned() };
    // SAFETY: `table_ptr` is derived from `buffer.as_ptr()`, so offset_from is
    // computed between pointers into the same allocation.
    let table_offset = unsafe { table_ptr.cast::<u8>().offset_from(buffer.as_ptr()) };
    let table_offset = usize::try_from(table_offset).map_err(|_| {
        WholockError::system_info("System handle table offset was negative".to_string())
    })?;
    if table_offset > buffer.len() {
        return Err(WholockError::system_info(format!(
            "System handle table offset {table_offset} exceeds buffer length {}",
            buffer.len()
        )));
    }

    let max_len = (buffer.len() - table_offset) / mem::size_of::<HandleEntry>();
    if len > max_len {
        return Err(WholockError::system_info(format!(
            "System handle table reports {len} entries but buffer can hold {max_len}"
        )));
    }

    // SAFETY: The checks above verify the advertised handle count fits in
    // the returned buffer. `HandleEntry` is repr(transparent) over the NT entry.
    Ok(unsafe { slice::from_raw_parts(table_ptr, len) })
}

#[allow(dead_code)]
pub(crate) fn query_system_info() {
    use log::debug;

    let Ok(buffer) = query_system_information_buffer(SYSTEM_EXTENDED_HANDLE_INFORMATION) else {
        return;
    };
    let Ok(table) = get_handle_table(&buffer) else {
        return;
    };
    for (i, entry) in table.iter().enumerate() {
        debug!("entry {i}:");
        debug!("  Object = {:p}", entry.object());
        debug!("  UniqueProcessId = {}", entry.unique_process_id());
        debug!("  HandleValue = {:p}", entry.handle_value());
        debug!("  GrantedAccess = {:#x}", entry.granted_access());
        debug!(
            "  CreatorBackTraceIndex = {}",
            entry.creator_back_trace_index()
        );
        debug!("  ObjectTypeIndex = {}", entry.object_type_index());
        debug!("  HandleAttributes = {:#x}", entry.handle_attributes());
    }

    debug!("system info");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WholockError;
    use std::ptr::addr_of;

    #[test]
    fn test_query_system_information_buffer() {
        let result = query_system_information_buffer(SYSTEM_EXTENDED_HANDLE_INFORMATION);
        assert!(result.is_ok());
        let buffer = result.unwrap();
        assert!(!buffer.is_empty());
    }

    #[test]
    fn test_get_handle_table() {
        let buffer = query_system_information_buffer(SYSTEM_EXTENDED_HANDLE_INFORMATION).unwrap();
        let table = get_handle_table(&buffer).unwrap();
        assert!(!table.is_empty());
    }

    #[test]
    fn test_get_handle_table_rejects_short_buffer() {
        let result = get_handle_table(&[]);

        assert!(matches!(result, Err(WholockError::SystemInfoError(_))));
    }

    #[test]
    fn test_get_handle_table_rejects_overreported_count() {
        let mut buffer = vec![0u8; 2 * mem::size_of::<usize>()];
        let count = 1usize.to_ne_bytes();
        buffer[..count.len()].copy_from_slice(&count);

        let result = get_handle_table(&buffer);

        assert!(matches!(result, Err(WholockError::SystemInfoError(_))));
    }

    #[test]
    fn test_system_handle_struct_layout() {
        let info = SystemHandleInformationEx {
            number_of_handles: 0,
            _reserved: 0,
            handles: [SystemHandleTableEntryInfoEx {
                object: std::ptr::null_mut(),
                unique_process_id: 0,
                handle_value: std::ptr::null_mut(),
                granted_access: 0,
                creator_back_trace_index: 0,
                object_type_index: 0,
                handle_attributes: 0,
                _reserved: 0,
            }],
        };
        let info_base = addr_of!(info).cast::<u8>() as usize;
        let handles_offset = addr_of!(info.handles).cast::<u8>() as usize - info_base;

        assert_eq!(
            handles_offset,
            2 * mem::size_of::<usize>(),
            "SYSTEM_HANDLE_INFORMATION_EX handles offset must match NT ABI"
        );
        assert_eq!(
            mem::size_of::<SystemHandleTableEntryInfoEx>(),
            3 * mem::size_of::<usize>() + 4 * mem::size_of::<c_ulong>(),
            "SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX size must match NT ABI"
        );
        assert_eq!(
            mem::size_of::<HandleEntry>(),
            mem::size_of::<SystemHandleTableEntryInfoEx>(),
            "HandleEntry must remain a transparent wrapper"
        );
        assert_eq!(
            mem::align_of::<HandleEntry>(),
            mem::align_of::<SystemHandleTableEntryInfoEx>(),
            "HandleEntry alignment must match the underlying NT entry"
        );
    }
}
