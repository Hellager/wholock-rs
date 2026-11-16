mod file_path;
mod handle;
mod nt_handles;
mod object;
mod path_matcher;
mod process;
mod token;

pub(crate) use file_path::{ResolvedFilePath, get_final_path_name_by_handle};
pub(crate) use handle::{SafeHandle, duplicate_handle_value};
#[allow(unused_imports)]
pub(crate) use nt_handles::{
    PROCESS_ACCESS_RIGHTS_DUP_HANDLE, PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION,
    SYSTEM_EXTENDED_HANDLE_INFORMATION, get_handle_table, query_system_information_buffer,
};
pub(crate) use object::{get_object_name, is_disk_file_handle};
pub(crate) use path_matcher::LockedPathMatchers;
pub(crate) use path_matcher::kernel_path_for_path;
pub(crate) use process::{
    ProcessIdentity, get_process_identity, get_process_identity_by_handle, get_process_ids,
    get_process_module_paths,
};
pub(crate) use token::{enable_debug_privilege, get_handle_owner_info, is_process_elevated};
