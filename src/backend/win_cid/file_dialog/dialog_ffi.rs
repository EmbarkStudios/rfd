use crate::FileDialog;

use std::{
    ffi::{c_void, OsStr},
    iter::once,
    os::windows::ffi::OsStrExt,
    path::PathBuf,
};

use windows_sys::core::{GUID, HRESULT, PCWSTR, PWSTR};
use windows_sys::Win32::{
    Foundation::HWND,
    System::Com::{CoCreateInstance, CoTaskMemFree, CLSCTX_INPROC_SERVER},
    UI::Shell::{
        Common::COMDLG_FILTERSPEC, FileOpenDialog, FileSaveDialog, SHCreateItemFromParsingName,
        FILEOPENDIALOGOPTIONS, FOS_ALLOWMULTISELECT, FOS_PICKFOLDERS, SIGDN, SIGDN_FILESYSPATH,
    },
};

use raw_window_handle::RawWindowHandle;

unsafe fn read_to_string(ptr: *const u16) -> String {
    let mut cursor = ptr;

    loop {
        if *cursor == 0 {
            break;
        }

        cursor = cursor.add(1);
    }

    let slice = std::slice::from_raw_parts(ptr, cursor - ptr);
    String::from_utf16(slice).unwrap()
}

pub type Result<T> = std::result::Result<T, HRESULT>;

#[inline]
fn wrap_err(hresult: HRESULT) -> Result<()> {
    if hresult >= 0 {
        Ok(())
    } else {
        Err(hresult)
    }
}

#[repr(C)]
struct Interface<T> {
    vtable: *mut T,
}

#[repr(C)]
struct IUnknownV {
    __query_interface: usize,
    __add_ref: usize,
    release: unsafe extern "system" fn(this: *mut c_void) -> u32,
}

type IUnknown = Interface<IUnknownV>;

#[repr(C)]
struct IShellItemV {
    pub base: IUnknownV,
    __bind_to_handler: usize,
    __get_parent: usize,
    get_display_name:
        unsafe extern "system" fn(this: *mut c_void, name_look: SIGDN, name: *mut PWSTR) -> HRESULT,
    __get_attributes: usize,
    __compare: usize,
}

type IShellItem = Interface<IShellItemV>;

impl IShellItemV {
    fn get_path(&self) -> Result<PathBuf> {
        let mut dname = std::mem::MaybeUninit::uninit();
        wrap_err((*self.get_display_name)(
            self.cast(),
            SIGDN_FILESYSPATH,
            dname.as_mut_ptr(),
        ))?;
        let dname = dname.assume_init();

        let filename = read_to_string(dname);
        CoTaskMemFree(dname);

        Ok(filename)
    }
}

#[repr(C)]
struct IShellItemArrayV {
    base: IUnknownV,
    __bind_to_handler: usize,
    __get_property_store: usize,
    __get_property_description_list: usize,
    __get_attributes: usize,
    get_count: unsafe extern "system" fn(this: *mut c_void, num_items: *mut u32) -> HRESULT,
    get_item_at: unsafe extern "system" fn(
        this: *mut c_void,
        dwindex: u32,
        ppsi: *mut *mut IShellItem,
    ) -> HRESULT,
    __enum_items: usize,
}

type IShellItemArray = Interface<IShellItemArrayV>;

#[repr(C)]
struct IModalWindowV {
    base: IUnknownV,
    show: unsafe extern "system" fn(this: *mut c_void, owner: HWND) -> HRESULT,
}

type IModalWindow = Interface<IModalWindowV>;

/// <https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-ifiledialog>
#[repr(C)]
struct IFileDialogV {
    base: IModalWindowV,
    set_file_types: unsafe extern "system" fn(
        this: *mut c_void,
        count_filetypes: u32,
        filter_spec: *const COMDLG_FILTERSPEC,
    ) -> HRESULT,
    __set_file_type_index: usize,
    __get_file_type_index: usize,
    __advise: usize,
    __unadvise: usize,
    set_options:
        unsafe extern "system" fn(this: *mut c_void, options: FILEOPENDIALOGOPTIONS) -> HRESULT,
    __get_options: usize,
    __set_default_folder: usize,
    set_folder: unsafe extern "system" fn(
        this: *mut c_void,
        shell_item: Option<*mut IShellItem>,
    ) -> HRESULT,
    __get_folder: usize,
    __get_current_selection: usize,
    set_file_name: unsafe extern "system" fn(this: *mut c_void, name: PCWSTR) -> HRESULT,
    __get_file_name: usize,
    set_title: unsafe extern "system" fn(this: *mut c_void, title: PCWSTR) -> HRESULT,
    __set_ok_button_label: usize,
    __set_file_name_label: usize,
    get_result:
        unsafe extern "system" fn(this: *mut c_void, shell_item: *mut *mut IShellItem) -> HRESULT,
    __add_place: usize,
    set_default_extension:
        unsafe extern "system" fn(this: *mut c_void, default_ext: PCWSTR) -> HRESULT,
    __close: usize,
    __set_client_guid: usize,
    __clear_client_data: usize,
    __set_filter: usize,
}

type IFileDialog = Interface<IFileDialogV>;

/// <https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-ifileopendialog>
#[repr(C)]
struct IFileOpenDialogV {
    base: IFileDialogV,
    /// <https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileopendialog-getresults>
    get_results:
        unsafe extern "system" fn(this: *mut c_void, results: *mut *mut IShellItemArray) -> HRESULT,
    __get_selected_items: usize,
}

type IFileOpenDialog = Interface<IFileOpenDialogV>;

enum DialogInner {
    Open(*mut IFileOpenDialog),
    Save(*mut IFileDialog),
}

impl DialogInner {
    unsafe fn new(open: bool) -> Result<Self> {
        const FILE_OPEN_DIALOG_IID: GUID = GUID::from_u128(0xd57c7288_d4ad_4768_be02_9d969532d960);
        const FILE_SAVE_DIALOG_IID: GUID = GUID::from_u128(0x84bccd23_5fde_4cdb_aea4_af64b83d78ab);

        unsafe {
            let (cls_id, iid) = if open {
                (&FileOpenDialog, &FILE_OPEN_DIALOG_IID)
            } else {
                (&FileSaveDialog, &FILE_SAVE_DIALOG_IID)
            };

            let mut inner = std::mem::MaybeUninit::uninit();
            wrap_err(CoCreateInstance(
                cls_id,
                std::ptr::null_mut(),
                CLSCTX_INPROC_SERVER,
                iid,
                inner.as_mut_ptr(),
            ))?;

            let iptr = inner.assume_init();

            Ok(if open {
                Self::Open(iptr.cast())
            } else {
                Self::Save(iptr.cast())
            })
        }
    }

    #[inline]
    unsafe fn open() -> Result<Self> {
        unsafe { Self::new(true) }
    }

    #[inline]
    unsafe fn save() -> Result<Self> {
        unsafe { Self::new(false) }
    }

    #[inline]
    unsafe fn fd(&self) -> &mut IFileDialog {
        match self {
            Self::Save(s) => s,
            Self::Open(o) => unsafe { &mut (*o).base },
        }
    }

    #[inline]
    unsafe fn set_options(&self, opts: FILEOPENDIALOGOPTIONS) -> Result<()> {
        wrap_err(self.fd().set_options(self, opts))
    }

    #[inline]
    unsafe fn set_title(&self, title: &[u16]) -> Result<()> {
        wrap_err(self.fd().set_title(self, title.as_ptr()))
    }

    #[inline]
    unsafe fn set_default_extension(&self, extension: &[u16]) -> Result<()> {
        wrap_err(self.fd().set_default_extension(self, extension.as_ptr()))
    }

    #[inline]
    unsafe fn set_file_types(&self, specs: &[COMDLG_FILTERSPEC]) -> Result<()> {
        wrap_err(
            self.fd()
                .set_file_types(self, specs.len() as _, specs.as_ptr()),
        )
    }

    #[inline]
    unsafe fn set_filename(&self, fname: &[u16]) -> Result<()> {
        wrap_err(self.fd().set_file_name(self, fname.as_ptr()))
    }

    #[inline]
    unsafe fn set_folder(&self, folder: Option<&IShellItem>) -> Result<()> {
        wrap_err(self.fd().set_folder(self, folder.map(|si| si.cast())))
    }

    #[inline]
    unsafe fn show(&self, parent: Option<HWND>) -> Result<()> {
        wrap_err(self.fd().show(self, parent.unwrap_or_default()))
    }

    #[inline]
    unsafe fn get_result(&self) -> Result<PathBuf> {
        let mut res = std::mem::MaybeUninit::uninit();
        wrap_err(self.fd().get_result(self, res.as_mut_ptr()))?;
        let res = res.assume_init();
        (&*res).get_path();
    }

    #[inline]
    unsafe fn get_results(&self) -> Result<PathBuf> {
        let Self::Open(od) = self else { unreachable!() };

        let mut res = std::mem::MaybeUninit::uninit();
        wrap_err((*od).get_results(od, res.as_mut_ptr()))?;
        let items = res.assume_init();

        let count = items.GetCount()?;

        let mut paths = Vec::with_capacity(count as usize);
        for id in 0..count {
            let res_item = items.GetItemAt(id)?;

            let path = (&*res_item).get_path()?;
            paths.push(path);
        }

        Ok(paths)
    }
}

impl Drop for DialogInner {
    fn drop(&mut self) {
        let s = self.fd();

        s.base.base.release(s.cast());
    }
}

pub struct IDialog(DialogInner, Option<HWND>);

impl IDialog {
    fn new_open_dialog(opt: &FileDialog) -> Result<Self> {
        let dialog = DialogInner::open()?;

        let parent = match opt.parent {
            Some(RawWindowHandle::Win32(handle)) => Some(handle.hwnd as _),
            None => None,
            _ => unreachable!("unsupported window handle, expected: Windows"),
        };

        Ok(Self(dialog, parent))
    }

    fn new_save_dialog(opt: &FileDialog) -> Result<Self> {
        let dialog = DialogInner::save()?;

        let parent = match opt.parent {
            Some(RawWindowHandle::Win32(handle)) => Some(handle.hwnd as _),
            None => None,
            _ => unreachable!("unsupported window handle, expected: Windows"),
        };

        Ok(Self(dialog, parent))
    }

    fn add_filters(&self, filters: &[crate::file_dialog::Filter]) -> Result<()> {
        if let Some(first_filter) = filters.first() {
            if let Some(first_extension) = first_filter.extensions.first() {
                let extension: Vec<u16> = first_extension.encode_utf16().chain(Some(0)).collect();
                unsafe { self.0.set_default_extension(&extension)? }
            }
        }

        let mut f_list = {
            let mut f_list = Vec::new();

            for f in filters.iter() {
                let name: Vec<u16> = OsStr::new(&f.name).encode_wide().chain(once(0)).collect();
                let ext_string = f
                    .extensions
                    .iter()
                    .map(|item| format!("*.{}", item))
                    .collect::<Vec<_>>()
                    .join(";");

                let ext: Vec<u16> = OsStr::new(&ext_string)
                    .encode_wide()
                    .chain(once(0))
                    .collect();

                f_list.push((name, ext));
            }
            f_list
        };

        let spec: Vec<_> = f_list
            .iter_mut()
            .map(|(name, ext)| COMDLG_FILTERSPEC {
                pszName: name.as_ptr(),
                pszSpec: ext.as_ptr(),
            })
            .collect();

        unsafe {
            if !spec.is_empty() {
                self.0.set_file_types(&spec)?;
            }
        }
        Ok(())
    }

    fn set_path(&self, path: &Option<PathBuf>) -> Result<()> {
        const SHELL_ITEM_IID: GUID = GUID::from_u128(0x43826d1e_e718_42ee_bc55_a1e261c37bfe);

        let Some(path) = path.and_then(|p| p.to_str()) else { return Ok(()) };

        // Strip Win32 namespace prefix from the path
        let path = path.strip_prefix(r"\\?\").unwrap_or(path);

        let mut wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();

        unsafe {
            let mut item = std::mem::MaybeUninit::uninit();
            if wrap_err(SHCreateItemFromParsingName(
                wide_path.as_ptr(),
                std::ptr::null_mut(),
                &SHELL_ITEM_IID,
                item.as_mut_ptr(),
            ))
            .is_ok()
            {
                let item = item.assume_init();
                // For some reason SetDefaultFolder(), does not guarantees default path, so we use SetFolder
                self.0.set_folder(item.as_ref())?;
            }
        }

        Ok(())
    }

    fn set_file_name(&self, file_name: &Option<String>) -> Result<()> {
        if let Some(path) = file_name {
            let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();

            unsafe {
                self.0.set_filename(&wide_path)?;
            }
        }
        Ok(())
    }

    fn set_title(&self, title: &Option<String>) -> Result<()> {
        if let Some(title) = title {
            let wide_title: Vec<u16> = OsStr::new(title).encode_wide().chain(once(0)).collect();

            unsafe {
                self.0.set_title(&wide_title)?;
            }
        }
        Ok(())
    }

    pub fn get_results(&self) -> Result<Vec<PathBuf>> {
        unsafe { self.0.get_results() }
    }

    pub fn get_result(&self) -> Result<PathBuf> {
        unsafe { self.0.get_result() }
    }

    pub fn show(&self) -> Result<()> {
        unsafe { self.0.show(self.1) }
    }
}

impl IDialog {
    pub fn build_pick_file(opt: &FileDialog) -> Result<Self> {
        let dialog = IDialog::new_open_dialog(opt)?;

        dialog.add_filters(&opt.filters)?;
        dialog.set_path(&opt.starting_directory)?;
        dialog.set_file_name(&opt.file_name)?;
        dialog.set_title(&opt.title)?;

        Ok(dialog)
    }

    pub fn build_save_file(opt: &FileDialog) -> Result<Self> {
        let dialog = IDialog::new_save_dialog(opt)?;

        dialog.add_filters(&opt.filters)?;
        dialog.set_path(&opt.starting_directory)?;
        dialog.set_file_name(&opt.file_name)?;
        dialog.set_title(&opt.title)?;

        Ok(dialog)
    }

    pub fn build_pick_folder(opt: &FileDialog) -> Result<Self> {
        let dialog = IDialog::new_open_dialog(opt)?;

        dialog.set_path(&opt.starting_directory)?;
        dialog.set_title(&opt.title)?;

        unsafe {
            dialog.0.set_options(FOS_PICKFOLDERS)?;
        }

        Ok(dialog)
    }

    pub fn build_pick_folders(opt: &FileDialog) -> Result<Self> {
        let dialog = IDialog::new_open_dialog(opt)?;

        dialog.set_path(&opt.starting_directory)?;
        dialog.set_title(&opt.title)?;
        let opts = FOS_PICKFOLDERS | FOS_ALLOWMULTISELECT;

        unsafe {
            dialog.0.set_options(opts)?;
        }

        Ok(dialog)
    }

    pub fn build_pick_files(opt: &FileDialog) -> Result<Self> {
        let dialog = IDialog::new_open_dialog(opt)?;

        dialog.add_filters(&opt.filters)?;
        dialog.set_path(&opt.starting_directory)?;
        dialog.set_file_name(&opt.file_name)?;
        dialog.set_title(&opt.title)?;

        unsafe {
            dialog.0.set_options(FOS_ALLOWMULTISELECT)?;
        }

        Ok(dialog)
    }
}
