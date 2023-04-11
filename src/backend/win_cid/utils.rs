use windows_sys::{
    core::HRESULT,
    Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
    },
};

/// Makes sure that COM lib is initialized long enough
pub fn init_com<T, F: FnOnce() -> T>(f: F) -> Result<T, HRESULT> {
    let res = unsafe {
        CoInitializeEx(
            std::ptr::null(),
            COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE,
        )
    };

    if res < 0 {
        return Err(res);
    }

    let out = f();

    unsafe {
        CoUninitialize();
    }

    Ok(out)
}
