// sapcli-auht-plugin-sso - send an HTTPS request authenticated with a Windows-store client
// certificate (non-exportable private key supported) and print received cookies.
//
// Uses WinHTTP for the request and CryptoAPI to locate the cert. The private key
// stays in the CSP/KSP — we only hand WinHTTP the CERT_CONTEXT pointer, and
// SChannel does the TLS handshake using the key in place.
#![cfg(windows)]

use std::ptr;
use std::io::Read;
use std::ffi::c_void;
use std::collections::HashMap;
use std::ops::Deref;

use serde_json;
use serde::{Serialize, Deserialize};

//use clap::Parser;
use cookie::Cookie;
use chrono::{DateTime, Utc};
use anyhow::{anyhow, bail, Context, Result};


use windows::core::{PCWSTR};
use windows::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
use windows::Win32::Networking::WinHttp::*;
use windows::Win32::Security::Cryptography::*;

use windows::Win32::System::Diagnostics::Debug::{
    FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_HMODULE,
    FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, LoadLibraryW};
use windows::core::{w, PWSTR};

#[derive(Deserialize)]
struct SapcliPluginConnection {
    proto: String,
    ashost: String,
    port: String,
    client: String,
    #[serde(rename = "type")]
    conn_type: String,
    path: String,
    #[allow(unused)]
    sysnr: Option<String>,
    #[serde(rename = "verify")]
    verify_ssl: bool,
    #[allow(unused)]
    ssl_server_cert: Option<String>,
}

type SapcliPluginParameters = HashMap<String, String>;

#[derive(Deserialize)]
struct SapcliPluginRequest {
    connection: SapcliPluginConnection,
    #[allow(unused)]
    parameters: SapcliPluginParameters,
}

#[derive(Serialize, Deserialize)]
struct SapcliCookie {
    name: String,
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secure: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct SapcliCookiePluginContent     {
    #[serde(rename = "type")]
    plugin_type: String,
    cookies: Vec<SapcliCookie>,
}

#[derive(Serialize, Deserialize)]
struct SapcliCookiePluginResponse {
    message: String,
    expiration: String,
    content: SapcliCookiePluginContent,
}

// Convert a Rust &str into a NUL-terminated UTF-16 Vec<u16>.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// RAII wrapper for CERT_CONTEXT. Freed with CertFreeCertificateContext.
struct CertCtx(*const CERT_CONTEXT);

impl Drop for CertCtx {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = CertFreeCertificateContext(Some(self.0));
            }
        }
    }
}

/// RAII wrapper for an HCERTSTORE.
struct CertStore(HCERTSTORE);

impl Drop for CertStore {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CertCloseStore(Some(self.0), 0);
            }
        }
    }
}

/// RAII wrapper for WinHTTP handles (HINTERNET).
struct WinHttpHandle(*mut c_void);

impl Drop for WinHttpHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = WinHttpCloseHandle(self.0);
            }
        }
    }
}


/// Wraps CertNameToStrW with the X.500 format that matches win32crypt.CertNameToStr's default.
unsafe fn cert_name_to_string(blob: &CRYPT_INTEGER_BLOB) -> Result<String> {
    // First call with null buffer to get required size (in WCHARs, including NUL).
    unsafe {
        let needed = CertNameToStrW(
            CERT_QUERY_ENCODING_TYPE(0x00010001), // X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
            blob as *const _,
            CERT_X500_NAME_STR,
            None,
        );
        if needed <= 1 {
            return Ok(String::new());
        }
        let mut buf = vec![0u16; needed as usize];
        let written = CertNameToStrW(
            CERT_QUERY_ENCODING_TYPE(0x00010001),
            blob as *const _,
            CERT_X500_NAME_STR,
            Some(&mut buf),
        );
        // Strip trailing NUL.
        let len = (written as usize).saturating_sub(1);
        Ok(String::from_utf16_lossy(&buf[..len]))
    }
}


/// Open the personal ("MY") certificate store and locate a cert whose subject
/// contains the given substring (case-insensitive, matches what certmgr shows).
fn find_cert(subject_substr: &str) -> Result<(CertStore, CertCtx)> {
    let store_flags = CERT_SYSTEM_STORE_CURRENT_USER_ID;

    let store_name = wide("MY");
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE(0),
            Some(HCRYPTPROV_LEGACY(0)),
            CERT_OPEN_STORE_FLAGS(store_flags << CERT_SYSTEM_STORE_LOCATION_SHIFT)
                | CERT_STORE_OPEN_EXISTING_FLAG
                | CERT_STORE_READONLY_FLAG,
            Some(store_name.as_ptr() as *const _),
        )
    }
    .context("CertOpenStore(MY) failed")?;

    let store = CertStore(store);

    let mut ctx: *mut CERT_CONTEXT = ptr::null_mut();
    if subject_substr.is_empty() {
        ctx = unsafe {
            CertEnumCertificatesInStore(store.0, Some(ctx))
        } as *mut CERT_CONTEXT;

        if ctx.is_null() {
            bail!("No certificates found in {} \\MY", "CurrentUser");
        }
    } else {
        // CERT_FIND_SUBJECT_STR_W performs a case-insensitive substring match
        // against the subject's CN — exactly the "display name" you see in certmgr.
        let needle = wide(subject_substr);
        ctx = unsafe {
            CertFindCertificateInStore(
                store.0,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_STR_W,
                Some(needle.as_ptr() as *const c_void),
                None,
            )
        };

        if ctx.is_null() {
            bail!(
                "No certificate in {} \\MY whose subject contains \"{}\"",
                "CurrentUser", subject_substr
            );
        }
    }

    let found_subject = unsafe { cert_name_to_string(&(*ctx).pCertInfo.read().Subject) }?;
    eprintln!("matched cert subject: {found_subject:?}");

    Ok((store, CertCtx(ctx)))
}

fn winhttp_error_message(code: u32) -> String {
    // winhttp.dll is loaded as soon as you call any WinHttp* function,
    // but be defensive in case this is called from an unusual context.
    let module = unsafe {
        let h = GetModuleHandleW(w!("winhttp.dll")).ok();
        match h {
            Some(h) if !h.is_invalid() => h,
            _ => match LoadLibraryW(w!("winhttp.dll")) {
                Ok(h) => h,
                Err(_) => return format!("WinHTTP error {code} (winhttp.dll not loadable)"),
            },
        }
    };

    let mut buf_ptr: PWSTR = PWSTR::null();
    let len = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_FROM_HMODULE
                | FORMAT_MESSAGE_FROM_SYSTEM
                | FORMAT_MESSAGE_IGNORE_INSERTS,
            Some(module.0 as *const _),
            code,
            0, // default language
            // ALLOCATE_BUFFER mode: pass &mut PWSTR cast to PWSTR
            PWSTR(&mut buf_ptr as *mut PWSTR as *mut u16),
            0,
            None,
        )
    };

    if len == 0 || buf_ptr.is_null() {
        return format!("WinHTTP error {code} (no message)");
    }

    let slice = unsafe { std::slice::from_raw_parts(buf_ptr.0, len as usize) };
    let msg = String::from_utf16_lossy(slice).trim().to_string();
    // TODO: Free the allocated buffer
    format!("WinHTTP error {code}: {msg}")
}

fn get_cookies(client_subject: &str, client_url: &str, method: &str, verify_ssl: bool, auth: String) -> Result<Vec<String>> {
    // 1. Locate the cert.
    let (_store, cert) = find_cert(client_subject)?;

    // 2. Crack the URL into components.
    let url_w = wide(client_url);
    let mut comps = URL_COMPONENTS {
        dwStructSize: std::mem::size_of::<URL_COMPONENTS>() as u32,
        // Setting dwXxxLength = u32::MAX with a null pointer tells WinHttpCrackUrl
        // to fill in pointers + lengths into the original url_w buffer (no copies).
        dwSchemeLength: u32::MAX,
        dwHostNameLength: u32::MAX,
        dwUrlPathLength: u32::MAX,
        dwExtraInfoLength: u32::MAX,
        ..Default::default()
    };
    unsafe {
        WinHttpCrackUrl(&url_w, 0, &mut comps).context("WinHttpCrackUrl failed")?;
    }

    if comps.nScheme != WINHTTP_INTERNET_SCHEME_HTTPS {
        bail!("Only HTTPS URLs are supported (client-cert auth requires TLS)");
    }

    let host = unsafe {
        std::slice::from_raw_parts(comps.lpszHostName.0, comps.dwHostNameLength as usize)
    };
    let mut host_z: Vec<u16> = host.to_vec();
    host_z.push(0);

    // path + extra (query string) concatenated; WinHttpOpenRequest wants the
    // object name including query.
    let path_len = comps.dwUrlPathLength as usize + comps.dwExtraInfoLength as usize;
    let mut path_z: Vec<u16> = if path_len == 0 {
        wide("/")
    } else {
        let p = unsafe {
            std::slice::from_raw_parts(comps.lpszUrlPath.0, path_len)
        };
        let mut v = p.to_vec();
        v.push(0);
        v
    };

    let method_w = wide(method.to_uppercase().deref());

    // 3. Session → Connection → Request.
    let session = unsafe {
        WinHttpOpen(
            PCWSTR(wide("wincertauth/0.1").as_ptr()),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        )
    };
    if session.is_null() {
        bail!("WinHttpOpen failed: {:?}", unsafe { GetLastError() });
    }
    let session = WinHttpHandle(session);

    let conn = unsafe {
        WinHttpConnect(session.0, PCWSTR(host_z.as_ptr()), comps.nPort, 0)
    };
    if conn.is_null() {
        bail!("WinHttpConnect failed: {:?}", unsafe { GetLastError() });
    }
    let conn = WinHttpHandle(conn);

    let req = unsafe {
        WinHttpOpenRequest(
            conn.0,
            PCWSTR(method_w.as_ptr()),
            PCWSTR(path_z.as_mut_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            ptr::null(),
            WINHTTP_FLAG_SECURE | WINHTTP_FLAG_REFRESH,
        )
    };
    if req.is_null() {
        bail!("WinHttpOpenRequest failed: {:?}", unsafe { GetLastError() });
    }
    let req = WinHttpHandle(req);

    // 4. Bind the client cert to the request.
    //
    // The server *might* not actually ask for a client cert until after we send
    // the first time, in which case WinHttpSendRequest returns
    // ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED and we'd set the option then and
    // retry. Setting it up front is simpler and always works when we already
    // know we want to authenticate.
    //
    // WinHTTP duplicates the CERT_CONTEXT internally, so it's safe to let our
    // RAII wrapper free the original when we return.
    let cert_ptr = cert.0 as *const c_void;
    let cert_slice = unsafe {
        std::slice::from_raw_parts(
            cert_ptr as *const u8,
            std::mem::size_of::<CERT_CONTEXT>(),
        )
    }; 

    unsafe {
        WinHttpSetOption(
            Some(req.0),
            WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
            Some(cert_slice),
        )
        .context("WinHttpSetOption(CLIENT_CERT_CONTEXT) failed")?;
    }

    if !verify_ssl {
        //let flags: u32 = WINHTTP_FLAG_SECURE_DEFAULTS | WINHTTP_FEATURE_SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
        let flags: u32 = SECURITY_FLAG_IGNORE_UNKNOWN_CA
            | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
            | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
            | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        unsafe {
            WinHttpSetOption(
                Some(req.0),
                WINHTTP_OPTION_SECURITY_FLAGS,
                Some(std::slice::from_raw_parts(
                    &flags as *const u32 as *const u8,
                    std::mem::size_of::<u32>(),
                )),
            )
            .context("WinHttpSetOption(SECURITY_FLAGS) failed")?;
        }
    }

    if !auth.is_empty() {
        eprintln!("Adding Authorization header: {}", auth);
        let header = format!("Authorization: {}", auth);
        let header_w: Vec<u16> = header.encode_utf16().collect(); // no NUL

        unsafe {
            WinHttpAddRequestHeaders(
                req.0,
                &header_w,                    // slice; length is taken from the slice
                WINHTTP_ADDREQ_FLAG_ADD,
            )
            .context("WinHttpAddRequestHeaders failed")?;
        }
    }

    // 5. Send + receive.
    match unsafe {
        WinHttpSendRequest(
            req.0,
            None,         // additional headers
            None,         // optional body
            0,            // optional body length
            0,            // total length
            0,            // context value
        )
    } {
        Ok(_) => {}
        Err(_) => {
            let code = unsafe { GetLastError().0 };
            let msg = winhttp_error_message(code);
            bail!("WinHttpSendRequest failed: {}", msg);
        }
    }

    unsafe {
        WinHttpReceiveResponse(req.0, ptr::null_mut())
            .context("WinHttpReceiveResponse failed")?;
    }

    // 6. Pull all Set-Cookie headers.
    let cookies = read_cookies(req.0)?;

    Ok(cookies)
}

/// Query every Set-Cookie header on the response and print one per line.
/// We use WINHTTP_QUERY_FLAG_NUMBER? No — we need the raw header value.
/// Index starts at 0 and we increment until WinHttpQueryHeaders fails with
/// ERROR_WINHTTP_HEADER_NOT_FOUND (12150).
fn read_cookies(req: *mut c_void) -> Result<Vec<String>> {
    const ERROR_WINHTTP_HEADER_NOT_FOUND: u32 = 12150;

    let mut index: u32 = 0;
    let mut any = false;

    let mut cookies : Vec<String> = Vec::new();
    loop {
        // First call with null buffer to get required size.
        let mut size: u32 = 0;
        let ok = unsafe {
            WinHttpQueryHeaders(
                req,
                WINHTTP_QUERY_SET_COOKIE,
                PCWSTR::null(),
                None,
                &mut size,
                &mut index,
            )
        };

        if ok.is_err() {
            let err = unsafe { GetLastError() };
            if err.0 == ERROR_WINHTTP_HEADER_NOT_FOUND {
                break; // no more cookies
            }
            if err != ERROR_INSUFFICIENT_BUFFER {
                return Err(anyhow!(
                    "WinHttpQueryHeaders sizing call failed: {:?}",
                    err
                ));
            }
        }

        // size is in BYTES, including the terminating NUL.
        let wchars = (size as usize) / 2;
        let mut buf: Vec<u16> = vec![0u16; wchars];

        unsafe {
            WinHttpQueryHeaders(
                req,
                WINHTTP_QUERY_SET_COOKIE,
                PCWSTR::null(),
                Some(buf.as_mut_ptr() as *mut c_void),
                &mut size,
                &mut index,
            )
            .context("WinHttpQueryHeaders data call failed")?;
        }

        // Trim NUL terminator(s).
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let cookie = String::from_utf16_lossy(&buf[..end]);
        eprintln!("Got Set-Cookie header: {}", cookie);
        cookies.push(cookie);
        any = true;
    }

    if !any {
        eprintln!("(no Set-Cookie headers in response)");
    }
    Ok(cookies)
}

async fn handle_request(request: SapcliPluginRequest) -> Result<SapcliCookiePluginResponse, Box<dyn std::error::Error>> {
    let url = format!("{}://{}:{}{}?sap-client={}", request.connection.proto, request.connection.ashost, request.connection.port, request.connection.path, request.connection.client);

    let method = match request.connection.conn_type.as_str() {
        "adt" => "GET",
        "rest" => "HEAD",
        _ => return Err("Unsupported connection type".into()),
    };

    let auth = request.parameters.get("auth").cloned().unwrap_or_default();
    let subject = request.parameters.get("cert_subject").cloned().unwrap_or_default();

    let fetched_cookies = get_cookies(subject.deref(), &url, &method, request.connection.verify_ssl, auth)?;

    let format = time::format_description::parse(
        "[year]-[month]-[day] [hour]:[minute]:[second] [offset_hour \
            sign:mandatory]:[offset_minute]:[offset_second]",
    )?;

    let cookies = fetched_cookies.into_iter().map(|cookie_line| { let cookie = Cookie::parse_encoded(cookie_line.as_str()).unwrap();
       SapcliCookie {
            name: cookie.name().to_string(),
            value: cookie.value().to_string(),
            domain: cookie.domain().map(String::from),
            path: cookie.path().map(String::from),
            expires: cookie.expires_datetime().map(|e| e.format(&format).unwrap()),
            secure: cookie.secure(),
        }
    }).collect::<Vec<SapcliCookie>>();

    let content = SapcliCookiePluginContent {
        plugin_type: "cookie".to_string(),
        cookies: cookies,
    };

    // TODO: Determine the actual expiration time based on the cookies or set a default expiration time
    // Now + 1 hour to ISO 8601
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let expiration = now + 3600; 
    let expiration: DateTime<Utc> = DateTime::from(std::time::UNIX_EPOCH + std::time::Duration::from_secs(expiration));

    let response = SapcliCookiePluginResponse {
        message: "Request handled successfully".to_string(),
        expiration: expiration.to_rfc3339(),
        content,
    };

    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read the request from stdin
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;

    // Stderr is used for logging
    eprintln!("Received request: {}", buffer);

    let request: SapcliPluginRequest = serde_json::from_str(&buffer)?;
    let response = handle_request(request).await?;
    // Write the response to stdout
    let response_json = serde_json::to_string(&response)?;
    println!("{}", response_json);
    Ok(())
}