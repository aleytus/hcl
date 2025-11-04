local ffi = require("ffi")
local bindings = require("bindings")
local C = bindings.crypto
local SSL = bindings.ssl
local ffi_gc = ffi.gc
local lfs = require("lfs")

local M = {}

local CERT_VALID_DAYS = 365
local CA_KEY_SIZE = 2048
local SERVER_KEY_SIZE = 2048

local server_ctx_cache = setmetatable({}, {__mode = "v"})

local function ossl_error()
    local err_str = ""
    while true do
        local e = C.ERR_get_error()
        if e == 0 then break end
        local buf = ffi.new("char[256]")
        C.ERR_error_string(e, buf)
        err_str = err_str .. ffi.string(buf) .. " | "
    end
    if #err_str == 0 then return "Unknown OpenSSL error" end
    return err_str:sub(1, -4)
end

local function bio_to_string(bio)
    local buf_size = 4096
    local buf = ffi.new("char[?]", buf_size)
    local chunks = {}
    while true do
        local len_read = C.BIO_read(bio, buf, buf_size)
        if len_read > 0 then
            table.insert(chunks, ffi.string(buf, len_read))
        else
            break
        end
    end
    
    if #chunks == 0 then
        return nil, "bio_to_string read 0 bytes"
    end
    
    return table.concat(chunks)
end

function M.pkey_to_pem(pkey)
    local bio = ffi_gc(C.BIO_new(C.BIO_s_mem()), C.BIO_free_all)
    if C.PEM_write_bio_PKCS8PrivateKey(bio, pkey, ffi.NULL, ffi.NULL, 0, ffi.NULL, ffi.NULL) ~= 1 then
        return nil, "PEM_write_bio_PKCS8PrivateKey failed: " .. ossl_error()
    end
    local pem_str, err = bio_to_string(bio)
    if not pem_str then
        return nil, "bio_to_string failed (pkey): " .. (err or ossl_error())
    end
    return pem_str
end

function M.cert_to_pem(cert)
    local bio = ffi_gc(C.BIO_new(C.BIO_s_mem()), C.BIO_free_all)
    if C.PEM_write_bio_X509(bio, cert) ~= 1 then
        return nil, "PEM_write_bio_X509 failed: " .. ossl_error()
    end
    local pem_str, err = bio_to_string(bio)
    if not pem_str then
        return nil, "bio_to_string failed (cert): " .. (err or ossl_error())
    end
    return pem_str
end

function M.pem_to_pkey(pem)
    local bio = ffi_gc(C.BIO_new(C.BIO_s_mem()), C.BIO_free_all)
    C.BIO_write(bio, pem, #pem)
    local pkey = C.PEM_read_bio_PrivateKey(bio, ffi.NULL, ffi.NULL, ffi.NULL)
    if pkey == ffi.NULL then return nil, "PEM_read_bio_PrivateKey failed: " .. ossl_error() end
    return ffi_gc(pkey, C.EVP_PKEY_free)
end

function M.pem_to_cert(pem)
    local bio = ffi_gc(C.BIO_new(C.BIO_s_mem()), C.BIO_free_all)
    C.BIO_write(bio, pem, #pem)
    local cert = C.PEM_read_bio_X509(bio, ffi.NULL, ffi.NULL, ffi.NULL)
    if cert == ffi.NULL then return nil, "PEM_read_bio_X509 failed: " .. ossl_error() end
    return ffi_gc(cert, C.X509_free)
end

local function load_key(filename)
    local f = io.open(filename, "rb")
    if not f then return nil end
    local data = f:read("*a")
    f:close()
    if not data then return nil end
    return M.pem_to_pkey(data)
end

local function load_cert(filename)
    local f = io.open(filename, "rb")
    if not f then return nil end
    local data = f:read("*a")
    f:close()
    if not data then return nil end
    return M.pem_to_cert(data)
end

local function save_file(filename, data)
    local f, err = io.open(filename, "wb")
    if not f then return nil, "Failed to write file " .. filename .. ": " .. (err or "") end
    f:write(data)
    f:close()
    return true
end

local function generate_rsa_key(bits)
    local pkey_ptr = ffi.new("EVP_PKEY*[1]")
    local ctx = ffi_gc(C.EVP_PKEY_CTX_new_id(bindings.EVP_PKEY_RSA, ffi.NULL), C.EVP_PKEY_CTX_free)
    if ctx == ffi.NULL then
        return nil, "EVP_PKEY_CTX_new_id failed: " .. ossl_error()
    end

    if C.EVP_PKEY_keygen_init(ctx) <= 0 then
        return nil, "EVP_PKEY_keygen_init failed: " .. ossl_error()
    end

    if C.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0 then
        return nil, "EVP_PKEY_CTX_set_rsa_keygen_bits failed: " .. ossl_error()
    end

    if C.EVP_PKEY_keygen(ctx, pkey_ptr) <= 0 then
        return nil, "EVP_PKEY_keygen failed: " .. ossl_error()
    end

    return ffi_gc(pkey_ptr[0], C.EVP_PKEY_free)
end


local function add_ext(x509_ctx, cert, nid, value)
    local ex = C.X509V3_EXT_conf_nid(ffi.NULL, x509_ctx, nid, value)
    if ex == ffi.NULL then
        return nil, "X509V3_EXT_conf_nid failed for nid " .. nid
    end
    C.X509_add_ext(cert, ex, -1)
    C.X509_EXTENSION_free(ex)
    return true
end

local function sign_x509_certificate(host, ca_key, ca_cert)
    local pkey, pkey_err = generate_rsa_key(SERVER_KEY_SIZE)
    if not pkey then return nil, nil, "Server key gen error: " .. pkey_err end
    
    local cert = ffi_gc(C.X509_new(), C.X509_free)
    C.X509_set_version(cert, 2)
    
    C.ASN1_INTEGER_set(C.X509_get_serialNumber(cert), math.floor(os.time() * 1000 + math.random(1000)))
    
    C.X509_gmtime_adj(C.X509_getm_notBefore(cert), -3600 * 24)
    C.X509_gmtime_adj(C.X509_getm_notAfter(cert), 3600 * 24 * CERT_VALID_DAYS)
    
    C.X509_set_pubkey(cert, pkey)
    
    local subject_name = C.X509_get_subject_name(cert)
    C.X509_NAME_add_entry_by_txt(subject_name, "CN", bindings.MBSTRING_ASC, host, -1, -1, 0)
    
    C.X509_set_issuer_name(cert, C.X509_get_subject_name(ca_cert))
    
    local v3_ctx_data = ffi.new("X509V3_CTX")
    C.X509V3_set_ctx(v3_ctx_data, ca_cert, cert, ffi.NULL, ffi.NULL, 0)
    C.X509V3_set_ctx_nodb(v3_ctx_data)
    
    add_ext(v3_ctx_data, cert, bindings.NID_subject_alt_name, "DNS:" .. host)

    if C.X509_sign(cert, ca_key, C.EVP_sha256()) == 0 then
        return nil, nil, "X509_sign failed: " .. ossl_error()
    end
    
    return pkey, cert, nil
end

function M.load_or_generate_ca(key_path, cert_path)
    local pkey, err_pkey = load_key(key_path)
    local cert, err_cert = load_cert(cert_path)
    
    if pkey and cert then
        return { key = pkey, cert = cert }
    end
    
    print("Generating new CA certificate...")
    local pkey_err
    pkey, pkey_err = generate_rsa_key(CA_KEY_SIZE)
    if not pkey then return nil, "CA key gen error: " .. pkey_err end
    
    cert = ffi_gc(C.X509_new(), C.X509_free)
    C.X509_set_version(cert, 2)
    C.ASN1_INTEGER_set(C.X509_get_serialNumber(cert), 1)
    C.X509_gmtime_adj(C.X509_getm_notBefore(cert), 0)
    C.X509_gmtime_adj(C.X509_getm_notAfter(cert), 3600 * 24 * CERT_VALID_DAYS * 10)
    C.X509_set_pubkey(cert, pkey)
    
    local name = C.X509_get_subject_name(cert)
    C.X509_NAME_add_entry_by_txt(name, "CN", bindings.MBSTRING_ASC, "HandyCache Root CA", -1, -1, 0)
    C.X509_set_issuer_name(cert, name)

    if C.X509_sign(cert, pkey, C.EVP_sha256()) == 0 then
        return nil, "CA self-sign failed: " .. ossl_error()
    end
    
    local key_pem, key_pem_err = M.pkey_to_pem(pkey)
    if not key_pem then return nil, key_pem_err end
    
    local cert_pem, cert_pem_err = M.cert_to_pem(cert)
    if not cert_pem then return nil, cert_pem_err end
    
    save_file(key_path, key_pem)
    save_file(cert_path, cert_pem)
    
    print("New CA generated and saved to " .. key_path .. " and " .. cert_path)
    
    return { key = pkey, cert = cert }
end

function M.get_server_ctx(host, ca_key, ca_cert)
    if server_ctx_cache[host] then
        return server_ctx_cache[host]
    end

    local certs_dir = "certs/"
    local key_file = certs_dir .. host .. ".key"
    local cert_file = certs_dir .. host .. ".crt"
    
    local pkey = load_key(key_file)
    local cert = load_cert(cert_file)

    if not pkey or not cert then
        local err
        pkey, cert, err = sign_x509_certificate(host, ca_key, ca_cert)
        if not pkey or not cert then
            return nil, "Failed to sign certificate: " .. (err or "")
        end
        
        local key_pem, key_err = M.pkey_to_pem(pkey)
        local cert_pem, cert_err = M.cert_to_pem(cert)
        
        if key_pem then save_file(key_file, key_pem) end
        if cert_pem then save_file(cert_file, cert_pem) end
    end

    local ctx = ffi_gc(SSL.SSL_CTX_new(C.TLS_server_method()), SSL.SSL_CTX_free)
    SSL.SSL_CTX_ctrl(ctx, bindings.SSL_CTRL_SET_READ_AHEAD, 1, ffi.NULL)

    if SSL.SSL_CTX_use_certificate(ctx, cert) ~= 1 then
        return nil, "SSL_CTX_use_certificate failed: " .. ossl_error()
    end
    if SSL.SSL_CTX_use_PrivateKey(ctx, pkey) ~= 1 then
        return nil, "SSL_CTX_use_PrivateKey failed: " .. ossl_error()
    end
    if SSL.SSL_CTX_check_private_key(ctx) ~= 1 then
        return nil, "SSL_CTX_check_private_key failed: " .. ossl_error()
    end

    local alpn_protos = ffi.new("unsigned char[]", "\x02h2\x08http/1.1")
    SSL.SSL_CTX_set_alpn_protos(ctx, alpn_protos, #alpn_protos)
    
    server_ctx_cache[host] = ctx
    return ctx
end

function M.create_client_ctx(use_h2)
    local ctx = ffi_gc(SSL.SSL_CTX_new(C.TLS_client_method()), SSL.SSL_CTX_free)
    SSL.SSL_CTX_ctrl(ctx, bindings.SSL_CTRL_SET_READ_AHEAD, 1, ffi.NULL)
    
    if use_h2 then
        local alpn_protos = ffi.new("unsigned char[]", "\x02h2\x08http/1.1")
        SSL.SSL_CTX_set_alpn_protos(ctx, alpn_protos, #alpn_protos)
    end
    
    return ctx
end

return M