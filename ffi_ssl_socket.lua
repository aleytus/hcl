local ffi = require("ffi")
local socket = require("socket.core")
local bindings = require("bindings")
local C = bindings.crypto
local SSL = bindings.ssl

local M = {}
M.__index = M

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

function M:new(sock, ctx, is_server)
    local ssl_ptr = SSL.SSL_new(ctx)
    if ssl_ptr == nil then
        return nil, "SSL_new failed: " .. ossl_error()
    end
    
    local fd = sock:getfd()
    if SSL.SSL_set_fd(ssl_ptr, fd) ~= 1 then
        SSL.SSL_free(ssl_ptr)
        return nil, "SSL_set_fd failed: " .. ossl_error()
    end
    
    if is_server then
        SSL.SSL_set_accept_state(ssl_ptr)
    else
        SSL.SSL_set_connect_state(ssl_ptr)
    end

    local self = setmetatable({
        sock = sock,
        ssl = ffi.gc(ssl_ptr, SSL.SSL_free),
        timeout = 10,
        is_server = is_server
    }, M)
    
    return self
end

function M:get_sock()
    return self.sock
end

function M:settimeout(timeout)
    self.timeout = timeout
    self.sock:settimeout(timeout)
end

local function handle_want_io(self, err_code, sock_err)
    if err_code == bindings.SSL_ERROR_WANT_READ then
        local r, _, e = socket.select({self.sock}, nil, self.timeout)
        if not r or #r == 0 then
            return nil, e or "timeout"
        end
        return true
    elseif err_code == bindings.SSL_ERROR_WANT_WRITE then
        local _, w, e = socket.select(nil, {self.sock}, self.timeout)
        if not w or #w == 0 then
            return nil, e or "timeout"
        end
        return true
    else
        return nil, sock_err or "ssl_error: " .. ossl_error()
    end
end

function M:connect()
    while true do
        local ret = SSL.SSL_connect(self.ssl)
        
        if ret == 1 then
            return true
        elseif ret == 0 then
            return nil, "closed"
        else
            local err = SSL.SSL_get_error(self.ssl, ret)
            local ok, err_io = handle_want_io(self, err)
            if not ok then return nil, err_io end
        end
    end
end

function M:accept()
    while true do
        local ret = SSL.SSL_accept(self.ssl)
        
        if ret == 1 then
            return true
        elseif ret == 0 then
            return nil, "closed"
        else
            local err = SSL.SSL_get_error(self.ssl, ret)
            local ok, err_io = handle_want_io(self, err)
            if not ok then return nil, err_io end
        end
    end
end

function M:handshake()
    if self.is_server then
        return self:accept()
    else
        return self:connect()
    end
end

function M:read(pattern)
    if pattern == "*a" then
        local chunks = {}
        while true do
            local data, err = self:read(4096)
            if data then
                table.insert(chunks, data)
            elseif err == "closed" or err == "timeout" then
                break
            else
                return nil, err
            end
            if #data < 4096 then break end
        end
        return table.concat(chunks)
    end
    
    local size = tonumber(pattern) or 4096
    local buf = ffi.new("uint8_t[?]", size)
    
    while true do
        local ret = SSL.SSL_read(self.ssl, buf, size)
        
        if ret > 0 then
            return ffi.string(buf, ret)
        elseif ret == 0 then
            return nil, "closed"
        else
            local err = SSL.SSL_get_error(self.ssl, ret)
            local ok, err_io = handle_want_io(self, err)
            if not ok then return nil, err_io end
        end
    end
end

function M:read_nonblock(size)
    local buf = ffi.new("uint8_t[?]", size)
    
    local ret = SSL.SSL_read(self.ssl, buf, size)
    
    if ret > 0 then
        return ffi.string(buf, ret)
    elseif ret == 0 then
        return nil, "closed"
    else
        local err = SSL.SSL_get_error(self.ssl, ret)
        
        if err == bindings.SSL_ERROR_WANT_READ then
            return nil, "want_read"
        elseif err == bindings.SSL_ERROR_WANT_WRITE then
            return nil, "want_write"
        else
            return nil, "ssl_error: " .. ossl_error()
        end
    end
end

function M:write(data)
    local written = 0
    local total = #data
    local c_data = ffi.new("uint8_t[?]", total)
    ffi.copy(c_data, data)
    
    while written < total do
        local ret = SSL.SSL_write(self.ssl, c_data + written, total - written)
        
        if ret > 0 then
            written = written + ret
        elseif ret == 0 then
            return nil, "closed"
        else
            local err = SSL.SSL_get_error(self.ssl, ret)
            local ok, err_io = handle_want_io(self, err)
            if not ok then return nil, err_io end
        end
    end
    return true
end

function M:write_nonblock(data, length)
    local written = 0
    local total = length
    
    while written < total do
        local ret = SSL.SSL_write(self.ssl, data + written, total - written)
        
        if ret > 0 then
            written = written + ret
        elseif ret == 0 then
            return nil, "closed"
        else
            local err = SSL.SSL_get_error(self.ssl, ret)
            
            if err == bindings.SSL_ERROR_WANT_WRITE then
                return nil, "want_write"
            elseif err == bindings.SSL_ERROR_WANT_READ then
                return nil, "want_read"
            else
                return nil, "ssl_error: " .. ossl_error()
            end
        end
    end
    return true
end

function M:get_alpn_selected()
    local data_ptr = ffi.new("const unsigned char*[1]")
    local len_ptr = ffi.new("unsigned int[1]")
    
    SSL.SSL_get0_alpn_selected(self.ssl, data_ptr, len_ptr)
    
    if data_ptr[0] ~= nil and len_ptr[0] > 0 then
        return ffi.string(data_ptr[0], len_ptr[0])
    end
    return nil
end

function M:close()
    if self.ssl then
        SSL.SSL_shutdown(self.ssl)
        self.ssl = nil
    end
    if self.sock then
        self.sock:close()
        self.sock = nil
    end
end

return M