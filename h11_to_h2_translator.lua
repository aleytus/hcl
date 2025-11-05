local ffi = require("ffi")
local ffi_gc = ffi.gc
local bindings = require("bindings")
local C = bindings.crypto
local NGHTTP2 = bindings.nghttp2
local SSL = bindings.ssl
local socket = require("socket.core")
local HTTP_PARSER = require("http_parser")
local CACHE_LOGIC = require("cache_logic")

local M = {}
M.__index = M

local TIMEOUT = 10
local bit_bor = bit.bor

ffi.cdef[[
typedef void FFI_SSL_Socket;

typedef struct {
    void *handler;
    void *client_ssl;
    void *remote_ssl;
    char *host;
} nghttp2_session_data;

typedef struct {
    int32_t stream_id;
    int32_t remote_stream_id;
    void *session_data;
    bool response_headers_sent;
} nghttp2_stream_data;
]]

local function c_send_callback(session, data, length, flags, user_data)
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local ssl_sock = ffi.cast("FFI_SSL_Socket", session_data.remote_ssl)
    local ok, err = ssl_sock:write_nonblock(data, length)
    if ok then return length end
    if err == "want_read" or err == "want_write" then return bindings.NGHTTP2_ERR_WOULDBLOCK end
    return bindings.NGHTTP2_ERR_CALLBACK_FAILURE
end

local function c_recv_callback(session, buf, length, flags, user_data)
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local ssl_sock = ffi.cast("FFI_SSL_Socket", session_data.remote_ssl)
    local data, err = ssl_sock:read_nonblock(length)
    if data then
        ffi.copy(buf, data, #data)
        return #data
    end
    if err == "want_read" or err == "want_write" then return bindings.NGHTTP2_ERR_WOULDBLOCK end
    return bindings.NGHTTP2_ERR_CALLBACK_FAILURE
end

local function get_stream_data(handler, stream_id)
    local stream = handler.streams[stream_id]
    if not stream then
        local cdata = ffi_gc(ffi.new("nghttp2_stream_data"), function(s) end)
        cdata.stream_id = stream_id
        cdata.session_data = ffi.NULL
        cdata.remote_stream_id = 0
        cdata.response_headers_sent = false
        stream = { cdata = cdata, lua_headers = {} }
        handler.streams[stream_id] = stream
    end
    return stream
end

local function c_on_begin_headers_callback(session, frame, user_data)
    if frame.hd.type ~= 1 then return 0 end
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local handler = ffi.from_handle(session_data.handler)
    local stream = get_stream_data(handler, frame.hd.stream_id)
    stream.lua_headers = {}
    return 0
end

local function c_on_header_callback(session, frame, name, namelen, value, valuelen, flags, user_data)
    if frame.hd.type ~= 1 then return 0 end
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local handler = ffi.from_handle(session_data.handler)
    local stream = get_stream_data(handler, frame.hd.stream_id)
    table.insert(stream.lua_headers, ffi.string(name, namelen))
    table.insert(stream.lua_headers, ffi.string(value, valuelen))
    return 0
end

local function c_on_frame_recv_callback(session, frame, user_data)
    local stream_id = frame.hd.stream_id
    if stream_id == 0 or frame.hd.type ~= 1 then return 0 end

    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local handler = ffi.from_handle(session_data.handler)
    local stream = get_stream_data(handler, stream_id)
    local cdata = stream.cdata
    local client_ssl = ffi.cast("FFI_SSL_Socket", session_data.client_ssl)
    
    local status_code, h11_headers = HTTP_PARSER.h2_headers_to_h11_response(stream.lua_headers)
    local h11_response = HTTP_PARSER.build_http11_response(status_code, "OK", h11_headers)
    
    client_ssl:write(h11_response)
    cdata.response_headers_sent = true
    
    return 0
end

local function c_on_data_chunk_recv_callback(session, flags, stream_id, data, len, user_data)
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local client_ssl = ffi.cast("FFI_SSL_Socket", session_data.client_ssl)
    client_ssl:write(ffi.string(data, len))
    return 0
end

local function c_on_stream_close_callback(session, stream_id, error_code, user_data)
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local handler = ffi.from_handle(session_data.handler)
    handler.streams[stream_id] = nil
    return 0
end

local function create_callbacks()
    local cbs_ptr = ffi.new("nghttp2_session_callbacks*[1]")
    NGHTTP2.nghttp2_session_callbacks_new(cbs_ptr)
    local callbacks = ffi_gc(cbs_ptr[0], NGHTTP2.nghttp2_session_callbacks_del)
    NGHTTP2.nghttp2_session_callbacks_set_send_callback(callbacks, c_send_callback)
    NGHTTP2.nghttp2_session_callbacks_set_recv_callback(callbacks, c_recv_callback)
    NGHTTP2.nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, c_on_frame_recv_callback)
    NGHTTP2.nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, c_on_data_chunk_recv_callback)
    NGHTTP2.nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, c_on_stream_close_callback)
    NGHTTP2.nghttp2_session_callbacks_set_on_header_callback(callbacks, c_on_header_callback)
    NGHTTP2.nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, c_on_begin_headers_callback)
    return callbacks
end

local global_callbacks = create_callbacks()

function M:new(client_ssl, remote_ssl, host)
    local self = setmetatable({
        client_ssl = client_ssl,
        remote_ssl = remote_ssl,
        remote_session = nil,
        session_data = nil,
        streams = {},
        host = host,
        client_buffer = ""
    }, M)
    
    local handler_handle = ffi.new_handle(self)

    local remote_session_ptr = ffi.new("nghttp2_session*[1]")
    local remote_session_data = ffi.new("nghttp2_session_data")
    remote_session_data.handler = handler_handle
    remote_session_data.client_ssl = client_ssl
    remote_session_data.remote_ssl = remote_ssl
    remote_session_data.host = host
    NGHTTP2.nghttp2_session_client_new(remote_session_ptr, global_callbacks, remote_session_data)
    self.remote_session = ffi_gc(remote_session_ptr[0], NGHTTP2.nghttp2_session_del)
    self.session_data = remote_session_data

    self:send_settings(self.remote_session)
    return self
end

function M:send_settings(session)
    local iv = ffi.new("nghttp2_settings_entry[2]")
    iv[0].settings_id = bindings.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS; iv[0].value = 100
    iv[1].settings_id = bindings.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE; iv[1].value = 65535
    NGHTTP2.nghttp2_submit_settings(session, bindings.NGHTTP2_FLAG_NONE, iv, 2)
end

function M:poll_client_request()
    local data, err = self.client_ssl:read_nonblock(4096)
    if not data then
        if err == "want_read" or err == "want_write" then return true end
        return nil, "client read error: " .. err
    end
    
    self.client_buffer = self.client_buffer .. data
    local headers_end = self.client_buffer:find("\r\n\r\n")
    if not headers_end then return true end
    
    local req_text = self.client_buffer:sub(1, headers_end + 4)
    self.client_buffer = self.client_buffer:sub(headers_end + 5)
    
    local req, err_parse = HTTP_PARSER.parse_http11_request(req_text)
    if not req then return nil, err_parse end
    
    local nva_list = HTTP_PARSER.headers_to_h2_nva(req.method, req.url, req.headers)
    local nva_out = ffi.new("nghttp2_nv[?]", #nva_list)
    for i=1, #nva_list do
        nva_out[i-1] = { name = nva_list[i].name, value = nva_list[i].value, namelen = #nva_list[i].name, valuelen = #nva_list[i].value, flags = 0 }
    end
    
    local new_stream_id = NGHTTP2.nghttp2_submit_headers(self.remote_session, 0, -1, ffi.NULL, nva_out, #nva_list, ffi.NULL)
    if new_stream_id <= 0 then return nil, "Failed to submit H2 headers" end
    
    local stream = get_stream_data(self, new_stream_id)
    stream.cdata.remote_stream_id = new_stream_id
    
    return true
end

function M:run_proxy_loop()
    local client_sock = self.client_ssl:get_sock()
    local remote_sock = self.remote_ssl:get_sock()
    
    while true do
        local want_read_h2 = NGHTTP2.nghttp2_session_want_read(self.remote_session)
        local want_write_h2 = NGHTTP2.nghttp2_session_want_write(self.remote_session)
        
        if want_read_h2 == 0 and want_write_h2 == 0 then
        end

        local read_fds, write_fds = {}, {}
        
        table.insert(read_fds, client_sock)
        if want_read_h2 ~= 0 then read_fds[remote_sock] = true end
        if want_write_h2 ~= 0 then write_fds[remote_sock] = true end
        
        local read_tbl, write_tbl = {}, {}
        for k, _ in pairs(read_fds) do table.insert(read_tbl, k) end
        for k, _ in pairs(write_fds) do table.insert(write_tbl, k) end
        
        if #read_tbl == 0 and #write_tbl == 0 then break end

        local r, w, e = socket.select(read_tbl, write_tbl, TIMEOUT)
        
        if not r and not w then
            return nil, "select error: " .. (e or "unknown")
        end
        
        local read_map, write_map = {}, {}
        for _, sock in ipairs(r or {}) do read_map[sock] = true end
        for _, sock in ipairs(w or {}) do write_map[sock] = true end
        
        if read_map[client_sock] then
            local ok, err = self:poll_client_request()
            if not ok then return nil, err end
        end
        
        if read_map[remote_sock] or write_map[remote_sock] then
            local ret = NGHTTP2.nghttp2_session_recv(self.remote_session)
            if ret ~= 0 and ret ~= bindings.NGHTTP2_ERR_WOULDBLOCK then return nil, "remote recv: " .. NGHTTP2.nghttp2_strerror(ret) end
            local ret = NGHTTP2.nghttp2_session_send(self.remote_session)
            if ret ~= 0 and ret ~= bindings.NGHTTP2_ERR_WOULDBLOCK then return nil, "remote send: " .. NGHTTP2.nghttp2_strerror(ret) end
        end
    end
    
    return true
end

return M