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
    void *session_data;
    
    char* cache_key;
    char* method;
    char* url;
    int h2_status;
    bool cacheable;
    void* cache_writer_handle;
    void* cache_reader_handle;

    char* data_buffer;
    size_t data_len;
    size_t data_offset;
    
    void* stale_meta;
    
    bool remote_headers_sent;
    char* remote_buffer;
    size_t remote_buffer_len;
} nghttp2_stream_data;
]]

local function c_send_callback(session, data, length, flags, user_data)
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local ssl_sock = ffi.cast("FFI_SSL_Socket", session_data.client_ssl)
    local ok, err = ssl_sock:write_nonblock(data, length)
    if ok then return length end
    if err == "want_read" or err == "want_write" then return bindings.NGHTTP2_ERR_WOULDBLOCK end
    return bindings.NGHTTP2_ERR_CALLBACK_FAILURE
end

local function c_recv_callback(session, buf, length, flags, user_data)
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local ssl_sock = ffi.cast("FFI_SSL_Socket", session_data.client_ssl)
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
        local cdata = ffi_gc(ffi.new("nghttp2_stream_data"), function(s)
            if s.data_buffer ~= ffi.NULL then ffi.C.free(s.data_buffer) end
            if s.remote_buffer ~= ffi.NULL then ffi.C.free(s.remote_buffer) end
            if s.cache_writer_handle then ffi.from_handle(s.cache_writer_handle)(nil) end
            if s.cache_reader_handle then ffi.free_handle(s.cache_reader_handle) end
            if s.stale_meta then ffi.free_handle(s.stale_meta) end
        end)
        cdata.stream_id = stream_id
        cdata.session_data = ffi.NULL
        cdata.data_len = 0
        cdata.data_offset = 0
        cdata.data_buffer = ffi.NULL
        cdata.h2_status = 0
        cdata.cache_key = ffi.NULL
        cdata.method = ffi.NULL
        cdata.url = ffi.NULL
        cdata.cacheable = false
        cdata.cache_writer_handle = ffi.NULL
        cdata.cache_reader_handle = ffi.NULL
        cdata.stale_meta = ffi.NULL
        cdata.remote_headers_sent = false
        cdata.remote_buffer = ffi.NULL
        cdata.remote_buffer_len = 0
        
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
    local name_str = ffi.string(name, namelen)
    local value_str = ffi.string(value, valuelen)
    table.insert(stream.lua_headers, name_str)
    table.insert(stream.lua_headers, value_str)
    if name_str == ":method" then stream.cdata.method = value_str end
    if name_str == ":path" then stream.cdata.url = value_str end
    return 0
end

local function data_read_callback(session, stream_id, buf, length, data_flags, user_data)
    local cdata = ffi.cast("nghttp2_stream_data*", user_data)
    data_flags[0] = bit_bor(data_flags[0], bindings.NGHTTP2_DATA_FLAG_EOF)
    return 0
end

local function build_nva_from_h11(status_code, h11_headers)
    local nva_list = {}
    table.insert(nva_list, { name = ":status", value = tostring(status_code) })
    for k, v in pairs(h11_headers) do
         local key_lower = k:lower()
         if key_lower ~= "connection" and key_lower ~= "keep-alive" and key_lower ~= "proxy-connection" and key_lower ~= "transfer-encoding" then
            table.insert(nva_list, { name = key_lower, value = v })
        end
    end
    local nva_out = ffi.new("nghttp2_nv[?]", #nva_list)
    for i=1, #nva_list do
        nva_out[i-1] = { name = nva_list[i].name, value = nva_list[i].value, namelen = #nva_list[i].name, valuelen = #nva_list[i].value, flags = 0 }
    end
    return nva_out, #nva_list
end

local function c_on_frame_recv_callback(session, frame, user_data)
    local stream_id = frame.hd.stream_id
    if stream_id == 0 or frame.hd.type ~= 1 then return 0 end

    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local handler = ffi.from_handle(session_data.handler)
    local stream = get_stream_data(handler, stream_id)
    local cdata = stream.cdata
    cdata.session_data = user_data
    
    local remote_ssl = ffi.cast("FFI_SSL_Socket", session_data.remote_ssl)
    local host = ffi.string(session_data.host)

    local cache_key = CACHE_LOGIC.get_cache_key(cdata.method, host .. cdata.url)
    cdata.cache_key = cache_key
    local status, meta = CACHE_LOGIC.check_cache(cache_key)
    
    if status == "HIT" then
        local nva_out, nvlen = build_nva_from_h11(meta.status_code, meta.headers)
        local body_reader = CACHE_LOGIC.get_cache_body_reader(cache_key)
        local data_prd = nil
        if body_reader then
            cdata.cache_reader_handle = ffi.new_handle(body_reader)
            data_prd = ffi.new("nghttp2_data_provider")
            data_prd.read_callback = data_read_callback
            data_prd.source.ptr = cdata
        end
        NGHTTP2.nghttp2_submit_response(session, stream_id, nva_out, nvlen, data_prd)
        return 0
    end

    local h11_request = HTTP_PARSER.h2_headers_to_h11_request(stream.lua_headers, host)
    
    if status == "STALE" then
        local h = "if-none-match: " .. (meta.headers["etag"] or "") .. "\r\n" ..
                  "if-modified-since: " .. (meta.headers["last-modified"] or "") .. "\r\n"
        h11_request = h11_request .. h
        cdata.stale_meta = ffi.new_handle(meta)
    end
    
    local ok, err = remote_ssl:write(h11_request)
    if not ok then
        print("H2-H1.1 remote write error: " .. (err or ""))
        return bindings.NGHTTP2_ERR_CALLBACK_FAILURE
    end
    
    handler:start_stream_poll(stream_id)
    return 0
end

local function c_on_data_chunk_recv_callback(session, flags, stream_id, data, len, user_data)
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local remote_ssl = ffi.cast("FFI_SSL_Socket", session_data.remote_ssl)
    remote_ssl:write(ffi.string(data, len))
    return 0
end

local function c_on_stream_close_callback(session, stream_id, error_code, user_data)
    local session_data = ffi.cast("nghttp2_session_data*", user_data)
    local handler = ffi.from_handle(session_data.handler)
    local stream = handler.streams[stream_id]
    if not stream then return 0 end
    
    if stream.cdata.cache_writer_handle then
        local writer = ffi.from_handle(stream.cdata.cache_writer_handle)
        writer(nil)
    end
    
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
        client_session = nil,
        session_data = nil,
        streams = {},
        host = host,
        polling_streams = {}
    }, M)
    
    local handler_handle = ffi.new_handle(self)

    local client_session_ptr = ffi.new("nghttp2_session*[1]")
    local client_session_data = ffi.new("nghttp2_session_data")
    client_session_data.handler = handler_handle
    client_session_data.client_ssl = client_ssl
    client_session_data.remote_ssl = remote_ssl
    client_session_data.host = host
    NGHTTP2.nghttp2_session_server_new(client_session_ptr, global_callbacks, client_session_data)
    self.client_session = ffi_gc(client_session_ptr[0], NGHTTP2.nghttp2_session_del)
    self.session_data = client_session_data

    self:send_settings(self.client_session)
    return self
end

function M:send_settings(session)
    local iv = ffi.new("nghttp2_settings_entry[2]")
    iv[0].settings_id = bindings.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS; iv[0].value = 100
    iv[1].settings_id = bindings.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE; iv[1].value = 65535
    NGHTTP2.nghttp2_submit_settings(session, bindings.NGHTTP2_FLAG_NONE, iv, 2)
end

function M:start_stream_poll(stream_id)
    self.polling_streams[stream_id] = true
end

function M:poll_remote_streams()
    local remote_sock = self.remote_ssl:get_sock()
    local r, _, e = socket.select({remote_sock}, nil, 0)
    if not r or #r == 0 then return true end
    
    local data, err = self.remote_ssl:read_nonblock(65536)
    if not data then
        if err ~= "want_read" and err ~= "want_write" then
            return nil, "remote read error: " .. err
        end
        return true
    end
    
    for stream_id, _ in pairs(self.polling_streams) do
        local stream = self.streams[stream_id]
        if stream then
            local cdata = stream.cdata
            if cdata.remote_buffer == ffi.NULL then
                cdata.remote_buffer = ffi.C.malloc(#data)
                ffi.copy(cdata.remote_buffer, data, #data)
                cdata.remote_buffer_len = #data
            else
                local new_len = cdata.remote_buffer_len + #data
                local new_buf = ffi.C.realloc(cdata.remote_buffer, new_len)
                if new_buf then
                    cdata.remote_buffer = new_buf
                    ffi.copy(new_buf + cdata.remote_buffer_len, data, #data)
                    cdata.remote_buffer_len = new_len
                end
            end
            
            local buf_str = ffi.string(cdata.remote_buffer, cdata.remote_buffer_len)
            local headers_end = buf_str:find("\r\n\r\n")
            
            if headers_end then
                local header_part = buf_str:sub(1, headers_end)
                local body_chunk = buf_str:sub(headers_end + 4)
                
                local status_code, h11_headers = HTTP_PARSER.parse_http11_response_headers(header_part)
                
                if cdata.stale_meta and status_code == 304 then
                    local meta = ffi.from_handle(cdata.stale_meta)
                    local nva_out, nvlen = build_nva_from_h11(meta.status_code, meta.headers)
                    local body_reader = CACHE_LOGIC.get_cache_body_reader(cdata.cache_key)
                    if body_reader then
                        cdata.cache_reader_handle = ffi.new_handle(body_reader)
                        local data_prd = ffi.new("nghttp2_data_provider"); data_prd.read_callback = data_read_callback; data_prd.source.ptr = cdata
                        NGHTTP2.nghttp2_submit_response(self.client_session, stream_id, nva_out, nvlen, data_prd)
                    end
                    CACHE_LOGIC.update_cache_meta(cdata.cache_key, meta)
                else
                    cdata.cacheable = CACHE_LOGIC.is_cacheable(cdata.method, status_code, h11_headers)
                    if cdata.cacheable then
                        cdata.cache_writer_handle = ffi.new_handle(CACHE_LOGIC.get_cache_body_writer(cdata.cache_key))
                        ffi.from_handle(cdata.cache_writer_handle)(body_chunk)
                        CACHE_LOGIC.save_cache_meta(cdata.cache_key, status_code, h11_headers)
                    end
                    
                    local nva_out, nvlen = build_nva_from_h11(status_code, h11_headers)
                    cdata.data_buffer = ffi.C.malloc(#body_chunk)
                    ffi.copy(cdata.data_buffer, body_chunk, #body_chunk)
                    cdata.data_len = #body_chunk
                    cdata.data_offset = 0
                    local data_prd = ffi.new("nghttp2_data_provider"); data_prd.read_callback = data_read_callback; data_prd.source.ptr = cdata
                    NGHTTP2.nghttp2_submit_response(self.client_session, stream_id, nva_out, nvlen, data_prd)
                end
                
                ffi.C.free(cdata.remote_buffer)
                cdata.remote_buffer = ffi.NULL
                cdata.remote_buffer_len = 0
                self.polling_streams[stream_id] = nil
            end
        end
    end
    return true
end

function M:run_proxy_loop()
    local client_sock = self.client_ssl:get_sock()
    local remote_sock = self.remote_ssl:get_sock()
    
    while true do
        local want_read_h2 = NGHTTP2.nghttp2_session_want_read(self.client_session)
        local want_write_h2 = NGHTTP2.nghttp2_session_want_write(self.client_session)
        
        if want_read_h2 == 0 and want_write_h2 == 0 and next(self.polling_streams) == nil then
            break
        end

        local read_fds, write_fds = {}, {}
        
        if want_read_h2 ~= 0 then read_fds[client_sock] = true end
        if want_write_h2 ~= 0 then write_fds[client_sock] = true end
        if next(self.polling_streams) ~= nil then read_fds[remote_sock] = true end
        
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
        
        if read_map[client_sock] or write_map[client_sock] then
            local ret = NGHTTP2.nghttp2_session_recv(self.client_session)
            if ret ~= 0 and ret ~= bindings.NGHTTP2_ERR_WOULDBLOCK then return nil, "client recv: " .. NGHTTP2.nghttp2_strerror(ret) end
            local ret = NGHTTP2.nghttp2_session_send(self.client_session)
            if ret ~= 0 and ret ~= bindings.NGHTTP2_ERR_WOULDBLOCK then return nil, "client send: " .. NGHTTP2.nghttp2_strerror(ret) end
        end
        
        if read_map[remote_sock] then
            local ok, err = self:poll_remote_streams()
            if not ok then return nil, err end
        end
    end
    
    return true
end

return M