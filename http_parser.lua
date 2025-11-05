local M = {}

function M.parse_http11_request(raw_request)
    local headers = {}
    
    local request_line_end = raw_request:find("\r?\n", 1, true)
    if not request_line_end then return nil, "Incomplete request line" end
    local request_line = raw_request:sub(1, request_line_end - 1)
    
    local method, url, proto = request_line:match("^(%S+) (%S+) (HTTP/1%.%d)\r?$")
    
    if not method then return nil, "Invalid request line: " .. request_line end
    
    local headers_end = raw_request:find("\r\n\r\n", request_line_end + 1)
    if not headers_end then 
        return nil, "Incomplete headers" 
    end
    
    local header_section = raw_request:sub(request_line_end + 1, headers_end + 1)
    
    local host
    for line in header_section:gmatch("([^\r\n]*)\r?\n") do
        if line == "" then break end
        local k, v = line:match("^([^:]+):%s*(.*)$")
        if k then
            local key_lower = k:lower()
            headers[key_lower] = v:match("^[ \t]*(.-)[ \t]*$")
            if key_lower == "host" then
                host = v:match("^[ \t]*(.-)[ \t]*$")
            end
        end
    end
    
    local body_start = headers_end + 4
    local body
    local content_length = tonumber(headers["content-length"] or "0")
    
    if content_length > 0 then
        body = raw_request:sub(body_start, body_start + content_length - 1)
    elseif method ~= "CONNECT" and #raw_request > body_start - 1 then
        body = raw_request:sub(body_start)
    end
    
    return {
        method = method,
        url = url,
        proto = proto,
        headers = headers,
        body = body,
        host = host or (method == "CONNECT" and url)
    }, nil, body_start
end

function M.parse_http11_response_headers(header_section)
    local headers = {}
    local status_code = 0
    local status_text = ""
    
    local request_line_end = header_section:find("\r?\n", 1, true)
    if not request_line_end then return 0, {} end
    
    local response_line = header_section:sub(1, request_line_end - 1)
    status_code, status_text = response_line:match("^HTTP/1%.%d (%d+) (.*)\r?$")
    status_code = tonumber(status_code) or 0
    
    for line in header_section:gmatch("([^\r\n]*)\r?\n") do
        if line == "" then break end
        local k, v = line:match("^([^:]+):%s*(.*)$")
        if k then
            headers[k:lower()] = v:match("^[ \t]*(.-)[ \t]*$")
        end
    end
    
    return status_code, headers
end

function M.build_http11_response(status_code, status_text, headers, body)
    local response_line = "HTTP/1.1 " .. status_code .. " " .. (status_text or "OK") .. "\r\n"
    local header_lines = {}
    
    local has_content_length = false
    for k, v in pairs(headers) do
        table.insert(header_lines, k .. ": " .. v .. "\r\n")
        if k:lower() == "content-length" then has_content_length = true end
    end
    
    if body and #body > 0 and not has_content_length then
        table.insert(header_lines, "Content-Length: " .. #body .. "\r\n")
    elseif not body and not has_content_length and status_code ~= 204 and status_code ~= 304 then
         table.insert(header_lines, "Content-Length: 0\r\n")
    end
    
    return response_line .. table.concat(header_lines) .. "\r\n" .. (body or "")
end

function M.h2_headers_to_h11_request(h2_headers, host, proto)
    local method, path
    local h11_headers = {}
    
    for i=1, #h2_headers, 2 do
        local k = h2_headers[i]
        local v = h2_headers[i+1]
        if k == ":method" then
            method = v
        elseif k == ":path" then
            path = v
        elseif k:sub(1,1) ~= ":" then
            h11_headers[k] = v
        end
    end
    
    h11_headers["Host"] = host
    h11_headers["Connection"] = "keep-alive"
    
    local request_line = string.format("%s %s %s\r\n", method, path, proto or "HTTP/1.1")
    local header_lines = {}
    for k, v in pairs(h11_headers) do
        table.insert(header_lines, k .. ": " .. v .. "\r\n")
    end
    
    return request_line .. table.concat(header_lines) .. "\r\n"
end

function M.h2_headers_to_h11_response(nva)
    local headers = {}
    local status = "200"
    
    for _, nv in ipairs(nva) do
        if nv.name == ":status" then
            status = nv.value
        elseif nv.name:sub(1, 1) ~= ":" then
            headers[nv.name] = nv.value
        end
    end
    
    return tonumber(status), headers
end

return M