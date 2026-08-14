-- ==============================================================================
-- PROJECT SENTINEL - KONG DECLARATIVE CONFIG RENDERER (BOOT-TIME)
-- File: gateway/render_config.lua
-- Purpose: Đọc tệp allowlist.json, parse danh sách JSON endpoints, format thành
--          chuỗi Lua lookup table ["/path"] = true và thay thế các placeholder
--          (${ALLOWED_PATHS_LUA}, ${AGENT_API_KEY}) trong kong.yml xuất ra /tmp/kong.yml.
-- Inputs:
--   - Template File: /usr/local/kong/declarative/kong.yml
--   - Allowlist File: /usr/local/kong/declarative/allowlist.json
--   - Environment Var: AGENT_API_KEY
-- Output:
--   - Generated Declarative File: /tmp/kong.yml
-- ==============================================================================

-- Nạp cjson thư viện từ OpenResty
package.cpath = package.cpath .. ";/usr/local/openresty/lualib/?.so"
local cjson = require("cjson")

-- Danh sách endpoints mặc định (Fallback mặc định khi file bị rỗng hoặc lỗi JSON)
local DEFAULT_PATHS = {
    "/api/Quantitys",
    "/rest/products/search",
    "/rest/user/login"
}

--- Đọc toàn bộ nội dung của tệp tin
-- @param file_path Đường dẫn tuyệt đối tới tệp tin
-- @return Content (string) hoặc nil nếu đọc thất bại
local function read_file(file_path)
    local f, err = io.open(file_path, "r")
    if not f then
        return nil, err
    end
    local content = f:read("*a")
    f:close()
    return content
end

--- Ghi nội dung vào tệp tin
-- @param file_path Đường dẫn tuyệt đối tới tệp tin đích
-- @param content Chuỗi dữ liệu cần ghi
-- @return boolean (true nếu thành công, false nếu thất bại)
local function write_file(file_path, content)
    local f, err = io.open(file_path, "w")
    if not f then
        return false, err
    end
    f:write(content)
    f:close()
    return true
end

--- Loại bỏ khoảng trắng ở 2 đầu chuỗi (Trim whitespace)
-- @param s Chuỗi đầu vào
-- @return Chuỗi đã được làm sạch
local function trim(s)
    if type(s) ~= "string" then return "" end
    return s:match("^%s*(.-)%s*$")
end

--- Trích xuất danh sách paths từ nội dung file JSON với đầy đủ kiểm tra lỗi (Edge Cases)
-- @param allowlist_path Đường dẫn file allowlist.json
-- @return Bảng chứa danh sách các path hợp lệ (table array)
local function get_allowed_paths(allowlist_path)
    local raw_json, err = read_file(allowlist_path)
    if not raw_json or trim(raw_json) == "" then
        print("[WARN] File allowlist.json rỗng hoặc không tồn tại. Tự động sử dụng Default Fallback Allowlist.")
        return DEFAULT_PATHS
    end

    local success, decoded = pcall(cjson.decode, raw_json)
    if not success or type(decoded) ~= "table" then
        print("[WARN] Cú pháp JSON trong allowlist.json bị lỗi: " .. tostring(decoded) .. ". Sử dụng Default Fallback Allowlist.")
        return DEFAULT_PATHS
    end

    local raw_list = {}
    if decoded[1] ~= nil then
        -- Cấu hình kiểu JSON Array: ["/path1", "/path2"]
        raw_list = decoded
    elseif type(decoded.endpoints) == "table" then
        -- Cấu hình kiểu Object: {"endpoints": ["/path1", "/path2"]}
        raw_list = decoded.endpoints
    elseif type(decoded.allowlist) == "table" then
        -- Cấu hình kiểu Object: {"allowlist": ["/path1", "/path2"]}
        raw_list = decoded.allowlist
    end

    local valid_paths = {}
    local seen = {}

    for _, p in ipairs(raw_list) do
        if type(p) == "string" then
            local clean_path = trim(p)
            if clean_path ~= "" and not seen[clean_path] then
                seen[clean_path] = true
                table.insert(valid_paths, clean_path)
            end
        end
    end

    if #valid_paths == 0 then
        print("[WARN] Không tìm thấy path hợp lệ nào trong allowlist.json. Sử dụng Default Fallback Allowlist.")
        return DEFAULT_PATHS
    end

    return valid_paths
end

--- Hàm thực thi chính (Main Entrypoint)
local function main()
    local template_path = "/usr/local/kong/declarative/kong.yml"
    local allowlist_path = "/usr/local/kong/declarative/allowlist.json"
    local output_path = "/tmp/kong.yml"

    -- 1. Đọc danh sách path và chuyển đổi thành chuỗi Lua lookup table: ["/path"] = true
    local paths = get_allowed_paths(allowlist_path)
    local lua_entries = {}
    for _, p in ipairs(paths) do
        -- Escape kí tự ngoặc kép nếu có trong path để tránh lỗi cú pháp Lua
        local safe_p = p:gsub('"', '\\"')
        table.insert(lua_entries, string.format('["%s"] = true', safe_p))
    end
    local lua_table_str = table.concat(lua_entries, ", ")

    -- 2. Đọc tệp template kong.yml
    local template_content, err = read_file(template_path)
    if not template_content then
        error("[ERROR] Không thể đọc template kong.yml: " .. tostring(err))
    end

    -- 3. Thay thế biến môi trường AGENT_API_KEY và placeholder ALLOWED_PATHS_LUA
    local agent_api_key = os.getenv("AGENT_API_KEY") or "sentinel-agent-secure-key-2026"

    -- Thay thế ${ALLOWED_PATHS_LUA}
    local rendered = template_content:gsub("%$%{ALLOWED_PATHS_LUA%}", lua_table_str)
    -- Thay thế ${AGENT_API_KEY}
    rendered = rendered:gsub("%$%{AGENT_API_KEY%}", agent_api_key)

    -- 4. Ghi kết quả ra /tmp/kong.yml
    local ok, write_err = write_file(output_path, rendered)
    if not ok then
        error("[ERROR] Không thể ghi kết quả ra /tmp/kong.yml: " .. tostring(write_err))
    end

    print(string.format("[SUCCESS] Đã render thành công /tmp/kong.yml với %d allowed endpoints.", #paths))
end

main()
