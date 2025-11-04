@echo off
setlocal
set "LUAROCKS_SYSCONFDIR=C:\Program Files\luarocks"
"C:\HandyCache\luajit\bin\luajit.exe" -e "package.path=\"C:\\HandyCache\\luarocks\\rocks\\share\\lua\\5.1\\?.lua;C:\\HandyCache\\luarocks\\rocks\\share\\lua\\5.1\\?\\init.lua;\"..package.path;package.cpath=\"C:\\HandyCache\\luarocks\\rocks\\lib\\lua\\5.1\\?.dll;\"..package.cpath;local k,l,_=pcall(require,'luarocks.loader') _=k and l.add_context('lua-cjson','2.1.0.10-1')" "C:\HandyCache\luarocks\rocks\lib\luarocks\rocks-5.1\lua-cjson\2.1.0.10-1\bin\json2lua" %*
exit /b %ERRORLEVEL%
