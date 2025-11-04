@echo off

:: Задать переменные окружения
set CURRENT_DIR=%CD%

:: Настройка LUA_PATH и LUA_CPATH
set LUA_PATH=%CURRENT_DIR%\?.lua;%CURRENT_DIR%\luarocks\rocks\share\lua\5.1\?.lua;%CURRENT_DIR%\luarocks\rocks\share\lua\5.1\?\?.lua;%LUA_PATH%
set LUA_CPATH=%CURRENT_DIR%\luarocks\rocks\lib\lua\5.1\?.dll;%CURRENT_DIR%\luarocks\rocks\lib\lua\5.1\?\core.dll;%LUA_CPATH%

:: Указать путь к конфигурации для luarocks
set LUAROCKS_CONFIG=%CURRENT_DIR%\luarocks\config-luajit.lua

:: Показать используемую конфигурацию
echo Using LUAROCKS_CONFIG at: %LUAROCKS_CONFIG%

:: Запуск luarocks с параметрами, переданными из командной строки
luarocks\luarocks.exe %*

:: Указываем путь к OpenSSL и nghttp2
set PATH=%PATH%;%CURRENT_DIR%\openssl;%CURRENT_DIR%\nghttp2\lib
set OPENSSL_CONF=%CURRENT_DIR%\openssl\openssl.cnf

:: Запуск скрипта Lua с помощью LuaJIT
chcp 65001
luajit\bin\luajit.exe main.lua

pause
