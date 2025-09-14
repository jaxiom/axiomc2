@ECHO OFF
msbuild .\Client.sln /p:configuration=Release
copy x64\Release\Client.exe