@echo off

SET MYFILE="data.db"
IF EXIST %MYFILE% del /F %MYFILE%

SET DATADIR="data"
IF EXIST %DATADIR% rmdir /S /Q %DATADIR% & mkdir %DATADIR%
