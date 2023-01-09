::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::::::::::::::::::::::: 공통 부분 시작:::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

@echo off

setlocal
set tnd=C:\tnd
set john=%tnd%\john
set script=%tnd%\script

rem 스크립트 실행 시 항목 카운트 보여주기 위한 변수df
set item_count=0

TITLE Windosws Security Check

::실제 버전 확인 시작
ver > ver.txt
for /f "delims=[ tokens=2" %%i in (ver.txt) do set MV=%%i
del ver.txt 2> nul

if exist %windir%\SysWOW64 (
	set WinBit=64
) else (
	set WinBit=32
)

:: windows 2000
if "%MV:~8,3%"=="5.0" (
	set WinVer=1
	set WinVer_name=2000
	echo Windows 2000 %WinBit%bit                                                            > %tnd%\real_ver.txt
)

:: windows 2003
if "%MV:~8,3%"=="5.2" (
	set WinVer=2
	set WinVer_name=2003
	echo Windows 2003 %WinBit%bit                                                            > %tnd%\real_ver.txt
)

:: windows 2008
if "%MV:~8,3%"=="6.0" (
	set WinVer=3
	set WinVer_name=2008
	echo Windows 2008 %WinBit%bit                                                            > %tnd%\real_ver.txt
)

:: windows 2008 r2
if "%MV:~8,3%"=="6.1" (
	set WinVer=4
	set WinVer_name=2008_R2
	echo Windows 2008 R2 %WinBit%bit                                                         > %tnd%\real_ver.txt
)

:: windows 2012
if "%MV:~8,3%"=="6.2" (
	set WinVer=5
	set WinVer_name=2012
	echo Windows 2012 %WinBit%bit                                                            > %tnd%\real_ver.txt
)

:: windows 2012 r2
if "%MV:~8,3%"=="6.3" (
	set WinVer=6
	set WinVer_name=2012_R2
	echo Windows 2012 R2 %WinBit%bit                                                         > %tnd%\real_ver.txt
)

:: windows 2016
if "%MV:~8,4%"=="10.0" (
	set WinVer=7
	set WinVer_name=2016
	echo Windows 2016 %WinBit%bit                                                         > %tnd%\real_ver.txt
)

type real_ver.txt > %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

:: windows 2008 이상버전은 icacls
if %WinVer% geq 3 (
	doskey cacls=icacls $*
)
::실제 버전 확인 끝




set SCRIPT_LAST_UPDATE=2017.09.01
echo ======================================================================================= >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■■■■■■■■■■■■■■■■■■■      Windows %WinVer_name% Security Check      ■■■■■■■■■■■■■■■■■■■■ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■■■■■■■■■■■■■■■■■■■      Copyright ⓒ 2017, SK tnd Co. Ltd.    ■■■■■■■■■■■■■■■■■■■■ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ======================================================================================= >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo LAST_UPDATE %SCRIPT_LAST_UPDATE%                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■  Start Time  ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
date /t                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
time /t                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt     
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
::sysinfo 한글(chcp 437이후 한글 ??로 깨짐 현상 방지)
echo [+] Gathering systeminfo...
systeminfo																					 > %tnd%\systeminfo_ko.txt 2>nul

::영문으로 변경
chcp 437

::공통 설정파일 추출
secedit /EXPORT /CFG Local_Security_Policy.txt >nul
net accounts > %tnd%\net-accounts.txt 


::FTP 사용확인
net start | find /i "ftp" > nul
if not errorlevel 1 (
	echo FTP Enable                                                                         > ftp-enable.txt
) else (
goto FTP-Disable
)

:: FTP Version 구별하기
net start | find /i "FTP Publishing Service" > nul
if not errorlevel 1 (
	set iis_ftp_ver_major=6
) else (
	net start | find /i "Microsoft FTP Service" > nul
	if not errorlevel 1 (
		set iis_ftp_ver_major=7
	) else (
		set iis_ftp_ver_major=0
	)
)

:: FTP Site List 구하기 ( ftpsite-list.txt )
:: iis ver >= 7
if %iis_ftp_ver_major% geq 7 (
	%systemroot%\System32\inetsrv\appcmd list site | find /i "ftp"                           > %tnd%\ftpsite-list.txt
)
:: iis ver <= 6
if %iis_ftp_ver_major% leq 6 (
	cscript %script%\adsutil.vbs enum MSFTPSVC | find /i "MSFTPSVC" | findstr /i /v "FILTERS APPPOOLS INFO" > ftpsite-list.txt
)

:: FTP Site Name 구하기 ( ftpsite-name.txt )
:: iis ver >= 7
if %iis_ftp_ver_major% geq 7 (
	for /f "tokens=1 delims=(" %%a in (ftpsite-list.txt) do (
		for /f "tokens=2-11 delims= " %%b in ("%%a") do (
			echo %%b %%c %%d %%e %%f %%g %%h %%i %%j %%k                                   >> %tnd%\ftpsite-name.txt
		)
	)
)
:: iis ver <= 6
if %iis_ftp_ver_major% leq 6 (
	for /f "tokens=1 delims=[]" %%i in (ftpsite-list.txt) do (
		cscript %script%\adsutil.vbs enum %%i | findstr /i "ServerComment ServerState"     >> %tnd%\ftpsite-name.txt
		echo -----------------------------------------------------------------------	   >> %tnd%\ftpsite-name.txt
	)
)

:: FTP Site physicalpath 구하기 ( ftpsite-physicalpath.txt )
:: iis ver >= 7
if %iis_ftp_ver_major% geq 7 (
	%systemroot%\System32\inetsrv\appcmd list config -section:system.applicationHost/sites | find /i "physicalpath" > %tnd%\ftpsite-physicalpath-temp.txt
	for /f "tokens=3 delims= " %%a in (ftpsite-physicalpath-temp.txt) do (
		for /f "tokens=2 delims==" %%b in ("%%a") do echo %%~b >> ftpsite-physicalpath.txt
	)
	del ftpsite-physicalpath-temp.txt 2> nul
)
:: iis ver <= 6
if %iis_ftp_ver_major% leq 6 (
	for /f "tokens=1 delims=[]" %%i in (ftpsite-list.txt) do (
		cscript %script%\adsutil.vbs enum %%i/root | find /i "path" | find /i /v "AspEnableParentPaths" >> %tnd%\ftpsite-physicalpath-temp.txt
	)
	for /f "tokens=4-8 delims= " %%i in (ftpsite-physicalpath-temp.txt) do (
		echo %%i %%j %%k %%l %%m                                                              >> %tnd%\ftpsite-physicalpath.txt
	)
	del ftpsite-physicalpath-temp.txt 2> nul
)
:FTP-Disable

::IIS 사용확인
net start | find /i "world wide web publishing service" > nul
if not errorlevel 1 (
	echo IIS Enable                                                                           > iis-enable.txt
) else (
 goto IIS-Disable
 )

:: IIS Version 구하기
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters" | find /i "version" > iis-version.txt
type iis-version.txt | find /i "major"                                                        > iis-version-major.txt
for /f "tokens=3" %%a in (iis-version-major.txt) do set iis_ver_major=%%a
del iis-version-major.txt 2> nul

:: WebSite List 구하기 ( website-list.txt )
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	%systemroot%\System32\inetsrv\appcmd list site | find /i "http"                             > website-list.txt
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	cscript %script%\adsutil.vbs enum W3SVC | find /i "W3SVC" | findstr /i /v "FILTERS APPPOOLS INFO" > website-list.txt
)

:: WebSite Name 구하기 ( website-name.txt )
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	for /f "tokens=1 delims=(" %%a in (website-list.txt) do (
		for /f "tokens=2-11 delims= " %%b in ("%%a") do (
			echo %%b %%c %%d %%e %%f %%g %%h %%i %%j %%k                                         >> website-name.txt
		)
	)
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	for /f "tokens=1 delims=[]" %%i in (website-list.txt) do (
		cscript %script%\adsutil.vbs enum %%i | findstr /i "ServerComment ServerAutoStart"       >> website-name.txt
		cscript %script%\adsutil.vbs enum %%i/ROOT | find "AppRoot"                              >> website-name.txt
		echo -----------------------------------------------------------------------			 >> website-name.txt
	)
)

:: Web Site physicalpath 구하기 ( website-physicalpath.txt )
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	%systemroot%\System32\inetsrv\appcmd list config -section:system.applicationHost/sites | find /i "physicalpath" > website-physicalpath-temp.txt
	for /f "tokens=3 delims= " %%a in (website-physicalpath-temp.txt) do (
		for /f "tokens=2 delims==" %%b in ("%%a") do echo %%~b >> website-physicalpath.txt
	)
	del website-physicalpath-temp.txt 2> nul
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	for /f "tokens=1 delims=[]" %%i in (website-list.txt) do (
		cscript %script%\adsutil.vbs enum %%i/root | find /i "path" | find /i /v "AspEnableParentPaths" >> website-physicalpath-temp.txt
	)
	for /f "tokens=4-8 delims= " %%i in (website-physicalpath-temp.txt) do (
		echo %%i %%j %%k %%l %%m                                                              >> website-physicalpath.txt
	)
	del website-physicalpath-temp.txt 2> nul
)
:IIS-Disable


::sysinfo 영문
systeminfo																					 > %tnd%\systeminfo.txt 2>nul

::Process List
:: winver = 2000
if %WinVer% equ 1 (
	%script%\pslist                                                                          > tasklist.txt
)
:: winver >= 2003
if %WinVer% geq 2 (
	tasklist																				 > %tnd%\tasklist.txt 2>nul
)

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::::::::::::::::::::::: 공통 부분 끝:::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0101 START                                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################        1.01 Administrator 계정 이름 바꾸기         ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: Administrator 계정 이름을 변경하여 사용하는 경우 양호                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net localgroup Administrators | findstr /V "Comment Members completed" | findstr .           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

net localgroup Administrators | findstr /V "Comment Members completed" | findstr .           > %tnd%\1.01-result.txt
type 1.01-result.txt | findstr /V "Alias name" | findstr /i administrator | findstr .        > %tnd%\result.txt

net localgroup Administrators | findstr /V "Comment Members completed" | findstr . | findstr /V "Alias name" | findstr /i administrator | findstr . > nul
if %errorlevel% equ 0 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=Administrator																		>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O																				>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
del %tnd%\1.01-result.txt 2>nul
del %tnd%\result.txt 2>nul

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0101 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0102 START                                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo #################               1.02 GUEST 계정 상태                ######################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: Guest 계정 비활성화일 경우 양호                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net user guest | find "User name"                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net user guest | find "Account active"                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

net user guest | find "Account active" | %script%\awk -F" " {print$3}        >> %tnd%\result.txt

net user guest | find "Account active" | find "Yes" > nul
if %errorlevel% equ 0 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=Yes												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=No												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

del %tnd%\result.txt 2>nul

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0102 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0103 START                                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################              1.03 불필요한 계정 제거               ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 불필요한 계정이 존재하지 않을 경우                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ****************************  User Accounts List  *****************************         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net user | find /V "successfully" | findstr .                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo *****************************  Account Information  ***************************         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        > %tnd%\account.txt 2>nul
FOR /F "tokens=1,2,3 skip=4" %%i IN ('net user') DO (
echo -------------------------------------------------------------------------------         >> %tnd%\account.txt 2>nul
net user %%i >> account.txt 2>nul
echo -------------------------------------------------------------------------------         >> %tnd%\account.txt 2>nul
net user %%j >> account.txt 2>nul
echo -------------------------------------------------------------------------------         >> %tnd%\account.txt 2>nul
net user %%k >> account.txt 2>nul
)
findstr "User active Comment Last --" account.txt                                            > %tnd%\account_temp1.txt
findstr /v "change profile Memberships User's" account_temp1.txt                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0103 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0104 START                                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################            1.04 계정 잠금 임계값 설정             ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 로그온 실패 수를 제한하는 계정 잠금 임계값이 5번 이하로 설정되어 있으면 양호          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type net-accounts.txt | find "Lockout threshold"                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


type net-accounts.txt | find "Lockout threshold" | %script%\awk -F" " {print$3}        		> %tnd%\result.txt

type %tnd%\result.txt | find /i "never" > nul
if %errorlevel% neq 1 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=Never												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
)


echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
del %tnd%\result.txt 2>nul

echo 0104 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0105 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################    1.05 해독 가능한 암호화를 사용하여 암호 저장    ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "해독 가능한 암호화를 사용하여 암호 저장" 정책이 "사용안함"으로 설정되어 있으면 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (ClearTextPassword = 0 일 경우 양호)                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type Local_Security_Policy.txt | Find /I "ClearTextPassword"                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type Local_Security_Policy.txt | Find /I "ClearTextPassword"  |  %script%\awk -F" " {print$3}    >> %tnd%\result.txt

for /f "delims= tokens=1" %%r in (result.txt) do set result=%%r
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=%result%												 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

del %tnd%\result.txt 2>nul
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


echo 0105 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0106 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################      1.06 관리자 그룹에 최소한의 사용자 포함        ##################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: Administrators 그룹에 불필요한 계정이 존재 하지 않을 경우 양호                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net localgroup Administrators | findstr /V "Comment Members completed" | findstr .           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        > %tnd%\admin-account.txt 2>nul
echo *********************  Administrators Account Information  ********************         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
FOR /F "tokens=1,2,3,4 skip=6" %%j IN ('net localgroup administrators') DO (
net user %%j %%k %%l %%m >> %tnd%\admin-account.txt 2>nul
echo -------------------------------------------------------------------------------         >> %tnd%\admin-account.txt 2>nul
)
findstr c/:"User name | Account active | Last logon | -----" admin-account.txt               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0106 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0107 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ################     1.07 Everyone 사용 권한을 익명 사용자에게 적용          ############### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : “Everyone 사용 권한을 익명 사용자에게 적용” 정책이 “사용안함” 으로 되어 있을 경우 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 		: (EveryoneIncludesAnonymous=4,0 이면 양호)                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	echo Win 2000 해당사항 없음                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: winver >= 2003
if %WinVer% geq 2 (
	type Local_Security_Policy.txt | Find /I "EveryoneIncludesAnonymous"                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type Local_Security_Policy.txt | Find /I "EveryoneIncludesAnonymous"						 >> %tnd%\result.txt

for /f "tokens=2 delims==" %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

del %tnd%\result.txt 2>nul
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0107 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0108 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo #################              1.08 계정 잠금 기간 설정              ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "계정 잠금 기간", "계정 잠금 기간 원래대로 설정" 값이 60분 이상으로 설정되어 있으면 양호                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type net-accounts.txt | find "Lockout duration"                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type net-accounts.txt | find "Lockout observation"                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type net-accounts.txt | find "Lockout duration" | %script%\awk -F" " {print$4} > %tnd%\lockout.txt
type net-accounts.txt | find "Lockout observation" |%script%\awk -F" " {print$5} > %tnd%\lockout2.txt

for /f %%r in (lockout.txt) do set lockout1=%%r
for /f %%p in (lockout2.txt) do set lockout=%lockout1%:%%p					
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo Result=%lockout%												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

del %tnd%\lockout.txt 2>nul
del %tnd%\lockout2.txt 2>nul

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0108 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0109 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo #################             1.09 패스워드 복잡성 설정              ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "암호는 복잡성을 만족해야 함" 정책이 "사용" 으로 되어 있을 경우 양호            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (PasswordComplexity = 1 일 경우 양호)                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type Local_Security_Policy.txt | Find /I "PasswordComplexity"                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


type Local_Security_Policy.txt | Find /I "PasswordComplexity" | %script%\awk -F" " {print$3}  >> %tnd%\result.txt

for /f "delims= tokens=1" %%r in (result.txt) do set result=%%r
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=%result%												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

del %tnd%\result.txt 2>nul



echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0109 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0110 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo #################            1.10 패스워드 최소 암호 길이            ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 최소 암호 길이 설정이 8자 이상인 경우 양호                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type net-accounts.txt | find "length"                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type net-accounts.txt | find "length" | %script%\awk -F" " {print$4}                      >> %tnd%\result.txt

for /f "delims= tokens=1" %%r in (result.txt) do set result=%%r
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=%result%												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

del %tnd%\result.txt 2>nul

echo 0110 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0111 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo #################            1.11 패스워드 최대 사용 기간           ######################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 최대 암호 사용 기간 설정이 90일 이하인 경우 양호                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type net-accounts.txt | find "Maximum password"                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type account.txt | findstr "User active expires Last --"                        			 > %tnd%\account_temp2.txt
type account_temp2.txt | findstr /v "change profile Memberships User's" | findstr "User active Password Last --" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type net-accounts.txt | find "Maximum password" | %script%\awk -F" " {print$5}                      >> %tnd%\result.txt

for /f "delims= tokens=1" %%r in (result.txt) do set result=%%r
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=%result%												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

del %tnd%\result.txt 2>nul


echo 0111 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0112 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo #################           1.12 패스워드 최소 사용 기간            ######################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 계정의 패스워드 사용기간이 최소 1일 이상일 경우 양호                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type net-accounts.txt | find "Minimum password age"                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type net-accounts.txt | find "Minimum password age" | %script%\awk -F" " {print$5} > %tnd%\result.txt

for /f "delims= tokens=1" %%r in (result.txt) do set result=%%r
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=%result%												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

del %tnd%\result.txt 2>nul


echo 0112 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0113 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo #################         1.13 마지막 사용자 이름 표시 안함         ######################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "마지막 사용자 이름 표시 안함" 정책이 "사용"으로 설정되어 있을 경우 양호        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (DontDisplayLastUserName = 1)                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName" | %script%\awk -F" " {print$3}                      >> %tnd%\result.txt

for /f "delims= tokens=1" %%r in (result.txt) do set result=%%r
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=%result%												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

del %tnd%\result.txt 2>nul


echo 0113 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0114 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################               1.14 로컬 로그온 허용               ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "로컬 로그온 허용" 정책에 "Administrators", "IUSR_" 만 존재할 경우 양호         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (Administrators = *S-1-5-32-544), (IUSR = *S-1-5-17)                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type Local_Security_Policy.txt | Find /I "SeInteractiveLogonRight"                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type Local_Security_Policy.txt | Find /I "SeInteractiveLogonRight" | %script%\awk -F= {print$2}                      >> %tnd%\result.txt

for /F "delims=, tokens=1-26" %%a in (result.txt) do (
	echo %%a  >> result2.txt 2> nul
	echo %%b  >> result2.txt 2> nul
	echo %%c  >> result2.txt 2> nul
	echo %%d  >> result2.txt 2> nul
	echo %%e  >> result2.txt 2> nul
	echo %%f  >> result2.txt 2> nul
	echo %%g  >> result2.txt 2> nul
	echo %%h  >> result2.txt 2> nul
	echo %%i  >> result2.txt 2> nul
	echo %%j  >> result2.txt 2> nul
	echo %%k  >> result2.txt 2> nul
	echo %%l  >> result2.txt 2> nul
	echo %%m  >> result2.txt 2> nul
	echo %%n  >> result2.txt 2> nul
	echo %%o  >> result2.txt 2> nul
	echo %%p  >> result2.txt 2> nul
	echo %%q  >> result2.txt 2> nul
	echo %%r  >> result2.txt 2> nul
	echo %%s  >> result2.txt 2> nul
	echo %%t  >> result2.txt 2> nul
	echo %%u  >> result2.txt 2> nul
	echo %%v  >> result2.txt 2> nul
	echo %%w  >> result2.txt 2> nul
	echo %%x  >> result2.txt 2> nul
	echo %%y  >> result2.txt 2> nul
	echo %%z  >> result2.txt 2> nul
)

type result2.txt | findstr /V /i "*S-1-5-32-544 *S-1-5-17 ECHO" >> result3.txt

type result3.txt | findstr "*S-1" > nul
if NOT ERRORLEVEL 1 (
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

if ERRORLEVEL 1 (
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

del %tnd%\result.txt 2>nul
del %tnd%\result2.txt 2>nul
del %tnd%\result3.txt 2>nul

echo 0114 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0115 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################           1.15 익명 SID/이름 변환 허용            ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "익명 SID/이름 변환 허용" 정책이 "사용 안 함" 으로 되어 있을 경우 양호          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (LSAAnonymousNameLookup = 0)                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	echo Win 2000 해당사항 없음                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: winver >= 2003
if %WinVer% geq 2 (
	type Local_Security_Policy.txt | Find /I "LSAAnonymousNameLookup"                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type Local_Security_Policy.txt | Find /I "LSAAnonymousNameLookup" | %script%\awk -F" " {print$3}                      > %tnd%\result.txt

	for /f "delims= tokens=1" %%r in (result.txt) do echo Result=%%r	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

del %tnd%\result.txt 2>nul

)

echo.                                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0115 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0116 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################                1.16 최근 암호 기억                ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 계정의 최근 사용한 패스워드 기억 설정이 12개 이상인 경우 양호                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type net-accounts.txt | find "history"                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type net-accounts.txt | find "history" | %script%\awk -F" " {print$6}                      >> %tnd%\result.txt

type %tnd%\result.txt | find /i "None" > nul

for /f "tokens=1" %%r in (result.txt) do echo Result=%%r >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

del %tnd%\result.txt 2>nul

echo 0116 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0117 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################  1.17 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한  ################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한" 정책이 "사용"으로 되어 있을 경우 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (LimitBlankPasswordUse = 4,1)                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
rem 결과 값이 존재하지 않으면 Default 설정 적용(Default 설정: LimitBlankPasswordUse 1 양호)
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	echo Win 2000 해당사항 없음                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: winver >= 2003
if %WinVer% geq 2 (
	type Local_Security_Policy.txt | Find /I "LimitBlankPasswordUse"                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type Local_Security_Policy.txt | Find /I "LimitBlankPasswordUse"                >> %tnd%\result.txt
	for /f "delims== tokens=2" %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

del %tnd%\result.txt 2>nul

	
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0117 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0118 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################    1.18 원격터미널 접속 가능한 사용자 그룹 제한    ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 원격 터미널 접속이 가능한 Administrators그룹과 Remote Desktop Users그룹에       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : 불필요한 계정이 등록되어 있지 않은 경우 양호                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	echo Win 2000 해당사항 없음                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: winver >= 2008_R2
if %WinVer% geq 4 (
	net start | find /i "Remote Desktop Services" >nul
	IF NOT ERRORLEVEL 1 (
		echo ☞ Remote Desktop Services Enable                                          	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo ☞ 원격 터미널 접속 허용 계정                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		net localgroup "Administrators" | findstr /V "Comment Members completed" | findstr .         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		net localgroup "Remote Desktop Users" | findstr /V "Comment Members completed" | findstr .   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
	IF ERRORLEVEL 1 (
		echo ☞ Remote Desktop Services Disable                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
) else (
	NET START | FIND "Terminal Service" > NUL
	IF NOT ERRORLEVEL 1 (
		echo ☞ Terminal Service Enable                                          			>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo ☞ 원격 터미널 접속 허용 계정                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		net localgroup "Administrators" | findstr /V "Comment Members completed" | findstr .         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		net localgroup "Remote Desktop Users" | findstr /V "Comment Members completed" | findstr .   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
	IF ERRORLEVEL 1 (
		echo ☞ Terminal Service Disable                                             		 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0118 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0201 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
chcp 949
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################          2.01 공유 권한 및 사용자 그룹 설정        ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 일반공유 폴더가 없거나 공유 디렉토리 접근 권한이 Everyone 없을 경우 양호    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net share | find /v "$" | find /v "명령"			                                      	 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net share | find /v "$" | find /v "명령" | find /v "------"                                    	 > %tnd%\inf_share_folder.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type inf_share_folder.txt | find "\" > nul
IF %ERRORLEVEL% neq 0 echo 공유폴더가 존재하지 않습니다.								>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo ☞ cacls 결과                                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	FOR /F "tokens=2 skip=3" %%j IN (inf_share_folder.txt) DO cacls %%j                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2>nul
	
	FOR /F "tokens=2 skip=3" %%j IN (inf_share_folder.txt) DO cacls %%j  					>> %tnd%\result.txt
	type %tnd%\result.txt | findstr /i "everyone" > nul
	if NOT ERRORLEVEL 1 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
	if ERRORLEVEL 1 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
)
:: winver >= 2003
if %WinVer% geq 2 (	
	fsutil fsinfo drives 																	 > %tnd%\inf_using_drv_temp1.txt
	type inf_using_drv_temp1.txt | find /i "\" 												 > %tnd%\inf_using_drv_temp2.txt

	echo.																					 > %tnd%\inf_using_drv_temp3.txt
	FOR /F "tokens=1-26" %%a IN (inf_using_drv_temp2.txt) DO (
		echo %%a >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%b >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%c >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%d >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%e >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%f >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%g >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%h >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%i >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%j >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%k >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%l >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%m >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%n >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%o >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%p >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%q >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%r >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%s >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%t >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%u >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%v >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%w >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%x >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%y >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%z >> %tnd%\inf_using_drv_temp3.txt 2> nul
	)
	type inf_using_drv_temp3.txt | find /i "\" | find /v "A:\" 								 > %tnd%\inf_using_drv.txt
	
	FOR /F "tokens=1" %%a IN (inf_using_drv.txt) DO (
		type inf_share_folder.txt | find "%%a"												 >> %tnd%\inf_share_folder_temp.txt
	
	)
	
	%script%\sed "s/   */?/g" %tnd%\inf_share_folder_temp.txt 							 > %tnd%\inf_share_folder_temp_sed.txt
	type inf_share_folder_temp_sed.txt | findstr "^?"										 > %tnd%\inf_share_folder_temp_sed2.txt
	
	for /F "tokens=2 delims= " %%a in (inf_share_folder_temp.txt) do cacls ^"%%a^"		 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	for /F "tokens=2 delims=?" %%a in (inf_share_folder_temp_sed.txt) do cacls ^"%%a^"		 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	for /F "tokens=1 delims=?" %%a in (inf_share_folder_temp_sed2.txt) do cacls ^"%%a^"		 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	
	for /F "tokens=2 delims= " %%a in (inf_share_folder_temp.txt) do cacls ^"%%a^"		 >> %tnd%\result.txt
	for /F "tokens=2 delims=?" %%a in (inf_share_folder_temp_sed.txt) do cacls ^"%%a^"        >> %tnd%\result.txt 
	for /F "tokens=1 delims=?" %%a in (inf_share_folder_temp_sed2.txt) do cacls ^"%%a^"		  >> %tnd%\result.txt
	
	type %tnd%\result.txt | findstr /i "everyone" 2>nul
	if NOT ERRORLEVEL 1 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
	if ERRORLEVEL 1 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Everyone 권한이 존재하지 않습니다.														>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
	
)

del %tnd%\result.txt 2>nul
chcp 437
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0201 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0202 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
set result0202=Default
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################            2.02 하드디스크 기본 공유 제거          ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 기본공유 항목(C$, D$)이 존재하지 않고 AutoShareServer 레지스트리 값이 0일 경우 양호           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ☞ 하드디스크 기본 공유 확인                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net share | FIND /V "IPC$" | FIND /V "command PRINT$ FAX$" | FIND "$" | findstr /I "^[A-Z]"  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net share | FIND /V "IPC$" | FIND /V "command PRINT$ FAX$" | FIND "$" | findstr /I "^[A-Z]" > nul
if %ERRORLEVEL% EQU 1 (
echo 기본 공유 폴더가 존재 하지 않습니다.													>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ☞ Registry 설정								                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters\AutoShareServer" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
::%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters\AutoShareServer" | %script%\awk -F" " {print$3} > defaultshare.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

net share | FIND /V "IPC$" | FIND /V "command PRINT$ FAX$" | FIND "$" | findstr /I "^[A-Z]" > nul
IF %ERRORLEVEL% EQU 0 (	
	set result02021=F
) else (
	set result02021=O
)

%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters\AutoShareServer" | find "0" > nul
	if %ERRORLEVEL% EQU 0 (
		set result02022=O
		)
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters\AutoShareServer" | find "0" > nul
	if %ERRORLEVEL% EQU 1 (
		set result02022=F
		)
if not %result02021% == %result02022% (
	echo Result=F                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
	echo Result=%result02021%                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0202 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0203 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################              2.03 불필요한 서비스 제거             ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 시스템에서 필요하지 않는 취약한 서비스가 중지되어 있을 경우 양호                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (1) Alerter(서버에서 클라이언트로 경고메세지를 보냄)                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (2) Clipbook(서버내 Clipbook를 다른 클라이언트와 공유)                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (3) Messenger(Net send 명령어를 이용하여 클라이언트에 메시지를 보냄)          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (4) Simple TCP/IP Services(Echo, Discard, Character, Generator, Daytime, 등)  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | findstr "Alerter ClipBook Messenger"                                             > %tnd%\service.txt
net start | find "Simple TCP/IP Services"                                                    >> %tnd%\service.txt

net start | findstr /I "Alerter ClipBook Messenger TCP/IP" service.txt > NUL
IF ERRORLEVEL 1 ECHO ☞ 불필요한 서비스가 존재하지 않음.                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
IF NOT ERRORLEVEL 1 (
echo ☞ 아래와 같은 불필요한 서비스가 발견되었음.                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type service.txt                                                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | findstr /I "Alerter ClipBook Messenger TCP/IP" service.txt > NUL
IF ERRORLEVEL 1 ECHO Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
IF NOT ERRORLEVEL 1 echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0203 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0204 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################             2.04 IIS 서비스 구동 점검             ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : IIS 서비스가 불필요하게 동작하지 않는 경우 양호(담당자 인터뷰)                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                
if exist iis-enable.txt (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-04-enable
) else (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=Disabled																		>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-04-end
)


:2-04-enable

echo [IIS Version 확인]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type iis-version.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [등록 사이트]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	type website-list.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	type website-name.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

:2-04-end

echo 0204 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0205 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###################           2.05 IIS 디렉토리 리스팅 제거           ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : 기본 설정 및 사이트별 "디렉터리 검색" 설정이 False 이면 양호                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-05-enable
) else (
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-05-end
)

:2-05-enable

echo [등록 사이트]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	type website-list.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	type website-name.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [기본 설정]                                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	%systemroot%\System32\inetsrv\appcmd list config | find /i "directoryBrowse"             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%systemroot%\System32\inetsrv\appcmd list config | find /i "directoryBrowse"             > %tnd%\result.txt
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	cscript %script%\adsutil.vbs get W3SVC/EnableDirBrowsing  | find /i /v "Microsoft"      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cscript %script%\adsutil.vbs get W3SVC/EnableDirBrowsing  | find /i /v "Microsoft"      > %tnd%\result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo *** 사이트별 설정 확인                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	for /f "delims=" %%i in (website-name.txt) do (
		echo [WebSite Name] %%i                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%systemroot%\System32\inetsrv\appcmd list config %%i | find /i "directoryBrowse"       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%systemroot%\System32\inetsrv\appcmd list config %%i | find /i "directoryBrowse"      >> %tnd%\result.txt
		echo.                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	for /f "tokens=1 delims=[]" %%i in (website-list.txt) do (
		echo [WebSite AppRoot] %%i                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		cscript %script%\adsutil.vbs enum %%i/root | find /i "EnableDirBrowsing" > nul
		if not errorlevel 1 (
			cscript %script%\adsutil.vbs enum %%i/root | find /i "EnableDirBrowsing"         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			cscript %script%\adsutil.vbs enum %%i/root | find /i "EnableDirBrowsing"         >> %tnd%\result.txt
			echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		) else (
			echo * 기본 설정이 적용되어 있음.                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
	)
)

type result.txt | find /i "true" > nul
if %errorlevel% equ 0 (
echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=true												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=false												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

:2-05-end
echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
del %tnd%\result.txt 2>nul
echo 0205 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0206 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###################               2.06 IIS CGI 실행 제한              ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : C:\inetpub\scripts 와 C:\inetpub\cgi-bin 디렉터리를 사용하지 않는 경우 양호     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 사용 시 Everyone에 모든권한, 수정권한, 쓰기권한이 부여되어 있지 않은 경우 양호  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2.06-end
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

IF EXIST C:\inetpub\scripts (
	cacls C:\inetpub\scripts                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cacls C:\inetpub\scripts                                                                 > %tnd%\result.txt
	echo.                                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) ELSE (
	echo C:\inetpub\scripts 디렉터리가 존재하지 않음.                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

IF EXIST C:\inetpub\cgi-bin (
	cacls C:\inetpub\cgi-bin                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cacls C:\inetpub\cgi-bin                                                                >> %tnd%\result.txt
) ELSE (
	echo C:\inetpub\cgi-bin 디렉터리가 존재하지 않음.                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type %tnd%\result.txt | find /i /v "(ID)R" | find /i "everyone" > nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

:2.06-end
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0206 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0207 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###################          2.07 IIS 상위 디렉토리 접근 금지         ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : "상위 경로 사용" 옵션이 체크되어 있지 않을 경우 양호                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : (asp enableParentPaths="false" 인 경우 양호)                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-07-enable
) else (
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-07-end
)

:2-07-enable
echo [등록 사이트]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	type website-list.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	type website-name.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [기본 설정]                                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	%systemroot%\System32\inetsrv\appcmd list config /section:asp | find /i "enableParentPaths" > nul
	IF NOT ERRORLEVEL 1 (
		%systemroot%\System32\inetsrv\appcmd list config /section:asp | find /i "enableParentPaths" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%systemroot%\System32\inetsrv\appcmd list config /section:asp | find /i "enableParentPaths" > %tnd%\result.txt
	) ELSE (
		echo * 설정값 없음 * 기본설정 : enableParentPaths=false                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	cscript %script%\adsutil.vbs get W3SVC/AspEnableParentPaths  | find /i /v "Microsoft"    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cscript %script%\adsutil.vbs get W3SVC/AspEnableParentPaths  | find /i /v "Microsoft"    > %tnd%\result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo *** 사이트별 설정 확인                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	for /f "delims=" %%i in (website-name.txt) do (
		%systemroot%\System32\inetsrv\appcmd list config %%i /section:asp | find /i "enableParentPaths" > nul
		echo [WebSite Name] %%i                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		if not errorlevel 1 (
			%systemroot%\System32\inetsrv\appcmd list config %%i /section:asp | find /i "enableParentPaths" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			%systemroot%\System32\inetsrv\appcmd list config %%i /section:asp | find /i "enableParentPaths" >> %tnd%\result.txt
			echo.                                                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		) else (
			echo * 설정값 없음 * 기본설정 : enableParentPaths=false                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
	)
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	for /f "tokens=1 delims=[]" %%i in (website-list.txt) do (
		echo [WebSite AppRoot] %%i                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		cscript %script%\adsutil.vbs enum %%i/root | find /i "AspEnableParentPaths" > nul
		if not errorlevel 1 (
			cscript %script%\adsutil.vbs enum %%i/root | find /i "AspEnableParentPaths"     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			cscript %script%\adsutil.vbs enum %%i/root | find /i "AspEnableParentPaths"     >> %tnd%\result.txt
			echo.                                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		) else (
			echo AspEnableParentPaths : * 기본 설정이 적용되어 있음.                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
	)
)



type result.txt | find /i "true" > nul
if %errorlevel% equ 0 (
echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=true												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=false												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:2-07-end
del %tnd%\result.txt 2>nul
echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0207 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0208 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###################            2.08 IIS 불필요한 파일 제거            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : IISSamples, IISHelp 가상디렉터리가 존재하지 않을 경우 양호                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 		 (IIS 7.0 이상 버전 해당 사항 없음)						                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-08-enable
) else (
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-08-end
)

:2-08-enable
echo [가상 디렉터리 설정 현황]                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	echo ☞ IIS 7.0 이상 버전 해당 사항 없음							                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

::20160114 수정함(해당사항 없음으로 변경함)
::if %iis_ver_major% geq 7 (
	::%systemroot%\System32\inetsrv\appcmd list config -section:system.applicationHost/sites | find /i "virtualdirectory" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
::)

::20160114 수정함(IISSample 등 없는지 판단가능하게 변경함)
:: iis ver <= 6
::if %iis_ver_major% leq 6 (
	::%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\Virtual Roots" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
::)

if %iis_ver_major% leq 6 (
	%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\Virtual Roots" | findstr "IISSamples IISHelp" >> %tnd%\sample-app.txt
	type sample-app.txt                                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	findstr "IISSamples IISHelp" sample-app.txt > NUL
	IF ERRORLEVEL 1 (
		ECHO * 점검결과: IISSamples, IISHelp 가상디렉터리가 존재하지 않음.                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt		
	)	ELSE (
		ECHO * 점검결과: IISSamples, IISHelp 가상디렉터리가 존재함.                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt				
	)
)

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

:2-08-end
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0208 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0209 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###################          2.09 IIS 웹 프로세스 권한 제한           ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : IIS 서비스 동작 계정이 관리자 계정으로 등록되어 있지 않으면 양호                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2.09-end
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [World Wide Web Publishing Service 동작 계정]                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\ObjectName"                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\ObjectName"                 >> %tnd%\result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [IIS Admin Service 동작 계정]                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\IISADMIN\ObjectName"              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\IISADMIN\ObjectName"              >> %tnd%\result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type %tnd%\result.txt | find "LocalSystem" > nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:2.09-end
del %tnd%\result.txt 2>nul
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0209 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0210 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###################               2.10 IIS 링크 사용금지              ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : 웹 사이트 홈디렉터리에 심볼릭 링크, aliases, *.lnk 파일이 존재하지 않으면 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-10-enable
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-10-end
)

:2-10-enable
echo [등록 사이트]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	type website-list.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	type website-name.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

:: iis ver >= 7
if %iis_ver_major% geq 7 (
	echo [홈디렉토리 정보 - WEB/FTP 구분용]                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%systemroot%\System32\inetsrv\appcmd list config -section:system.applicationHost/sites | findstr /i "name protocol physicalpath" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo *** 사이트별 불필요 파일 체크                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
for /f "delims=" %%a in (website-physicalpath.txt) do (
	echo [Website HomeDir] %%a                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	call cd /d %%a			2>nul
	attrib /s | find /i ".lnk"                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	attrib /s | find /i ".lnk"                                                                >> %tnd%\%result.txt
	cd /d %tnd%
	echo.                                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ※ 결과 값이 존재하지 않으면 양호                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type %tnd%\result.txt | find ".lnk" > nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)


:2-10-end
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
del %tnd%\result.txt 2>nul
echo 0210 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0211 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###################       2.11 IIS 파일 업로드 및 다운로드 제한       ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : 웹 서비스의 서버 자원관리를 위해 업로드 및 다운로드 용량을 제한한 경우 양호     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 참고 : 7.0이상(maxAllowedContentLength: 콘텐츠 용량 제한 설정 /Default: 30MB)                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 7.0이상(MaxRequestEntityAllowed: 파일 업로드 용량 제한 설정 /Default: 200000 bytes)    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 7.0이상(bufferingLimit: 파일 다운로드 용량 제한 설정 /Default: 4MB(4194304 bytes))     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 6.0이하(AspMaxRequestEntityAllowed : 업로드 용량 제한 설정 /Default: 200KB(204800 byte)) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 6.0이하(AspBufferingLimit : 다운로드 용량 제한 설정 /Default: 4MB(4194304 byte)) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-11-enable
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt	
	goto 2-11-end
)

:2-11-enable
echo [등록 사이트]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	type website-list.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	type website-name.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [기본 설정]                                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	%systemroot%\System32\inetsrv\appcmd list config | findstr /i "maxAllowedContentLength maxRequestEntityAllowed bufferingLimit" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	cscript %script%\adsutil.vbs enum W3SVC | findstr /i "AspMaxRequestEntityAllowed AspBufferingLimit" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo * 값이 없을 경우 기본 설정이 적용되어 있음.                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo *** 사이트별 설정 확인                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	for /f "delims=" %%a in (website-name.txt) do (
		echo [WebSite Name] %%a                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%systemroot%\System32\inetsrv\appcmd list config %%a | findstr /i "maxAllowedContentLength maxRequestEntityAllowed bufferingLimit" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo * 값이 없을 경우 기본 설정이 적용되어 있음.                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	for /f "tokens=1 delims=[]" %%i in (website-list.txt) do (
		echo [WebSite AppRoot] %%i                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		cscript %script%\adsutil.vbs enum %%i | find /i "AspMaxRequestEntityAllowed" > nul
		if not errorlevel 1 (
			cscript %script%\adsutil.vbs enum %%i | find /i "AspMaxRequestEntityAllowed"  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		) else (
			echo AspMaxRequestEntityAllowed : * 기본 설정이 적용되어 있음.                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
		cscript %script%\adsutil.vbs enum %%i | find /i "AspBufferingLimit" > nul
		if not errorlevel 1 (
			cscript %script%\adsutil.vbs enum %%i | find /i "AspBufferingLimit"           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		) else (
			echo AspBufferingLimit          : * 기본 설정이 적용되어 있음.                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
	)
)

echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


:2-11-end
echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0211 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0212 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###################           2.12 IIS DB 연결 취약점 점검            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : 7.0이상- 요청 필터링에서 .asa, .asax 확장자가 False로 설정되어 있으면 양호     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo                   요청 필터링에서 .asa, .asax 확장자가 True로 설정되어 있을 경우        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo                   .asa, .asax 매핑이 등록되어 있어야 양호                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo                   (만약, Global.asa 파일을 사용하지 않는 경우 해당 사항 없음.)           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo                 > (1) fileExtension=".asa" allowed="false" 이면 양호                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo                 > (2) fileExtension=".asa" allowed="true" 이면, .asa 맵핑 확인           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo   	    : 6.0이하- .asa 매핑이 존재할 경우 양호                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo                   (설정 예) ".asa,C:\WINDOWS\system32\inetsrv\asp.dll,5,GET,HEAD,POST,TRACE" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo                    GET,HEAD,POST,TRACE 동사: 다음으로 제한								 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-12-enable
) else (
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt	
	goto 2-12-end
)

:2-12-enable
echo [등록 사이트]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	type website-list.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	type website-name.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [기본 설정]                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	%systemroot%\System32\inetsrv\appcmd list config | find /i ".asa" | find /i /v "httpforbiddenhandler" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	cscript %script%\adsutil.vbs enum W3SVC | find /i ".asa"                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo *** 사이트별 설정 확인                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	for /f "delims=" %%a in (website-name.txt) do (
		echo [WebSite Name] %%a                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%systemroot%\System32\inetsrv\appcmd list config %%a | find /i ".asa" | find /i /v "httpforbiddenhandler" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	for /f "tokens=1 delims=[]" %%i in (website-list.txt) do (
		echo [WebSite AppRoot] %%i                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		cscript %script%\adsutil.vbs enum %%i/root | find /i ".asa" > nul
		if not errorlevel 1 (
			cscript %script%\adsutil.vbs enum %%i/root | find /i ".asa"                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo.                                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		) else (
			cscript %script%\adsutil.vbs enum %%i/root | find /i "ScriptMaps" > nul
			if not errorlevel 1 (
				echo .asa 맵핑이 등록되어 있지 않음. [취약]                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
				echo.                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			) else (
				echo * 기본 설정이 적용되어 있음.                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
				echo.                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			)
		)
	)
)
echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt	
:2-12-end
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0212 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0213 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###################            2.13 IIS 가상 디렉토리 삭제            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : 해당 웹사이트에 IIS Admin, IIS Adminpwd 가상 디렉터리가 존재하지 않을 경우 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo        : IIS 6.0 이상 버전 해당 사항 없음 												 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-13-enable
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-13-end
)

:2-13-enable
echo [가상 디렉터리 설정 현황]                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
rem ##########20160114 6.0 이상 해당 사항 없음으로 소스 수정 시작##########
:: iis ver >= 6
if %iis_ver_major% geq 6 (
echo ☞ IIS 6.0 이상 버전 해당 사항 없음 												 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt	
echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 2-13-end
)

:: iis ver < 5
if %iis_ver_major% lss 5 (
	%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\Virtual Roots" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\Virtual Roots" >> %tnd%\result.txt
)
type %tnd%\result.txt | find /i "IIS" | findstr /I "Admin Adminpwd" > nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
rem ##########20160114 6.0 이상 해당 사항 없음으로 소스 수정 끝##########


rem ##########20160114 6.0 이상 해당 사항 없음으로 소스 삭제 시작##########
:: iis ver >= 7
::if %iis_ver_major% geq 7 (
	::%systemroot%\System32\inetsrv\appcmd list config -section:system.applicationHost/sites | find /i "virtualdirectory" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
::)
:: iis ver <= 6
::if %iis_ver_major% leq 6 (
	::%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\Virtual Roots" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
::)
rem ##########20160114 6.0 이상 해당 사항 없음으로 소스 삭제 끝##########
del %tnd%\result.txt 2>nul
:2-13-end
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0213 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0214 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###################           2.14 IIS 데이터 파일 ACL 적용           ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : 홈 디렉터리 내에 있는 파일들에 대해 Everyone 권한이 존재하지 않을 경우 양호   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : (정적컨텐트 파일은 Read 권한만)                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Enable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-14-enable
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-14-end
)

:2-14-enable
echo [등록 사이트]                                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	type website-list.txt                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	type website-name.txt                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo *** 사이트별 파일 Everyone 권한 체크                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo (exe, dll, cmd, pl, asp, inc, shtm, shtml, txt, gif, jpg, html)                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
for /f "delims=" %%a in (website-physicalpath.txt) do (
	echo [Website HomeDir] %%a                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2> nul
	echo -----------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	call cd /d %%a 2> nul																				
	cd 2> nul
	cacls *.exe /t | find /i "everyone"                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2> nul
	cacls *.dll /t | find /i "everyone"                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2> nul
	cacls *.cmd /t | find /i "everyone"                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2> nul
	cacls *.pl /t | find /i "everyone"                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2> nul
	cacls *.asp /t | find /i "everyone"                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2> nul
	cacls *.inc /t | find /i "everyone"                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2> nul
	cacls *.shtm /t | find /i "everyone"                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2> nul
	cacls *.shtml /t | find /i "everyone"                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2> nul
	cacls *.txt /t | find /i "everyone"                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2> nul
	cacls *.gif /t | find /i "everyone"                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2> nul
	cacls *.jpg /t | find /i "everyone"                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2> nul
	cacls *.html /t | find /i "everyone"                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2> nul
	cacls *.exe /t | find /i "everyone"                                                      >> %tnd%\result.txt 2> nul
	cacls *.dll /t | find /i "everyone"                                                      >> %tnd%\result.txt 2> nul
	cacls *.cmd /t | find /i "everyone"                                                      >> %tnd%\result.txt 2> nul
	cacls *.pl /t | find /i "everyone"                                                       >> %tnd%\result.txt 2> nul
	cacls *.asp /t | find /i "everyone"                                                      >> %tnd%\result.txt 2> nul
	cacls *.inc /t | find /i "everyone"                                                      >> %tnd%\result.txt 2> nul
	cacls *.shtm /t | find /i "everyone"                                                     >> %tnd%\result.txt 2> nul
	cacls *.shtml /t | find /i "everyone"                                                    >> %tnd%\result.txt 2> nul
	cacls *.txt /t | find /i "everyone"                                                      >> %tnd%\result.txt 2> nul
	cacls *.gif /t | find /i "everyone"                                                      >> %tnd%\result.txt 2> nul
	cacls *.jpg /t | find /i "everyone"                                                      >> %tnd%\result.txt 2> nul
	cacls *.html /t | find /i "everyone"                                                     >> %tnd%\result.txt 2> nul
	cd /d %tnd% 2> nul
	echo.                                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) 2> nul
echo ※ 결과 값이 존재하지 않으면 양호                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type %tnd%\result.txt | find /i "everyone" > nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

:2-14-end
del %tnd%\result.txt 2>nul
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0214 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0215 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###################         2.15 IIS 미사용 스크립트 매핑 제거        ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : 아래와 같은 취약한 매핑이 존재하지 않을 경우 양호(Windows 20003 이후 버전은 패치가 되어 양호함)                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : (.htr .idc .stm .shtm .shtml .printer .htw .ida .idq)                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-15-enable
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-15-end
)

:2-15-enable
if %WinVer% geq 2 (
	echo ☞ Windows 2003 이후 버전은 패치가 되어 해당사항 없음							>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-15-end
) else (
	echo [등록 사이트]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	:: iis ver >= 7
	if %iis_ver_major% geq 7 (
		type website-list.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
	:: iis ver <= 6
	if %iis_ver_major% leq 6 (
		type website-name.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

	:: iis ver >= 7
	if %iis_ver_major% geq 7 (
		echo [미사용 스크립트 매핑 확인]                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%systemroot%\System32\inetsrv\appcmd list config | find /i "scriptprocessor" | findstr /i ".htr .idc .stm .shtm .shtml .printer .htw .ida .idq" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo ※ 결과 값이 존재하지 않으면 양호                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)

	:: iis ver <= 6
	if %iis_ver_major% leq 6 (
		echo [기본 설정]                                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		cscript %script%\adsutil.vbs enum W3SVC | findstr /i ".htr .idc .stm .shtm .shtml .printer .htw .ida .idq" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		cscript %script%\adsutil.vbs enum W3SVC | findstr /i ".htr .idc .stm .shtm .shtml .printer .htw .ida .idq" >> %tnd%\result.txt
		echo ※ 결과 값이 존재하지 않으면 양호                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

		echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo *** 사이트별 설정 확인                                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		for /f "tokens=1 delims=[]" %%i in (website-list.txt) do (
			echo [WebSite AppRoot] %%i                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo -----------------------------------------------------------------------        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			cscript %script%\adsutil.vbs enum %%i/root | findstr /i ".htr .idc .stm .shtm .shtml .printer .htw .ida .idq" > nul
			if not errorlevel 1 (
				cscript %script%\adsutil.vbs enum %%i/root | findstr /i ".htr .idc .stm .shtm .shtml .printer .htw .ida .idq" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
				cscript %script%\adsutil.vbs enum %%i/root | findstr /i ".htr .idc .stm .shtm .shtml .printer .htw .ida .idq" >> %tnd%\result.txt
				echo.                                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			) else (
				cscript %script%\adsutil.vbs enum %%i/root | find /i "ScriptMaps" > nul
				if not errorlevel 1 (
					echo * 취약한 맵핑이 등록되어 있지 않음. [양호]                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
					echo.                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
				) else (
					echo * 기본 설정이 적용되어 있음.                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
					echo.                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
				)
			)
		)
	)
)

type %tnd%\result.txt | findstr /i ".htr .idc .stm .shtm .shtml .printer .htw .ida .idq" > nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)


del %tnd%\result.txt 2>nul
:2-15-end
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0215 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0216 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###################         2.16 IIS Exec 명령어 쉘 호출 진단         ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : 해당 서비스의 레지스트리 값이 0일 경우 양호                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : (참고1) IIS 5.0 버전에서 해당 레지스트리 값이 없을 경우 양호                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : (참고2) IIS 6.0 이상 양호                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-16-enable
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-16-end
)

:2-16-enable
:: iis ver >= 6
if %iis_ver_major% geq 6 (
	echo ☞ IIS 6.0 이상 양호			                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-16-end
)

:: iis ver < 6
if %iis_ver_major% lss 6 (
	echo [Registry 설정] 			                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\SSIEnableCmdDirective" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\SSIEnableCmdDirective" >> %tnd%\result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)


type %tnd%\result.txt | find /V "0" | findstr /i "SSIEnableCmdDirective" > nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
del %tnd%\result.txt 2>nul

:2-16-end
echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0216 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0217 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###################             2.17 IIS WebDAV 비활성화              ##################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : 다음 중 한 가지라도 해당되는 경우 양호                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 1. IIS 를 사용하지 않을 경우                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 2. DisableWebDAV 값이 1로 설정되어 있을경우                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 3. Windows NT, 2000은 서비스팩 4 이상이 설치되어 있을 경우                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 4. Windows 2003, Windows 2008은 WebDAV 가 금지 되어 있을 경우                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 참고 : "0,C:\WINDOWS\system32\inetsrv\httpext.dll,0,WEBDAV,WebDAV" (WebDAV 금지-양호) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : "1,C:\WINDOWS\system32\inetsrv\httpext.dll,0,WEBDAV,WebDAV" (WebDAV 허용-취약) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 2008 이상인 경우 allowed="false"   (WebDAV 금지-양호) 						>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 2008 이상인 경우 allowed="True"    (WebDAV 허용-취약) 						 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-17-enable
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-17-end
)

:2-17-enable

:: winver = 2000
if %WinVer% equ 1 (
	ECHO ☞ Win 2000일 경우 서비스팩 4 이상 양호                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type systeminfo.txt | find /i "kernel version"                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type systeminfo.txt | find /i "service pack"                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type systeminfo.txt | find /i "os version" | find /i /v "bios" | %script%\awk -F" " {print$6}	> %tnd%\result.txt
	goto 2.17-2000
	echo.
)

:: iis ver =< 6
if %iis_ver_major% leq 6 (
	echo [WebDAV 동작 확인]                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\adsutil.vbs enum W3SVC | find /i "webdav" | find /v "WebDAV;WEBDAV"            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\adsutil.vbs enum W3SVC | find /i "webdav" | find /v "WebDAV;WEBDAV"            > %tnd%\result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2.17-2003
)


:: iis ver >=7
if %iis_ver_major% geq 6 (
	echo [WebDAV 동작 확인]                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%systemroot%\System32\inetsrv\appcmd list config -section:isapiCgiRestriction | find /i "webdav" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%systemroot%\System32\inetsrv\appcmd list config -section:isapiCgiRestriction | find /i "webdav" > %tnd%\result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2.17-2008
)

:2.17-2003
type result.txt | find "1," >nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 2-17-end
)

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 2-17-end



:2.17-2008	
type result.txt | find /i "true" >nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 2-17-end
)

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 2-17-end


:2-17-end
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [참고 - Registry 설정(DisableWebDAV)]                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\registry\DisableWebDAV" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\DisableWebDAV"  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ※ 결과 값이 존재하지 않을 경우 다른 참고정보 검토                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [참고 - OS Version, Service Pack]                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	type systeminfo.txt | find /i "kernel version"                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type systeminfo.txt | find /i "service pack"                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

:: winver >= 2003
if %WinVer% geq 2 (
	type systeminfo.txt | find /i "os name"                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type systeminfo.txt | find /i "os version" | find /i /v "bios"                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
del %tnd%\result.txt 2>nul
echo 0217 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0218 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################         2.18 NetBIOS 바인딩 서비스 구동 점검       ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: TCP/IP와 NetBIOS 간의 바인딩이 제거 되어있는 경우 양호                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (NetBIOS 사용 안함 설정: NetbiosOptions 0x2 양호)                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (NetBIOS 사용 설정: NetbiosOptions 0x1 취약)                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (기본 값: NetbiosOptions 0x0 취약)                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (수동점검 방법) 인터넷 프로토콜(TCP/IP)의 등록정보 ▶ 고급 ▶ Wins 탭의 TCP/IP에서 NetBIOS 사용 안함 (139포트차단) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" | findstr /iv "listing" > 2-18-netbios-list.txt
	for /f "tokens=1 delims=[" %%a in (2-18-netbios-list.txt) do echo %%a >> 2-18-netbios-list-1.txt
	for /f "tokens=1 delims=]" %%a in (2-18-netbios-list-1.txt) do echo %%a >> 2-18-netbios-list-2.txt
	FOR /F %%a IN (2-18-netbios-list-2.txt) do echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\%%a\NetbiosOptions >> 2-18-netbios-query.txt
	FOR /F %%a IN (2-18-netbios-query.txt) do %script%\reg query %%a >> 2-18-netbios-result.txt
	echo [NetBIOS over TCP/IP 설정 현황]                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	TYPE 2-18-netbios-result.txt	                            							>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: winver >= 2003
if %WinVer% geq 2 (
	reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" /s | findstr . >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2>nul
)
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0218 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0219 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo #########################        2.19 FTP 서비스 구동 점검          ######################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : FTP 서비스를 사용하지 않는 경우 양호 (이용 목적은 담당자인터뷰)                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist ftp-enable.txt (
	echo ☞ FTP Service Enable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	net start | findstr /i "ftp"                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-19-enable
) else (
	echo ☞ FTP Service Disable                                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-19-end
)

:2-19-enable


echo [등록 사이트]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ftp_ver_major% geq 7 (
	type ftpsite-list.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: iis ver <= 6
if %iis_ftp_ver_major% leq 6 (
	type ftpsite-name.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


:2-19-end
echo 0219 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0220 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo #####################        2.20 FTP 디렉토리 접근권한 설정          ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : FTP 홈 디렉터리에 Everyone의 접근 권한이 존재하지 않으면 양호				              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist ftp-enable.txt (
	echo ☞ FTP Service Enable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	net start | findstr /i "ftp"                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-20-enable
) else (
	echo ☞ FTP Service Disable                                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-20-end
)


:2-20-enable
:: iis ver = 0
if %iis_ftp_ver_major%==0 (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ 윈도우 기본 FTP외 타 FTP 서비스 사용중 (수동확인^)                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-20-end
)
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [등록 사이트]                                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ftp_ver_major% geq 7 (
	type ftpsite-list.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: iis ver <= 6
if %iis_ftp_ver_major% leq 6 (
	type ftpsite-name.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

:: iis ver >= 7
if %iis_ftp_ver_major% geq 7 (
	echo [홈디렉토리 정보 - WEB/FTP 구분용]                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%systemroot%\System32\inetsrv\appcmd list config -section:system.applicationHost/sites | findstr /i "name protocol physicalpath" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo *** 사이트별 홈디렉토리 접근권한 확인                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
for /f "delims=" %%a in (ftpsite-physicalpath.txt) do (
	echo [FtpSite HomeDir] %%a                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	call cacls %%a                                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	call cacls %%a                                                                          >> %tnd%\result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type %tnd%\result.txt | findstr /i "everyone" > nul
if %ERRORLEVEL% NEQ 0 (
 echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
if %ERRORLEVEL% EQU 0 (
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
del %tnd%\result.txt 2>nul



:2-20-end
echo 0220 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0221 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###########################         2.21 Anonymous FTP 금지          ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : FTP를 사용하지 않거나 "익명 연결 허용"이 체크되어 있지 않은 경우 양호(Default : 사용 안 함)          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 참고 : metabase.xml 파일 기준 설명        											 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : IIsFtpService	Location ="/LM/MSFTPSVC" 는 FTP 사이트 기본 설정                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : FTP 사이트를 새로 생성 시 해당 기본 설정을 적용 받음.							 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : IIsFtpServer	Location ="/LM/MSFTPSVC/ID"는 FTP 사이트에 등록된 개별 사이트 설정 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 개별 사이트에 AllowAnonymous 설정이 없으면 FTP 사이트 기본 설정을 적용 받음   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : IIsFtpServer	Location ="/LM/MSFTPSVC/~/Public FTP Site"는 진단 시 고려하지 안함 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist ftp-enable.txt (
	echo ☞ FTP Service Enable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	net start | findstr /i "ftp"                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-21-enable
) else (
	echo ☞ FTP Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-21-end
)

:2-21-enable
:: iis ver = 0
if %iis_ftp_ver_major%==0 (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ 윈도우 기본 FTP외 타 FTP 서비스 사용중                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-21-end
)

echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [등록 사이트]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ftp_ver_major% geq 7 (


	type ftpsite-list.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo [FTP 서버 설정 확인]                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%systemroot%\System32\inetsrv\appcmd list config -section:system.applicationHost/sites | findstr /i "name protocol anonymousAuthentication enabled" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%systemroot%\System32\inetsrv\appcmd list config -section:system.applicationHost/sites | findstr /i "name protocol anonymousAuthentication enabled" > %tnd%\result.txt
	echo.                                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-218-enable	
) 
	type ftpsite-name.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo [기본 설정]                                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cscript %script%\adsutil.vbs enum MSFTPSVC | find /i "AllowAnonymous"                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cscript %script%\adsutil.vbs enum MSFTPSVC | find /i "AllowAnonymous"                   > %tnd%\result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo *** 사이트별 설정 확인                                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	for /f "tokens=1 delims=[]" %%i in (ftpsite-list.txt) do (
		echo [FtpSite AppRoot] %%i                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		cscript %script%\adsutil.vbs enum %%i | find /i "AllowAnonymous" > nul
		if not errorlevel 1 (
			cscript %script%\adsutil.vbs enum %%i | find /i "AllowAnonymous"                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			cscript %script%\adsutil.vbs enum %%i | find /i "AllowAnonymous"                 > %tnd%\result.txt
			echo.                                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			goto 2-213-enable
		) 
			echo AllowAnonymous : 기본 설정이 적용되어 있음.                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo AllowAnonymous : 기본 설정이 적용되어 있음.                                 > %tnd%\result.txt
			echo.                                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 2-213-enable
	)


::7이상
:2-218-enable
type %tnd%\result.txt | find /i "anonymousAuthentication" | find /i "true" > nul
::echo %errorlevel%
if %errorlevel% neq 0 (
	echo Result=false												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-21-end
) else (
	echo Result=true												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-21-end
)



:2-213-enable
::6미만
type %tnd%\result.txt | find /i "AllowAnonymous" | find /i "True" > nul
if %errorlevel% neq 0 (
 echo Result=false												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-21-end
)
echo Result=true												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt



:2-21-end
del %tnd%\result.txt 2>nul
echo 0221 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0222 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###########################        2.22 FTP 접근 제어 설정          ######################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준 : FTP 서비스에 접근제한 설정이 되어 있는 경우 양호				                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 참고 : metabase.xml 파일 기준 설명        												 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : IIsFtpService	Location ="/LM/MSFTPSVC" 는 FTP 사이트 기본 설정               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : IIsFtpVirtualDir	Location ="/LM/MSFTPSVC/ID/ROOT"는 FTP 개별 사이트 설정      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 개별 사이트에 IPSecurity 설정이 없으면 FTP 사이트 기본 설정을 적용 받음       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : IPSecurity="" 접근제어 없음, IPSecurity="0102~" 접근제어 설정 있음.           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 마지막에 사이트명이 붙지 않은 설정 내용은 점검시 고려 안함.                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : 2008이상 ipSecurity allowUnlisted 설정이 False로 되어야 양호                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■      : ipSecurity allowUnlisted True경우 액세스 허용 / False 경우 액세스 거부         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist ftp-enable.txt (
	echo ☞ FTP Service Enable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	net start | findstr /i "ftp"                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-22-enable
) else (
	echo ☞ FTP Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-22-end
)

:2-22-enable
:: iis ver = 0
if %iis_ftp_ver_major%==0 (
	echo ☞ 윈도우 기본 FTP외 타 FTP 서비스 사용중 (수동확인^)                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-22-end
)
echo [등록 사이트]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ftp_ver_major% geq 7 (
	type ftpsite-list.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: iis ver <= 6
if %iis_ftp_ver_major% leq 6 (
	type ftpsite-name.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

:: iis ver >= 7
if %iis_ftp_ver_major% geq 7 (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo *** 사이트별 FTP 접근제어 설정 확인                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	
	for /f "delims=" %%a in (ftpsite-name.txt) do (
		%systemroot%\System32\inetsrv\appcmd list config %%a /section:ipsecurity | find /i "ipAddress" > nul
		echo [FTP-Site Name] %%a                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		if not errorlevel 1 (
			%systemroot%\System32\inetsrv\appcmd list config %%a /section:ipsecurity | find /i "ipAddress" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			%systemroot%\System32\inetsrv\appcmd list config %%a /section:ipsecurity | find /i "ipAddress" >> %tnd%\result.txt
			%systemroot%\System32\inetsrv\appcmd list config %%a /section:ipsecurity | find /i "ipSecurity AllowUnlisted" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			%systemroot%\System32\inetsrv\appcmd list config %%a /section:ipsecurity | find /i "ipSecurity AllowUnlisted" >> %tnd%\result.txt
			echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		) else (
			echo * 접근제한 설정 없음                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			)
		)
)
:: iis ver <= 6
if %iis_ftp_ver_major% leq 6 (
	echo [FTP 접근제어 설정]                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cscript %script%\ftp_ipsecurity.vbs >nul
	type ftp-ipsecurity.txt                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)



if %iis_ftp_ver_major% geq 7 (
	goto 2-227-enable
) 
if %iis_ftp_ver_major% leq 6 (
	goto 2-226-enable
)

:2-227-enable
type %tnd%\result.txt | find "ipSecurity allowUnlisted" | find "true" > nul
	if %ERRORLEVEL% NEQ 0 (
		echo Result=false												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
		echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
	if %ERRORLEVEL% EQU 0 (
		echo Result=true												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
		echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
)
del %tnd%\result.txt 2>nul	
goto 2-22-end

:2-226-enable
type ftp-ipsecurity.txt | find "SiteName" | find "Access Allow" > nul
		if %ERRORLEVEL% NEQ 0 (
			echo Result=false												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
			echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
		if %ERRORLEVEL% EQU 0 (
			echo Result=true												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
			echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)	
)
del %tnd%\ftp-ipsecurity.txt 2>nul

:2-22-end
echo 0222 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0223 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################             2.23 DNS Zone Transfer 설정            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: DNS 서비스 설정이 아래 기준 중 하나라도 해당되는 경우 양호(SecureSecondaries 2) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (1) DNS 서비스를 사용하지 않을 경우                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (2) 영역 전송 허용을 하지 않을 경우                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (3) 특정 서버로만 영역 전송을 허용하는 경우                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : * 레지스트리값(영역전송 허용안함:3, 아무서버로나:0, 이름서버탭에나열된 서버로만:1, 다음서버로만:2 ) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : [참고]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : 결과 값이 없을 경우 DNS 서버에 등록된 정/역방향 조회 영역이 없는 것으로,      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : DNS 서비스를 사용하지 않을 경우 서비스를 중지할 것을 권고                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "DNS Server" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO ☞ DNS Service Enable                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)	ELSE (
	ECHO ☞ DNS Service Disable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
	goto 0223-end
	echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)


:: winver < 2008R2
if %WinVer% leq 3 (
goto 0223-2008
)

:: winver > 2008
if %WinVer% geq 4 (
 goto 0223-2008R2
)


:0223-2008
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | findstr . | find /v "Listing of" | find /v "system was unable" >nul
	IF %ERRORLEVEL% NEQ 0 (
		reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | find "SecureSecondaries" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | find "SecureSecondaries" >> %tnd%\result.txt
	) else (
		%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | find "SecureSecondaries" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | find "SecureSecondaries" >> %tnd%\result.txt
	)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type %tnd%\result.txt | %script%\awk -F" " {print$3} | find "0" > nul
	if %ERRORLEVEL% NEQ 0 (
		echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
		echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 0223-end
	)
	if %ERRORLEVEL% EQU 0 (
		echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
		echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 0223-end
	)
)

:0223-2008R2
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | findstr . | find /v "Listing of" | find /v "system was unable" >nul
	IF %ERRORLEVEL% NEQ 0 (
		reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | find "SecureSecondaries" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | find "SecureSecondaries" >> %tnd%\result.txt
	) else (
		%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | find "SecureSecondaries" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | find "SecureSecondaries" >> %tnd%\result.txt
	)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type %tnd%\result.txt | find "0x0" > nul
	if %ERRORLEVEL% NEQ 0 (
		echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
		echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 0223-end
	)
	if %ERRORLEVEL% EQU 0 (
		echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
		echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 0223-end
	)
)

:0223-end
del %tnd%\result.txt 2>nul	
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0223 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0224 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################         2.24 RDS (Remote Data Services) 제거       ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 다음의 중 한가지라도 해당되는 경우 양호                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (1) IIS 를 사용하지 않는 경우                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (2) Windows 2000 sp4, Windows 2003 sp2, Windows 2008 이상 양호  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (3) 디폴트 웹사이트에 MSADC 가상 디렉터리가 존재하지 않을 경우                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (4) 해당 레지스트리 값이 존재하지 않을 경우                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2.24-end
)

:: OS Version, Service Pack 버전 체크
echo [OS Version 확인]                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt	
:: winver = 2000
if %WinVer% equ 1 (
	ECHO ☞ Win 2000일 경우 서비스팩 4 이상 양호                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type systeminfo.txt | find /i "kernel version"                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type systeminfo.txt | find /i "service pack"                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type systeminfo.txt | find /i "os version" | find /i /v "bios" | %script%\awk -F" " {print$6}	> %tnd%\result.txt
	goto 2.24-2000
	echo.
)

:: winver >= 2003
if %WinVer% geq 2 (
	ECHO ☞ Windows 2003 sp2 이상, Windows 2008 이상 양호                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type systeminfo.txt | find /i "os name"                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type systeminfo.txt | find /i "os version" | find /i /v "bios"                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if %WinVer% EQU 2 (
	type systeminfo.txt | find /i "os version" | find /i /v "bios" | %script%\awk -F" " {print$6}     > %tnd%\result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2.24-2003
	)

if %WinVer% geq 3 (
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2.24-end
	)

:2.24-2000
type systeminfo.txt | find /i /v "bios" | find /V "N/A" | find /i "os version" >nul
if %errorlevel% neq 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 2.24-2003-0
)

for /f %%r in (result.txt) do set SP=%%r       
if %SP% geq 4 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 2.24-end
)

:2.24-2003-0	
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\Virtual Roots" | find /i "msadc" >> %tnd%\msadcdir.txt
	type msadcdir.txt                                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	find /i "msadc" msadcdir.txt > NUL
	IF ERRORLEVEL 1 (
		ECHO * 점검결과: MSADC 가상디렉터리가 존재하지 않음.                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt		
		goto 2.24-end
)

%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch" /s | findstr /i "RDSServer.DataFactory AdvancedDataFactory VbBusObj.VbbusObjCls" >> %tnd%\RDSREG.txt
type %tnd%\RDSREG.txt                                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	findstr /i "RDSServer.DataFactory AdvancedDataFactory VbBusObj.VbbusObjCls" RESREG.txt > NUL
	IF ERRORLEVEL 1 (
		ECHO * 점검결과: 등록된 REG값이 존재하지 않음.                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt		
		goto 2.24-end
)

		echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt		
		goto 2.24-end
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

:2.24-2003

type systeminfo.txt | find /i /v "bios" | find /V "N/A" | find /i "os version" >nul
if %errorlevel% neq 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 2.24-2003-1
)

for /f %%r in (result.txt) do set SP=%%r       
if %SP% geq 2 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 2.24-end
)

:2.24-2003-1

%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\Virtual Roots" | find /i "msadc" >> %tnd%\msadcdir.txt
	type msadcdir.txt                                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	find /i "msadc" msadcdir.txt > NUL
	IF ERRORLEVEL 1 (
		ECHO * 점검결과: MSADC 가상디렉터리가 존재하지 않음.                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt		
		goto 2.24-end
)

%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch" /s | findstr /i "RDSServer.DataFactory AdvancedDataFactory VbBusObj.VbbusObjCls" >> %tnd%\RDSREG.txt
type %tnd%\RDSREG.txt                                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	findstr /i "RDSServer.DataFactory AdvancedDataFactory VbBusObj.VbbusObjCls" RESREG.txt > NUL
	IF ERRORLEVEL 1 (
		ECHO * 점검결과: 등록된 REG값이 존재하지 않음.                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt		
		goto 2.24-end
)

		echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt		
		goto 2.24-end
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt	

	
:2.24-end	
del %tnd%\result.txt 2>nul
del %tnd%\msadcdir.txt 2>nul
del %tnd%\RDSREG.txt 2>nul

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0224 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0225 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################               2.25 최신 서비스팩 적용              ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 최신 서비스팩이 설치되어 있을 경우 양호                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (Windows NT 6a, Windows 2000 SP4, Windows 2003 SP2, Windows 2008 SP2)         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (Windows 2008R2 SP1, Windows 2012, 2012r2는 SP이 없음) 						 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type systeminfo.txt | find "Microsoft"                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type systeminfo.txt | find "Pack"                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [OS Version 확인]                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt	
:: winver = 2000
if %WinVer% equ 1 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type systeminfo.txt | find /i "service pack" | find /i /v "bios" | %script%\awk -F" " {print$6}		        > %tnd%\result.txt
	echo.
	goto 0225-2000
)

:: winver = 2003
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if %WinVer% EQU 2 (
	type systeminfo.txt | find /i "os version" | find /i /v "bios" | %script%\awk -F" " {print$6}		        > %tnd%\result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 0225-2003
	)

:: winver = 2008
if %WinVer% EQU 3 (
	type systeminfo.txt | find /i "os version" | find /i /v "bios" | %script%\awk -F" " {print$6}		        > %tnd%\result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 0225-2008
	)

:: winver = 2008R2
if %WinVer% EQU 4 (
	type systeminfo.txt | find /i "os version" | find /i /v "bios" | %script%\awk -F" " {print$6}		        > %tnd%\result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 0225-2008R2
	)
	
:: winver = 2012&2012R2
if %WinVer% GEQ 5 (
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 0225-end
	)

:0225-2000
type systeminfo.txt | find /i /v "bios" | find /V "N/A" | find /i "os version" >nul
if %errorlevel% neq 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0225-end
)

for /f %%r in (result.txt) do set SP=%%r       
if %SP% geq 4 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0225-end
)
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0225-end

:0225-2003
type systeminfo.txt | find /i /v "bios" | find /V "N/A" | find /i "os version" >nul
if %errorlevel% neq 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0225-end
)

for /f %%r in (result.txt) do set SP=%%r       
if %SP% geq 2 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0225-end
)
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0225-end

:0225-2008
type systeminfo.txt | find /i /v "bios" | find /V "N/A" | find /i "os version" >nul
if %errorlevel% neq 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0225-end
)

for /f %%r in (result.txt) do set SP=%%r       
if %SP% geq 2 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0225-end
)
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0225-end

:0225-2008R2
type systeminfo.txt | find /i /v "bios" | find /V "N/A" | find /i "os version" >nul
if %errorlevel% neq 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0225-end
)

for /f %%r in (result.txt) do set SP=%%r       
if %SP% geq 1 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0225-end
)
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0225-end

:0225-end	
del %tnd%\result.txt 2>nul
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0225 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0226 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################         2.26 터미널 서비스 암호화 수준 설정        ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 터미널 서비스를 사용하지 않는 경우 양호                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : 터미널 서비스를 사용 시 암호화 수준을 "클라이언트와 호환가능(중간)" 이상으로 설정한 경우 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (MinEncryptionLevel	2 이상이면 양호)                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver >= 2008_R2
if %WinVer% geq 4 (
	goto 2-262-enable
) else (
	goto 2-268-enable
)

:2-262-enable
net start | find /i "Remote Desktop Services" >nul
	IF NOT ERRORLEVEL 1 (
		echo ☞ Remote Desktop Services Enable                                          	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo ☞ 원격 터미널 서비스 암호화 수준 설정 확인                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo --------------------------------------------------------------------------------- >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel" | %script%\awk -F" " {print$3}	> %tnd%\result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                     
		)
	IF ERRORLEVEL 1 (
		echo ☞ Remote Desktop Services Disable                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=2												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)

goto 2-26-end

:2-268-enable
NET START | FIND "Terminal Service" > NUL
	IF NOT ERRORLEVEL 1 (
		echo ☞ Terminal Service Enable                                          			>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo ☞ 원격 터미널 서비스 암호화 수준 설정 확인                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo --------------------------------------------------------------------------------- >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel" | %script%\awk -F" " {print$3}	> %tnd%\result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
	IF ERRORLEVEL 1 (
		echo ☞ Terminal Service Disable                                             		 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=2												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)

:2-26-end

	


del %tnd%\result.txt 2>nul

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0226 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0227 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################             2.27 IIS 웹서비스 정보 숨김            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 등록된 웹 사이트의 [사용자 지정 오류] 탭에서                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : 400, 401, 403, 404, 500 에러에 대해 별도의 페이지가 지정되어 있는 경우 양호   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
::echo ■       : (취약 예문) prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="401.htm" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
rem 기본 설정이기 때문에 위 설정은 취약함.
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "World Wide Web Publishing Service" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO ☞ IIS Service Enable                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 1-45-enable
)	ELSE (
	ECHO ☞ IIS Service Disable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 46
)

:1-45-enable
echo [등록 사이트]                                                                        	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	type website-list.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	type website-name.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [기본 설정]                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	%systemroot%\System32\inetsrv\APPCMD list config | findstr "<error"                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

:: iis ver <= 6
if %iis_ver_major% leq 6 (
cscript %script%\adsutil.vbs enum W3SVC | findstr "400, 401, 403, 404, 500,"                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo *** 사이트별 설정 확인                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	for /f "delims=" %%i in (website-name.txt) do (
			echo [WebSite Name] %%i                                          						>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo ---------------------------------------------------------------                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			%systemroot%\System32\inetsrv\appcmd list config %%i | findstr "<error" 				>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo.                                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
)

:: iis ver <= 6
if %iis_ver_major% leq 6 (
	FOR /F "tokens=1 delims=[]" %%i in (website-list.txt) do (
		echo [WebSite AppRoot] %%i                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------------------------               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		cscript %script%\adsutil.vbs enum %%i/root | findstr "400, 401, 403, 404, 500," > nul
		IF NOT ERRORLEVEL 1 (
			cscript %script%\adsutil.vbs enum %%i/root | findstr "400, 401, 403, 404, 500,"          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo.                                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		) ELSE (
			echo 기본 설정이 적용되어 있음.                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo.                                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
	)
)
echo.                                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


:46
echo 0227 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0228 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################             2.28 SNMP 서비스 구동 점검             ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: SNMP 서비스를 불필요하게 사용하지 않으면 양호                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : SNMP 서비스는 구동되고 있으나 SNMP 설정이 없는 경우 불필요하게 동작되고 있는 것으로 판단됨. >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "SNMP Service" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO ☞ SNMP Service Enable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)	ELSE (
	ECHO ☞ SNMP Service Disable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [SNMP ValidCommunities 설정]                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" | findstr . >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [SNMP Trap 설정]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\TrapConfiguration" /s | findstr . >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0228 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0229 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################    2.29 SNMP 서비스 커뮤니티스트링의 복잡성 설정   ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: SNMP Community 이름이 public, private 이 아닌 유추하기 어렵게 설정되어 있으면 경우 양호                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (참고1) REG_DWORD Community String 숫자                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (참고2) 숫자: 2=알림, 4=읽기전용, 8=읽기와 쓰기, 16=읽기와 만들기             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "SNMP Service" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO ☞ SNMP Service Enable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)	ELSE (
	ECHO ☞ SNMP Service Disable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 29-end
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [SNMP ValidCommunities 설정]                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" | findstr . >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" | findstr . >> %tnd%\result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type result.txt | findstr /i "REG_DWORD" > nul
if %ERRORLEVEL% neq 0 (
	echo "string 값이 설정되어 있지 않음(N/A)"                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo "서비스 중지 권고"                                                						   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo [SNMP Trap Commnunities 설정]                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\TrapConfiguration" /s | findstr . >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 29-end
	)


echo [SNMP Trap Commnunities 설정]                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\TrapConfiguration" /s | findstr . >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


type result.txt | findstr /i "public private" > nul
	if %ERRORLEVEL% equ 0 (
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
	if %ERRORLEVEL% neq 0 (
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
	
	
	

:29-end
del %tnd%\result.txt 2>nul
echo 0229 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0230 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################            2.30 SNMP Access Control 설정           ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 특정 호스트만 SNMP 패킷을 받을 수 있도록 SNMP Access Control이 설정된 경우 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (PermittedManagers 설정이 있으면 양호)                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (PermittedManagers 설정이 없으면 모든 호스트에서 SNMP 패킷을 받을 수 있어 취약) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "SNMP Service" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO ☞ SNMP Service Enable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)	ELSE (
	ECHO ☞ SNMP Service Disable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 30-end
	)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [SNMP ValidCommunities 설정]                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" | findstr . >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" | findstr . >> %tnd%\result.txt
type %tnd%\result.txt | findstr /i "REG_DWORD" > nul
if %ERRORLEVEL% neq 0 (
	echo "string 값이 설정되어 있지 않음(N/A)"                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo "서비스 중지 권고"                                                						   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 30-end
	)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [SNMP Access Control 설정]                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" | findstr . >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" | findstr . > %tnd%\result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type %tnd%\result.txt | findstr /i "REG_SZ" > nul
	if %ERRORLEVEL% EQU 0 (
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
	if %ERRORLEVEL% NEQ 0 (
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

:30-end

del %tnd%\result.txt 2>nul
echo 0230 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0231 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################              2.31 DNS 서비스 구동 점검             ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: DNS 서비스를 사용 하지 않거나 동적 업데이트 설정이 "없음"으로 설정된 경우 양호  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (AllowUpdate	0 이면 양호)                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : [참고]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : 결과 값이 없을 경우 DNS 서버에 등록된 정/역방향 조회 영역이 없는 것으로,      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : DNS 서비스를 사용하지 않을 경우 서비스를 중지할 것을 권고                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : 윈도우2008이상에서 결과 값이 없을 경우 디폴트로 없음으로 설정                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "DNS Server" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO ☞ DNS Service Enable                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto dns-enable
)	ELSE (
	ECHO ☞ DNS Service Disable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto dns-end
)
:dns-enable
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | findstr "AllowUpdate" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | findstr "AllowUpdate" >> %tnd%\result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto dns-result1
	)


:: 2003 이상 검색
%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | findstr . | find /v "Listing of" | find /v "system was unable" > nul
	IF %ERRORLEVEL% neq 0 (
		reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | findstr "AllowUpdate" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | findstr "AllowUpdate" >> %tnd%\result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	) else (
		%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | findstr "AllowUpdate" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | findstr "AllowUpdate" >> %tnd%\result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)

:dns-result
	type %tnd%\result.txt | findstr /i "AllowUpdate" > nul
	if %ERRORLEVEL% neq 0 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto dns-end
	)

:: winver < 2008R2
if %WinVer% leq 3 (
goto 0231-2008
)

:: winver > 2008
if %WinVer% geq 4 (
 goto 0231-2008R2
)


:0231-2008
type %tnd%\result.txt | findstr /i "AllowUpdate" | find "1" > nul
	if %ERRORLEVEL% neq 0 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto dns-end
	) else (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto dns-end
	)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


:0231-2008R2
type %tnd%\result.txt | findstr /i "AllowUpdate" | findstr /i "0x1" > nul
	if %ERRORLEVEL% neq 0 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto dns-end
	) else (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto dns-end
	)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


:dns-end
del %tnd%\result.txt 2>nul
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0231 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0232 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################             2.32 HTTP/FTP/SMTP 배너 차단           ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: HTTP/FTP/SMTP 배너에 시스템 정보가 표시되지 않는 경우 양호                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "World Wide Web Publishing Service" > NUL
IF NOT ERRORLEVEL 1 (
echo ---------------------------------HTTP Banner-------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cscript %script%\http_banner.vbs >nul
	type http_banner.txt								>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2>nul
echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	del http_banner.txt 2>nul
)	ELSE (
	ECHO ☞ IIS Service Disable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find /i "ftp" > NUL
IF NOT ERRORLEVEL 1 (
echo -----------------------------------FTP Banner------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cscript %script%\ftp_banner.vbs >nul
	type ftp_banner.txt								>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2>nul
echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	del ftp_banner.txt 2>nul
)	ELSE (
	ECHO ☞ FTP Service Disable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find /i "smtp" > NUL
IF NOT ERRORLEVEL 1 (
echo ---------------------------------SMTP Banner-------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cscript %script%\smtp_banner.vbs >nul
	type smtp_banner.txt								>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	del smtp_banner.txt 2>nul
)	ELSE (
	ECHO ☞ SMTP Service Disable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0232 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0233 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################                2.33 Telnet 보안 설정               ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: Telnet 서비스가 구동 되고 있지 않거나, 인증방법이 NTLM 일 경우 양호             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : [참고]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (SecurityMechanism 2. NTLM)                                            	 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (SecurityMechanism 6. NTLM, Password)                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (SecurityMechanism 4. Password)                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find /i "telnet" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO ☞ TELNET Service Enable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto telnet-enable
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	) ELSE (
	ECHO ☞ TELNET Service Disable 																	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto telnet-end
)

:telnet-enable
	%script%\reg query "HKLM\Software\Microsoft\TelnetServer\1.0" /s | findstr . | find /v "Listing of" | find /v "system was unable" > nul
	IF %ERRORLEVEL% neq 0 (
		reg query "HKLM\Software\Microsoft\TelnetServer\1.0" /s | findstr /i "SecurityMechanism" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		reg query "HKLM\Software\Microsoft\TelnetServer\1.0" /s | findstr /i "SecurityMechanism" >> %tnd%\result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	) else (
		%script%\reg query "HKLM\Software\Microsoft\TelnetServer\1.0" /s | findstr /i "SecurityMechanism" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKLM\Software\Microsoft\TelnetServer\1.0" /s | findstr /i "SecurityMechanism" >> %tnd%\result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
	
:: winver < 2008R2
if %WinVer% leq 3 (
goto 0233-2008
)

:: winver > 2008
if %WinVer% geq 4 (
 goto 0233-2008R2
)


:0233-2008
type %tnd%\result.txt | findstr /i "REG_DWORD" | find "2" > nul
	if %ERRORLEVEL% neq 1 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto telnet-end
	) else (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto telnet-end
	)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


:0233-2008R2
type %tnd%\result.txt | findstr /i "REG_DWORD" | findstr /i "0x2" > nul
	if %ERRORLEVEL% neq 1 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto telnet-end
	) else (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto telnet-end
	)
echo.  	
	
	
:telnet-end
del %tnd%\result.txt 2>nul
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0233 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0234 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ################# 2.34 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거 #################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 시스템 DSN 부분의 Data Source를 현재 사용하고 있는 경우 양호                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : 시스템 DSN 부분의 Data Source가 사용하지 않는데 등록되어 있을 경우 취약       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources" | find "REG_SZ"           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
reg query "HKLM\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources" | find "REG_SZ"                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ※ 결과 값이 없을 경우 불필요한 ODBC/OLE-DB가 존재하지 않음 							               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0234 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0235 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################          2.35 원격터미널 접속 타임아웃 설정        ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 원격 터미널을 사용하지 않거나, 사용 시 Session Timeout이 설정되어 있는 경우 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (MaxIdleTime 설정 확인 방법: 60000=1분, 300000=5분)                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

:: winver <= 2008
if %WinVer% leq 3 (
	goto 35-2008
)

:: winver = 2008_R2
if %WinVer% equ 4 (
	goto 35-2008r2
)

:: winver >= 2012
if %WinVer% geq 5 (
	goto 35-2012
)



:35-2008
NET START > netstart.txt
type netstart.txt | FIND "Terminal Service" > NUL
	IF %ERRORLEVEL% neq 1 (
		echo ☞ Terminal Service Enable                                          			>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo ☞ 원격 터미널 Session Timeout 설정                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /s | findstr "MaxIdleTime" > %tnd%\idletime.txt
		type idletime.txt | findstr /v "fInheritMaxIdleTime"                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		type %tnd%\idletime.txt | findstr /v "fInheritMaxIdleTime" | find "REG_DWORD" | %script%\awk -F" " {print$3}        > %tnd%\result.txt
		for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.
		) else (
		echo ☞ Terminal Service Disable                                             		 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=1												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 35-end		
		)
goto 35-end



:35-2008R2
net start > netstart.txt
type netstart.txt | find /i "Remote Desktop Services" > nul
	IF %ERRORLEVEL% neq 1 (
		echo ☞ Remote Desktop Services Enable                                          	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo ☞ 원격 터미널 Session Timeout 설정                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /s | findstr "MaxIdleTime" > %tnd%\idletime.txt
		type idletime.txt | findstr /v "fInheritMaxIdleTime"                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		type %tnd%\idletime.txt | findstr /v "fInheritMaxIdleTime" | find "REG_DWORD" | %script%\awk -F" " {print$3}        > %tnd%\result.txt
		for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.        
		) else (
		echo ☞ Remote Desktop Services Disable                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=1												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 35-end		
		)
goto 35-end	


:35-2012
net start > netstart.txt
type netstart.txt | find /i "Remote Desktop Services" > nul
	IF %ERRORLEVEL% neq 1 (
		echo ☞ Remote Desktop Services Enable                                          	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo ☞ 원격 터미널 Session Timeout 설정                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /s | findstr "MaxIdleTime" > %tnd%\idletime.txt
		type idletime.txt | findstr /v "fInheritMaxIdleTime"                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		) else (
		echo ☞ Remote Desktop Services Disable                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=1												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 35-end		
		)
		
	type %tnd%\idletime.txt | findstr /v "fInheritMaxIdleTime" | find "REG_DWORD"	
		if %ERRORLEVEL% neq 0 (
		echo IdleTime 설정이 되어 있지 않습니다.					>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=0												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		) else (
		type %tnd%\idletime.txt | findstr /v "fInheritMaxIdleTime" | find "REG_DWORD" | %script%\awk -F" " {print$3}        > %tnd%\result.txt
		for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.											>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
		
goto 35-end	

		
		
:35-end
echo.     																								>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
del %tnd%\result.txt 2>nul                                                                                   
del %tnd%\netstart.txt 2>nul                                                                                   
echo 0235 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0236 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ############### 2.36 예약된 작업에 의심스러운 명령이 등록되어 있는지 점검 ################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 예약된 작업에 의심스러운 명령이 등록되어 있지 않은 경우 양호                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver >= 2003
if %WinVer% geq 2 (
	echo ☞ 예약된 작업 확인                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	schtasks | findstr [0-9][0-9][0-9][0-9]      	                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ☞ at 명령어로 등록한 작업 확인                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
at                                                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver >= 2003
if %WinVer% geq 2 (
	echo [참고] schtasks 전체                                                      				 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	schtasks                 									                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0236 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0301 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################                3.01 최신 HOT FIX 적용              ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 최신Hotfix 또는 PMS(Patch Management System) Agent가 설치되어 있을 경우 양호    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type systeminfo.txt | findstr /i "hotfix kb"                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0301 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0302 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################             3.02 백신 프로그램 업데이트            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있는 경우 양호           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ☞ 수동 점검 (백신 업데이트 일자 확인)                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0302 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0303 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################          3.03 정책에 따른 시스템 로깅 설정         ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 이벤트 감사 설정이 아래와 같이 설정되어 있는 경우 양호                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (1) 로그온 이벤트, 계정 로그온 이벤트, 정책 변경 : 성공/실패 감사             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (2) 계정 관리, 디렉터리 서비스 액세스, 권한 사용 : 실패 감사                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\auditpol  | findstr "Logon Policy Directory Management Privilege"                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\auditpol  | findstr "Logon Policy Directory Management Privilege"                   > %tnd%\result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

%script%\auditpol  | findstr "Logon Policy"  							                 > %tnd%\result1.txt
%script%\auditpol  | findstr "Directory Management Privilege"          			         > %tnd%\result2.txt



type %tnd%\result.txt | find "No" > nul
if %errorlevel% equ 0 (
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 3-03end
)


type %tnd%\result1.txt | find /V "Success and Failure" > nul
if %errorlevel% equ 0 (
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 3-03end
)

type %tnd%\result2.txt | find /V "Success and Failure" | find /V "Failure" > nul
if %errorlevel% equ 0 (
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)


:3-03end
del %tnd%\result.txt 2>nul
del %tnd%\result1.txt 2>nul
del %tnd%\result2.txt 2>nul
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0303 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0401 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################           4.01 로그의 정기적 검토 및 보고          ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 로그기록에 대해 정기적 검토, 분석, 리포트 작성 및 보고 등의 조치가 이루어지는 경우 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ☞ 수동 점검 (담당자 인터뷰 수행)                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0401 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0402 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################   4.02 원격으로 액세스할 수 있는 레지스트리 경로   ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: Remote Registry Service 가 중지되어 있을 경우 양호                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "Remote Registry" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO ☞ Remote Registry Service Enable                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)	ELSE (
	ECHO ☞ Remote Registry Service Disable                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "Remote Registry"                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0402 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0403 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################              4.03 이벤트 로그 관리 설정            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 최대 로그 크기 10240KB (10MB) 이상이고, Retention 7776000(90일) 이상이면 양호   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : "90일 이후 이벤트 덮어씀"으로 설정되어 있을 경우 양호(Windows2008 이상은 제외)                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (MaxSize 10485760 이상, Retention 7776000 이상)                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : Retention 0       = 필요한 경우 이벤트 덮어쓰기                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : Retention 7776000 = 다음보다 오래된 이벤트 덮어쓰기 (7776000 90일)            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : Retention -1      = 이벤트 덮어쓰지 않음(수동으로 로그 지우기)                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [Application Log Size]                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application\MaxSize"     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [Security Log Size]                                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\MaxSize"        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [System Log Size]                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System\MaxSize"          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

::Win <= 2003
if %WinVer% leq 2 (
	echo [Application log Retention]                                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application\Retention"   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo [Security log Retention]                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\Retention"      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo [System log Retention]                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System\Retention"        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) ELSE (
		echo ☞ Windows2008 이상은 덮어쓰기 날짜 지정 불가			   	     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0403 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0404 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################      4.04 원격에서 이벤트 로그 파일 접근 차단      ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 로그 디렉터리의 권한에 Everyone 이 없는 경우 양호                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (1) 시스템 로그 디렉터리: %systemroot%\system32\config                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (2) IIS 로그 디렉터리: %systemroot%\system32\LogFiles                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
cacls %systemroot%\system32\config                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
cacls %systemroot%\system32\config                                                           > %tnd%\result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo ☞ IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cacls %systemroot%\system32\logfiles                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cacls %systemroot%\system32\logfiles                                                         >> %tnd%\result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
	echo ☞ IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 0404-end
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
type %tnd%\result.txt | find /I "everyone" > nul
	if %errorlevel% neq 0 (
	echo Everyone 권한이 존재하지 않습니다.                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	) else (
	echo 
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

:0404-end

del %tnd%\result.txt 2>nul
echo 0404 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0501 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################               5.01 백신 프로그램 설치              ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 바이러스 백신 프로그램이 설치되어 있는 경우 양호                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
set vaccine="kaspersky norton bitdefender turbo avast v3"

echo ☞ Process List                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
for %%a IN (%vaccine%) DO (
type tasklist.txt | findstr /i %%a 															>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type tasklist.txt | findstr /i %%b >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type tasklist.txt | findstr /i %%c >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type tasklist.txt | findstr /i %%d >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type tasklist.txt | findstr /i %%e >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type tasklist.txt | findstr /i %%f >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

echo. 																						 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ☞ Service list                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
for %%a IN (%vaccine%) DO (
net start | findstr /i %%a >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | findstr /i %%b >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | findstr /i %%c >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | findstr /i %%d >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | findstr /i %%e >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | findstr /i %%f >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ※ 결과가 없는 경우 프로세스 목록 및 인터뷰를 통해 확인 필요                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0501 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0502 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################            5.02 SAM 파일 접근 통제 설정            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: SAM 파일 접근권한에 Administrator, System 그룹만 모든권한으로 등록된 경우 양호  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
cacls %systemroot%\system32\config\SAM							                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
cacls %systemroot%\system32\config\SAM							                             > %tnd%\result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type %tnd%\result.txt | find /V "NT AUTHORITY\SYSTEM" | find /V "BUILTIN\Administrators" | find "\" > nul
	if %errorlevel% neq 0 (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	) 
	if %errorlevel% equ 0 (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
echo.                                                                              	     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
del %tnd%\result.txt 2>nul
echo 0502 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0503 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################                5.03 화면보호기 설정                ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 화면 보호기를 설정하고, 암호를 사용하며, 대기 시간이 10분일 경우 양호            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 참고: 레지스트리 값이 없을 경우 AD 또는 OS설치 후 설정을 하지 않은 경우임             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKCU\Control Panel\Desktop\ScreenSaveActive"                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKCU\Control Panel\Desktop\ScreenSaverIsSecure"                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKCU\Control Panel\Desktop\ScreenSaveTimeOut"                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [AD(Active Directory)일 경우 레지값]                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaverIsSecure" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaveTimeOut" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

%script%\reg query "HKCU\Control Panel\Desktop\ScreenSaveActive"                             > %tnd%\result.txt
%script%\reg query "HKCU\Control Panel\Desktop\ScreenSaverIsSecure"                         >> %tnd%\result.txt
type %tnd%\result.txt | find /V "1" | find /I "REG_SZ" > nul
if %errorlevel% equ 0 (
	goto 5.03-start
	echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKCU\Control Panel\Desktop\ScreenSaveTimeOut"                           > %tnd%\result.txt
type result.txt | %script%\awk -F" " {print$3}      						                >> %tnd%\result1.txt
for /f %%r in (result1.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 5.03-end
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


:5.03-start
echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaverIsSecure" > %tnd%\result.txt

type %tnd%\result.txt | find /V "0" | find /V "unable to find" | find /I "REG_SZ" > nul
	if %errorlevel% neq 0 (
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 5.03-end
	)
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaveTimeOut" > %tnd%\result.txt
	type result.txt | %script%\awk -F" " {print$3}      						                >> %tnd%\result1.txt
	for /f %%r in (result1.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

:5.03-end

del %tnd%\result.txt 2>nul
del %tnd%\result1.txt 2>nul
echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0503 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0504 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################        5.04 로그온하지 않고 시스템 종료 허용       ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "로그온 하지 않고 시스템 종료 허용"이 "사용안함"으로 설정되어 있는 경우 양호    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (ShutdownWithoutLogon	0 이면 양호)                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon" > nul
if %errorlevel% equ 0 (
%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon" | %script%\awk -F" " {print$3}     >> %tnd%\result.txt
for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
del %tnd%\result.txt 2>nul
echo 0504 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0505 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################     5.05 원격 시스템에서 시스템 강제 종료 차단     ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "원격 시스템에서 강제로 시스템 종료" 정책에 "Administrators"만 존재할 경우 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (Administrators = *S-1-5-32-544)                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type Local_Security_Policy.txt | Find /I "SeRemoteShutdownPrivilege"                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type Local_Security_Policy.txt | Find /I "SeRemoteShutdownPrivilege" | %script%\awk -F= {print$2} >> %tnd%\result.txt
for /F "delims=, tokens=1-26" %%a in (result.txt) do (
	echo %%a  >> result2.txt 2> nul
	echo %%b  >> result2.txt 2> nul
	echo %%c  >> result2.txt 2> nul
	echo %%d  >> result2.txt 2> nul
	echo %%e  >> result2.txt 2> nul
	echo %%f  >> result2.txt 2> nul
	echo %%g  >> result2.txt 2> nul
	echo %%h  >> result2.txt 2> nul
	echo %%i  >> result2.txt 2> nul
	echo %%j  >> result2.txt 2> nul
	echo %%k  >> result2.txt 2> nul
	echo %%l  >> result2.txt 2> nul
	echo %%m  >> result2.txt 2> nul
	echo %%n  >> result2.txt 2> nul
	echo %%o  >> result2.txt 2> nul
	echo %%p  >> result2.txt 2> nul
	echo %%q  >> result2.txt 2> nul
	echo %%r  >> result2.txt 2> nul
	echo %%s  >> result2.txt 2> nul
	echo %%t  >> result2.txt 2> nul
	echo %%u  >> result2.txt 2> nul
	echo %%v  >> result2.txt 2> nul
	echo %%w  >> result2.txt 2> nul
	echo %%x  >> result2.txt 2> nul
	echo %%y  >> result2.txt 2> nul
	echo %%z  >> result2.txt 2> nul
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type %tnd%\result2.txt | find /V "Administrators" | find /V "S-1-5-32-544" | find /V "ECHO is off" > nul
if %errorlevel% equ 0 (
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt			
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
del %tnd%\result.txt 2>nul
del %tnd%\result2.txt 2>nul
echo 0505 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0506 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ################# 5.06 보안 감사를 로그할 수 없는 경우 즉시 시스템 종료 #################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료" 정책이 "사용안함"으로 설정되어 있는 경우 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (CrashOnAuditFail = 4,0 이면 양호)                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type Local_Security_Policy.txt | Find /I "CrashOnAuditFail"                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type Local_Security_Policy.txt | Find /I "CrashOnAuditFail" | %script%\awk -F= {print$2}       >> %tnd%\result.txt
for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

del %tnd%\result.txt 2>nul
echo 0506 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0507 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################     5.07 SAM 계정과 공유의 익명 열거 허용 안 함    ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "SAM 계정과 공유의 익명 열거 허용 안함" 정책이 "사용"이고,                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : "SAM 계정의 익명 열거 허용 안함" 정책이 "사용"으로 설정되어 있는 경우 양호    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (restrictanonymous	1 이고, RestrictAnonymousSAM	1 이면 양호)                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [SAM 계정과 공유의 익명 열거 허용 안함 설정]                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Control\LSA\restrictanonymous"             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [SAM 계정의 익명 열거 허용 안함 설정]                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM"	         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Control\LSA\restrictanonymous" | %script%\awk -F" " {print$3}       > %tnd%\result.txt
for /f %%r in (result.txt) do set restrict=%%r


%script%\reg query "HKLM\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM"	| %script%\awk -F" " {print$3}         > %tnd%\result.txt
for /f %%s in (result.txt) do echo Result=%restrict%:%%s												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
del %tnd%\result.txt 2>nul
echo 0507 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0508 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################              5.08 Autologon 기능 제어              ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: AutoAdminLogon 값이 없거나, AutoAdminLogon 0으로 설정되어 있는 경우 양호        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (DefaultPassword 엔트리가 존재한다면 삭제할 것을 권고)                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [AutoAdminLogon (1:Enable, 0:Disable, Default:Disable)]                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		reg export "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" AutoLogon_REG_Export.txt /Y > nul
		type %tnd%\AutoLogon_REG_Export.txt | findstr /i "AutoAdminLogon" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo. 																						>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [Username]                                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		reg export "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" AutoLogon_REG_Export.txt /Y > nul
		type %tnd%\AutoLogon_REG_Export.txt | findstr /i "DefaultUserName" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo. 																						>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [DefaultPassword]                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		reg export "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" AutoLogon_REG_Export.txt /Y > nul
		type %tnd%\AutoLogon_REG_Export.txt | findstr /i "DefaultPassword" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type %tnd%\AutoLogon_REG_Export.txt | findstr /i "AutoAdminLogon" > nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type %tnd%\AutoLogon_REG_Export.txt | findstr /i "AutoAdminLogon" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0508-enable
) else (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=0												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0508-end
)


:0508-enable

:: winver < 2008R2
if %WinVer% leq 3 (
goto 0508-2008
)

:: winver > 2008
if %WinVer% geq 4 (
 goto 0508-2008R2
)


:0508-2008
type %tnd%\result.txt | find "1" > nul
	if %ERRORLEVEL% neq 1 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=1												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 0508-end
	) else (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=0												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 0508-end
	)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


:0508-2008R2
type %tnd%\result.txt | find "0" > nul
if %errorlevel% equ 0 (
	echo Result=0                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
	echo Result=1                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 0508-end


:0508-end
::del %tnd%\result.txt 2>nul
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0508 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0509 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################       5.09 이동식 미디어 포맷 및 꺼내기 허용       ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "이동식미디어 포맷 및 꺼내기 허용" 정책이 "Administrators"으로 되어 있거나, 결과가 없는 경우 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (결과가 없으면 아무 그룹도 정의되지 않음: Default Administrators만 사용 가능 양호) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (AllocateDASD=1,"0" 이면 Administrators 양호)                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (AllocateDASD=1,"1" 이면 Administrators 및 Power Users)                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (AllocateDASD=1,"2" 이면 Administrators 및 Interactive Users)                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type Local_Security_Policy.txt | Find /I "AllocateDASD"                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ※ 결과가 없을 경우 Default로 Administrators 만 사용 가능함 							>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type Local_Security_Policy.txt | Find /I "AllocateDASD" > nul
if %errorlevel% neq 0 (
echo Result=0												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
type Local_Security_Policy.txt | Find /I "AllocateDASD" | %script%\awk -F, {print$2} | find "0" > nul
if %errorlevel% equ 0 (
echo Result=0												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
type Local_Security_Policy.txt | Find /I "AllocateDASD" | %script%\awk -F, {print$2} | find "1" > nul
if %errorlevel% equ 0 (
echo Result=1												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
type Local_Security_Policy.txt | Find /I "AllocateDASD" | %script%\awk -F, {print$2} | find "2" > nul
if %errorlevel% equ 0 (
echo Result=2												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0509 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0510 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################             5.10 디스크볼륨 암호화 설정            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "데이터 보호를 위해 내용을 암호화" 정책이 선택 된 경우 양호                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	FOR /F "tokens=1 delims=\" %%a IN ("%cd%") DO (
		echo %%a\ 																			 > %tnd%\inf_using_drv.txt
	)
	echo ☞ current using drive volume														 > %tnd%\inf_Encrypted_file_check.txt
	type inf_using_drv.txt 																	 >> %tnd%\inf_Encrypted_file_check.txt
	FOR /F "tokens=1" %%a IN (inf_using_drv.txt) DO (
		echo.								 												 >> %tnd%\inf_Encrypted_file_check.txt
		echo ☞ Search within the %%a drive...  											 >> %tnd%\inf_Encrypted_file_check.txt
		cipher /s:%%a | find "E "        												 	 >> %tnd%\inf_Encrypted_file_check.txt 2> nul
		if errorlevel 1 echo Encrypted file is not exist 									 >> %tnd%\inf_Encrypted_file_check.txt
		echo.								 												 >> %tnd%\inf_Encrypted_file_check.txt
	)
	type inf_Encrypted_file_check.txt 														 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: winver = 2003
if %WinVer% equ 2 (
	echo ☞ Current using drive volume 														 > %tnd%\inf_Encrypted_file_check.txt
	type inf_using_drv.txt 																	 >> %tnd%\inf_Encrypted_file_check.txt

	FOR /F "tokens=1" %%a IN (inf_using_drv.txt) DO (
		echo.								 												 >> %tnd%\inf_Encrypted_file_check.txt
		echo ☞ Search within the %%a drive...  											 >> %tnd%\inf_Encrypted_file_check.txt
		cipher /s:%%a | find "E " | findstr "^E"											 >> %tnd%\inf_Encrypted_file_check.txt 2> nul
		if errorlevel 1 echo Encrypted file is not exist 									 >> %tnd%\inf_Encrypted_file_check.txt
		echo.								 												 >> %tnd%\inf_Encrypted_file_check.txt
	)
	type inf_Encrypted_file_check.txt 														 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: winver <= 2008
if %WinVer% geq 3 (
	echo ☞ Windows 2008 이상 해당사항 없음 													 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0510 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0511 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################          5.11 Dos공격 방어 레지스트리 설정         ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: Dos 공격에 대한 방어 레지스트리가 설정되어 있는 경우 양호                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (1) SynAttackProtect = REG_DWORD 0 ▶ 1 로 변경 시 양호                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (2) EnableDeadGWDetect = REG_DWORD 1(True) ▶ 0 으로 변경 시 양호             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (3) KeepAliveTime = REG_DWORD 7,200,000(2시간) ▶ 300,000(5분)으로 변경 시 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (4) NoNameReleaseOnDemand = REG_DWORD 0(False) ▶ 1 로 변경 시 양호           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver >= 2008
if %WinVer% geq 3 (
	echo ☞ Windows 2008 이상 해당사항 없음                             			 				>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 5.11-end
) else (
	echo [SynAttackProtect 설정]                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\SynAttackProtect" /s >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo [EnableDeadGWDetect 설정]                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableDeadGWDetect" /s >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo [KeepAliveTime 설정]                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime" /s >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo [NoNameReleaseOnDemand 설정]                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\NoNameReleaseOnDemand" /s >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\SynAttackProtect" /s > %tnd%\result.txt

type %tnd%\result.txt | findstr "0 unable" > nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 5.11-end
)
%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableDeadGWDetect" /s > %tnd%\result.txt
type %tnd%\result.txt | findstr "1 unable" > nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 5.11-end
)
%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\NoNameReleaseOnDemand" /s > %tnd%\result.txt
type %tnd%\result.txt | findstr "0 unable" > nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
goto 5.11-end
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime" /s > %tnd%\result.txt
type %tnd%\result.txt | find "KeepAliveTime" > nul
if %errorlevel% equ 0 (
%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime" /s | %script%\awk -F" " {print$3}       > %tnd%\result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

:5.11-end
del %tnd%\result.txt 2>nul
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0511 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0512 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################  5.12 사용자가 프린터 드라이버를 설치할 수 없게 함 ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "사용자가 프린터 드라이버를 설치할 수 없게 함" 정책이 "사용"으로 설정된 경우 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (AddPrinterDrivers=4,1 이면 양호)                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type Local_Security_Policy.txt | Find /I "AddPrinterDrivers"                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type Local_Security_Policy.txt | Find /I "AddPrinterDrivers" | %script%\awk -F= {print$2}       >> %tnd%\result.txt
for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

del %tnd%\result.txt 2>nul


echo 0512 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0513 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################   5.13 세션 연결을 중단하기 전에 필요한 유휴시간   ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "로그온 시간이 만료되면 클라이언트 연결 끊기" 정책을 "사용"으로 설정하고,       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : "세션 연결을 중단하기 전에 필요한 유휴 시간" 정책이 "15분"으로 설정된 경우 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (EnableForcedLogOff	1 이고, AutoDisconnect	15 이면 양호)                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


%script%\reg query "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff" > %tnd%\result.txt
type %tnd%\result.txt | find "EnableForcedLogOff" | find "1" > nul
if %errorlevel% neq 0 (
set Result01=0
) else (
set Result01=1
)

%script%\reg query "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect" | %script%\awk -F" " {print$3}       > %tnd%\result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
for /f %%r in (result.txt) do set Result02=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

if %Result01% equ 1 (
	if %Result02% geq 15 (
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=O                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)else (
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=F                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

	)
) else (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

del %tnd%\result.txt 2>nul
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0513 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0514 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################                5.14 경고 메시지 설정               ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 시스템의 불법적인 사용에 대한 경고 메시지/제목이 설정되어 있는 경우 양호        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [Win NT]                                                            					 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\LegalNoticeCaption" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\LegalNoticeText" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [Win 2000이상]                                                            				>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system\legalnoticecaption" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system\legalnoticetext" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0514 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0515 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################         5.15 사용자별 홈 디렉터리 권한 설정        ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 사용자 계정별 홈 디렉터리에 Eveyone 권한이 없을 경우 양호                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo. > %tnd%\home-directory.txt
dir "C:\Users\*" | find "<DIR>" | findstr /V "All Defalt ."                                  >> %tnd%\home-directory.txt
FOR /F "tokens=5" %%i IN (home-directory.txt) DO cacls "C:\Users\%%i" | find /I "Everyone" > nul
IF %ERRORLEVEL% equ 1 (
echo ☞ Everyone 권한이 할당된 홈디렉터리가 발견되지 않았음.                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) ELSE (
	FOR /F "tokens=5" %%i IN (home-directory.txt) DO cacls "C:\Users\%%i" | find /I "Everyone" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0515 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0516 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################              5.16 LAN Manager 인증 수준            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "LAN Manager 인증 수준" 정책에 "NTLMv2 응답만 보냄"으로 설정되어 있는 경우 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 참고  : (LM NTML 응답 보냄: LmCompatibilityLevel=4,0)                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (LM NTML NTLMv2세션 보안 사용(협상된 경우): LmCompatibilityLevel=4,1)         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (NTLM 응답 보냄: LmCompatibilityLevel=4,2)                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (NTLMv2 응답만 보냄: LmCompatibilityLevel=4,3)                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (NTLMv2 응답만 보냄WLM거부: LmCompatibilityLevel=4,4)                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (NTLMv2 응답만 보냄WLM거부 NTLM 거부: LmCompatibilityLevel=4,5)               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : 값이 없을 경우 아무것도 설정이 안 된 상태임                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 주의: 해당 설정을 수정하면 클라이언트나 서비스 또는 응용 프로그램과의 호환성에 영향을 미칠 수 있음. >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type Local_Security_Policy.txt | Find /I "LmCompatibilityLevel"           					 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type Local_Security_Policy.txt | Find /I "LmCompatibilityLevel" > nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type Local_Security_Policy.txt | Find /I "LmCompatibilityLevel" | %script%\awk -F= {print$2}       >> %tnd%\result.txt
for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 값이 존재 하지 않음                                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

del %tnd%\result.txt 2>nul
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0516 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0517 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################   5.17 보안 채널 데이터 디지털 암호화 또는 서명    ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 아래 3가지 정책이 "사용" 으로 되어 있을 경우 양호                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 참고: (1) 도메인 구성원: 보안 채널 데이터를 디지털 암호화 또는 서명(항상)           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■     : (2) 도메인 구성원: 보안 채널 데이터를 디지털 암호화(가능한 경우)              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■     : (3) 도메인 구성원: 보안 채널 데이터를 디지털 서명(가능한 경우)                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■     : (4,1)사용, (4,0)사용 안 함                							  		 	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type Local_Security_Policy.txt | Findstr /I "RequireSignOrSeal SealSecureChannel SignSecureChannel" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

type Local_Security_Policy.txt | Findstr /I "RequireSignOrSeal SealSecureChannel SignSecureChannel" | findstr "4.0 unable" > nul
if %errorlevel% equ 0 (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=4,0												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=4,1												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

echo 0517 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0518 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################             5.18 파일 및 디렉토리 보호             ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 파일시스템이 보안 기능을 제공 해주는 NTFS일 경우 양호                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	fsutil fsinfo drives 																	 > %tnd%\inf_using_drv_temp1.txt
	type inf_using_drv_temp1.txt | find /i "\" 												 > %tnd%\inf_using_drv_temp2.txt
	echo.																					 > %tnd%\inf_using_drv_temp3.txt
	FOR /F "tokens=1-26" %%a IN (inf_using_drv_temp2.txt) DO (
		echo %%a >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%b >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%c >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%d >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%e >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%f >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%g >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%h >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%i >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%j >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%k >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%l >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%m >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%n >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%o >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%p >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%q >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%r >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%s >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%t >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%u >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%v >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%w >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%x >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%y >> %tnd%\inf_using_drv_temp3.txt 2> nul
		echo %%z >> %tnd%\inf_using_drv_temp3.txt 2> nul
	)
	type inf_using_drv_temp3.txt | find /i "\" | find /v "A:\" 								 > %tnd%\inf_using_drv.txt
	FOR /F "tokens=1" %%a IN (inf_using_drv.txt) DO (
		echo.                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo %%a                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		fsutil fsinfo drivetype %%a												 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		fsutil fsinfo volumeinfo %%a												 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		fsutil fsinfo drivetype %%a												 > %tnd%\result.txt
	type %tnd%\result.txt | find /I "Fixed Drive" > nul
	type %tnd%\result.txt | find /I "Fixed Drive" > nul
	if not errorlevel 1 (
	fsutil fsinfo volumeinfo %%a												 >> %tnd%\result1.txt
	)
)
	type %tnd%\result1.txt | find /I "File System Name" | find /i "fat" > nul
	if %errorlevel% equ 0 (
	echo.                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=FAT												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	) else (
	echo.                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=NTFS												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
	
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [참고]                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo C: 드라이브 권한 확인(NTFS일 경우 계정별 권한 부여 설정이 출력됨)                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
cacls c:\ 																					 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


del %tnd%\result.txt 2>nul
del %tnd%\result1.txt 2>nul
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0518 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0519 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################        5.19 컴퓨터 계정 암호 최대 사용 기간        ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: "컴퓨터 계정 암호 변경 사용 안함" 정책 "사용안함"으로 설정 되어 있고,           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : "컴퓨터 계정 암호 최대 사용 기간" 정책이 "90일"로 설정되어 있는 경우 양호     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (DisablePasswordChange=4,0 이고, MaximumPasswordAge=4,90 이면 양호)           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	echo Win 2000 해당사항 없음                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 5.19-end
)
:: winver >= 2003
if %WinVer% geq 2 (
	type Local_Security_Policy.txt | Findstr /I "\MaximumPasswordAge disablepasswordchange"      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

type Local_Security_Policy.txt | Find /I "disablepasswordchange" | find "4,0" > nul
if %errorlevel% neq 0 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 5.19-end
) 
	
type Local_Security_Policy.txt | Find /I "disablepasswordchange" | find "4,0" > nul
if %errorlevel% equ 0 (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	type Local_Security_Policy.txt | Find /I "\MaximumPasswordAge" | %script%\awk -F, {print$2}       > %tnd%\result.txt
	for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

:5.19-end
del %tnd%\result.txt 2>nul
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0519 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0520 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################             5.20 시작프로그램 목록 분석            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: 시작 프로그램에서 불필요한 서비스가 등록되어 있지 않고, 주기적으로 점검하는 경우 양호 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (담당자 인터뷰 및 시작 프로그램 점검관련 보고서 확인)                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ☞ 시작 프로그램 확인(HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run)  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	%script%\reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: winver >= 2003
if %WinVer% geq 2 (
	%script%\reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" | findstr . | find /v "Listing of" | find /v "system was unable" >nul
	IF NOT ERRORLEVEL 0 (
		reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	) else (
		%script%\reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ☞ 시작 프로그램 확인(HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	%script%\reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: winver >= 2003
if %WinVer% geq 2 (
	%script%\reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" | findstr . | find /v "Listing of" | find /v "system was unable" >nul
	IF NOT ERRORLEVEL 0 (
		reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	) else (
		%script%\reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0520 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0601 START >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################           6.01 Windows 인증 모드 사용             ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 기준: Windows 인증 모드로 설정되어 있는 경우 양호 (LoginMode 1 이면 양호)             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (1) LoginMode 1 이면 Windows 인증 모드                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■       : (2) LoginMode 2 이면 SQL Server 및 Windows 인증 모드                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■ 현황                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	echo Win 2000 해당사항 없음                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 6.01-end
)

:: winver >= 2003
if %WinVer% geq 2 (
	net start | find "SQL Server" > NUL
	IF NOT ERRORLEVEL 1 (
		ECHO ☞ SQL Server Enable                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 6.01-start
		echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)	ELSE (
		ECHO ☞ SQL Server Disable                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 6.01-end
	)
)


:6.01-start

%script%\reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server" /s | find "LoginMode" > nul
	IF %ERRORLEVEL% neq 0 (
		reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server" /s | find "LoginMode" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server" /s | find "LoginMode" | %script%\awk -F" " {print$3}       > %tnd%\result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	) else (
		%script%\reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server" /s | find "LoginMode" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server" /s | find "LoginMode" | %script%\awk -F" " {print$3} > %tnd%\result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)

:6.01-end
del %tnd%\result.txt 2>nul

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0601 END >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo @@FINISH>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

::시스템 정보 출력 시작
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###############################  Interface Information  ############################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
ipconfig /all                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###############################  System Information  ################################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


:: winver = 2000
if %WinVer% equ 1 (
	%script%\psinfo                                                                          > systeminfo.txt
	echo Hotfix:                                                                             >> systeminfo.txt
	%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix"            >> systeminfo.txt
	type systeminfo.txt                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

:: winver >= 2003
if %WinVer% geq 2 (
	type %tnd%\systeminfo_ko.txt                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###############################  tasklist Information  ################################ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	%script%\pslist                                                                          > tasklist.txt
	type %tnd%\tasklist.txt	                                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt	
)

:: winver >= 2003
if %WinVer% geq 2 (
	tasklist																				 > %tnd%\tasklist.txt 2>nul
	type %tnd%\tasklist.txt	                                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt	
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo #################################  Port Information  ################################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
netstat -an | find /v "TIME_WAIT"                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ############################  Service Daemon Information  ############################# >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find /v "started" | find /v "completed"                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##########################  Environment Variable Information  ######################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
set											                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################  metabase.xml  ################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
IF EXIST C:\WINDOWS\system32\inetsrv\MetaBase.xml (
	type C:\WINDOWS\system32\inetsrv\MetaBase.xml                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) ELSE (
	echo C:\WINDOWS\system32\inetsrv\MetaBase.xml 존재하지 않음.                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###############                      계정 정보                     #################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ****************************  User Accounts List  *****************************         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net user | find /V "successfully"                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ************************  Group List - net localgroup  ************************         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net localgroup | find /V "successfully"                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo *****************************  Account Information  ***************************         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
FOR /F "tokens=1,2,3 skip=4" %%i IN ('net user') DO (
net user %%i >> account.txt 2>nul
net user %%j >> account.txt 2>nul
net user %%k >> account.txt 2>nul
)
type account.txt>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

::시스템 정보 출력 끝



::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::::::::::::::::::::::: 공통 부분 시작2::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::



echo.>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo END_RESULT                                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
del %tnd%\account.txt 2>nul
del %tnd%\account_temp1.txt 2>nul
del %tnd%\account_temp2.txt 2>nul
del %tnd%\admin-account.txt 2>nul
del %tnd%\service.txt 2>nul
del %tnd%\idletime.txt 2>nul
del %tnd%\home-directory.txt 2>nul
del %tnd%\home-directory-acl.txt 2>nul
del %tnd%\Local_Security_Policy.txt 2>nul
del %tnd%\net-accounts.txt 2>nul
del %tnd%\reg-website-list.txt 2>nul
del %tnd%\systeminfo.txt 2>nul
del %tnd%\systeminfo_ko.txt 2>nul
del %tnd%\tasklist.txt 2>nul
del %tnd%\real_ver.txt 2>nul
del %tnd%\inf_share_folder.txt 2>nul
del %tnd%\inf_share_folder_temp.txt 2>nul
del %tnd%\inf_share_folder_temp_sed.txt 2>nul
del %tnd%\inf_share_folder_temp_sed2.txt 2>nul
del %tnd%\inf_Encrypted_file_check.txt 2>nul
del %tnd%\AutoLogon_REG_Export.txt 2>nul


rem Netbios 관련
del %tnd%\2-18-netbios-list-1.txt 2> nul
del %tnd%\2-18-netbios-list-2.txt 2> nul
del %tnd%\2-18-netbios-list.txt 2> nul
del %tnd%\2-18-netbios-query.txt 2> nul
del %tnd%\2-18-netbios-result.txt 2> nul


rem DB 관리 관련
del %tnd%\unnecessary-user.txt 2>nul
del %tnd%\password-null.txt 2>nul


rem IIS 관련 del
del %tnd%\iis-enable.txt 2>nul
del %tnd%\iis-version.txt 2>nul
del %tnd%\website-list.txt 2>nul
del %tnd%\website-name.txt 2>nul
del %tnd%\website-physicalpath.txt 2>nul
del %tnd%\sample-app.txt 2>nul


rem FTP 관련 del
del %tnd%\ftp-enable.txt 2>nul
del %tnd%\ftpsite-list.txt 2>nul
del %tnd%\ftpsite-name.txt 2>nul
del %tnd%\ftpsite-physicalpath.txt 2>nul
del %tnd%\ftp-ipsecurity.txt 2>nul


rem 파일 드라이브 경로 관련 del
del %tnd%\inf_using_drv_temp3.txt 2>nul
del %tnd%\inf_using_drv_temp2.txt 2>nul
del %tnd%\inf_using_drv_temp1.txt 2>nul
del %tnd%\inf_using_drv.txt 2>nul



echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■   END Time  ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
date /t                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
time /t                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


echo.
echo ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■■■                                                              ■■■   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■■■       Windows %WinVer_name% Security Check is Finished       ■■■   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■■■                                                              ■■■   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.
echo [+] Windows Security Check is Finished
pause

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::::::::::::::::::::::: 공통 부분 끝2::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

