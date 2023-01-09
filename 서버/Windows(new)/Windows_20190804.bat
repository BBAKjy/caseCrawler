::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::::::::::::::::::::::: ���� �κ� ����:::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

@echo off

setlocal
set tnd=C:\tnd
set john=%tnd%\john
set script=%tnd%\script

rem ��ũ��Ʈ ���� �� �׸� ī��Ʈ �����ֱ� ���� ����df
set item_count=0

TITLE Windosws Security Check

::���� ���� Ȯ�� ����
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

:: windows 2008 �̻������ icacls
if %WinVer% geq 3 (
	doskey cacls=icacls $*
)
::���� ���� Ȯ�� ��




set SCRIPT_LAST_UPDATE=2017.09.01
echo ======================================================================================= >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��������������������      Windows %WinVer_name% Security Check      ��������������������� >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��������������������      Copyright �� 2017, SK tnd Co. Ltd.    ��������������������� >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ======================================================================================= >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo LAST_UPDATE %SCRIPT_LAST_UPDATE%                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �������������������������������������  Start Time  �������������������������������������  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
date /t                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
time /t                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt     
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
::sysinfo �ѱ�(chcp 437���� �ѱ� ??�� ���� ���� ����)
echo [+] Gathering systeminfo...
systeminfo																					 > %tnd%\systeminfo_ko.txt 2>nul

::�������� ����
chcp 437

::���� �������� ����
secedit /EXPORT /CFG Local_Security_Policy.txt >nul
net accounts > %tnd%\net-accounts.txt 


::FTP ���Ȯ��
net start | find /i "ftp" > nul
if not errorlevel 1 (
	echo FTP Enable                                                                         > ftp-enable.txt
) else (
goto FTP-Disable
)

:: FTP Version �����ϱ�
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

:: FTP Site List ���ϱ� ( ftpsite-list.txt )
:: iis ver >= 7
if %iis_ftp_ver_major% geq 7 (
	%systemroot%\System32\inetsrv\appcmd list site | find /i "ftp"                           > %tnd%\ftpsite-list.txt
)
:: iis ver <= 6
if %iis_ftp_ver_major% leq 6 (
	cscript %script%\adsutil.vbs enum MSFTPSVC | find /i "MSFTPSVC" | findstr /i /v "FILTERS APPPOOLS INFO" > ftpsite-list.txt
)

:: FTP Site Name ���ϱ� ( ftpsite-name.txt )
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

:: FTP Site physicalpath ���ϱ� ( ftpsite-physicalpath.txt )
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

::IIS ���Ȯ��
net start | find /i "world wide web publishing service" > nul
if not errorlevel 1 (
	echo IIS Enable                                                                           > iis-enable.txt
) else (
 goto IIS-Disable
 )

:: IIS Version ���ϱ�
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters" | find /i "version" > iis-version.txt
type iis-version.txt | find /i "major"                                                        > iis-version-major.txt
for /f "tokens=3" %%a in (iis-version-major.txt) do set iis_ver_major=%%a
del iis-version-major.txt 2> nul

:: WebSite List ���ϱ� ( website-list.txt )
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	%systemroot%\System32\inetsrv\appcmd list site | find /i "http"                             > website-list.txt
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	cscript %script%\adsutil.vbs enum W3SVC | find /i "W3SVC" | findstr /i /v "FILTERS APPPOOLS INFO" > website-list.txt
)

:: WebSite Name ���ϱ� ( website-name.txt )
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

:: Web Site physicalpath ���ϱ� ( website-physicalpath.txt )
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


::sysinfo ����
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
:::::::::::::::::::::::::::::::::::::::::::::::: ���� �κ� ��:::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 0101 START                                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
SET /A item_count+=1
echo [+] %item_count%
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ##################        1.01 Administrator ���� �̸� �ٲٱ�         ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: Administrator ���� �̸��� �����Ͽ� ����ϴ� ��� ��ȣ                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo #################               1.02 GUEST ���� ����                ######################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: Guest ���� ��Ȱ��ȭ�� ��� ��ȣ                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################              1.03 ���ʿ��� ���� ����               ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ���ʿ��� ������ �������� ���� ���                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################            1.04 ���� ��� �Ӱ谪 ����             ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �α׿� ���� ���� �����ϴ� ���� ��� �Ӱ谪�� 5�� ���Ϸ� �����Ǿ� ������ ��ȣ          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################    1.05 �ص� ������ ��ȣȭ�� ����Ͽ� ��ȣ ����    ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "�ص� ������ ��ȣȭ�� ����Ͽ� ��ȣ ����" ��å�� "������"���� �����Ǿ� ������ ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (ClearTextPassword = 0 �� ��� ��ȣ)                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################      1.06 ������ �׷쿡 �ּ����� ����� ����        ##################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: Administrators �׷쿡 ���ʿ��� ������ ���� ���� ���� ��� ��ȣ                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ################     1.07 Everyone ��� ������ �͸� ����ڿ��� ����          ############### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : ��Everyone ��� ������ �͸� ����ڿ��� ���롱 ��å�� �������ԡ� ���� �Ǿ� ���� ��� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 		: (EveryoneIncludesAnonymous=4,0 �̸� ��ȣ)                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	echo Win 2000 �ش���� ����                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo #################              1.08 ���� ��� �Ⱓ ����              ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "���� ��� �Ⱓ", "���� ��� �Ⱓ ������� ����" ���� 60�� �̻����� �����Ǿ� ������ ��ȣ                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo #################             1.09 �н����� ���⼺ ����              ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "��ȣ�� ���⼺�� �����ؾ� ��" ��å�� "���" ���� �Ǿ� ���� ��� ��ȣ            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (PasswordComplexity = 1 �� ��� ��ȣ)                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo #################            1.10 �н����� �ּ� ��ȣ ����            ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �ּ� ��ȣ ���� ������ 8�� �̻��� ��� ��ȣ                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo #################            1.11 �н����� �ִ� ��� �Ⱓ           ######################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �ִ� ��ȣ ��� �Ⱓ ������ 90�� ������ ��� ��ȣ                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo #################           1.12 �н����� �ּ� ��� �Ⱓ            ######################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ������ �н����� ���Ⱓ�� �ּ� 1�� �̻��� ��� ��ȣ                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo #################         1.13 ������ ����� �̸� ǥ�� ����         ######################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "������ ����� �̸� ǥ�� ����" ��å�� "���"���� �����Ǿ� ���� ��� ��ȣ        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (DontDisplayLastUserName = 1)                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################               1.14 ���� �α׿� ���               ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "���� �α׿� ���" ��å�� "Administrators", "IUSR_" �� ������ ��� ��ȣ         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (Administrators = *S-1-5-32-544), (IUSR = *S-1-5-17)                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################           1.15 �͸� SID/�̸� ��ȯ ���            ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "�͸� SID/�̸� ��ȯ ���" ��å�� "��� �� ��" ���� �Ǿ� ���� ��� ��ȣ          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (LSAAnonymousNameLookup = 0)                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	echo Win 2000 �ش���� ����                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################                1.16 �ֱ� ��ȣ ���                ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ������ �ֱ� ����� �н����� ��� ������ 12�� �̻��� ��� ��ȣ                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################  1.17 �ܼ� �α׿� �� ���� �������� �� ��ȣ ��� ����  ################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "�ܼ� �α׿� �� ���� �������� �� ��ȣ ��� ����" ��å�� "���"���� �Ǿ� ���� ��� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (LimitBlankPasswordUse = 4,1)                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
rem ��� ���� �������� ������ Default ���� ����(Default ����: LimitBlankPasswordUse 1 ��ȣ)
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	echo Win 2000 �ش���� ����                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################    1.18 �����͹̳� ���� ������ ����� �׷� ����    ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ���� �͹̳� ������ ������ Administrators�׷�� Remote Desktop Users�׷쿡       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : ���ʿ��� ������ ��ϵǾ� ���� ���� ��� ��ȣ                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	echo Win 2000 �ش���� ����                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: winver >= 2008_R2
if %WinVer% geq 4 (
	net start | find /i "Remote Desktop Services" >nul
	IF NOT ERRORLEVEL 1 (
		echo �� Remote Desktop Services Enable                                          	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo �� ���� �͹̳� ���� ��� ����                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
		echo �� Remote Desktop Services Disable                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
) else (
	NET START | FIND "Terminal Service" > NUL
	IF NOT ERRORLEVEL 1 (
		echo �� Terminal Service Enable                                          			>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo �� ���� �͹̳� ���� ��� ����                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
		echo �� Terminal Service Disable                                             		 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################          2.01 ���� ���� �� ����� �׷� ����        ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �Ϲݰ��� ������ ���ų� ���� ���丮 ���� ������ Everyone ���� ��� ��ȣ    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net share | find /v "$" | find /v "���"			                                      	 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net share | find /v "$" | find /v "���" | find /v "------"                                    	 > %tnd%\inf_share_folder.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type inf_share_folder.txt | find "\" > nul
IF %ERRORLEVEL% neq 0 echo ���������� �������� �ʽ��ϴ�.								>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo �� cacls ���                                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
	echo Everyone ������ �������� �ʽ��ϴ�.														>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################            2.02 �ϵ��ũ �⺻ ���� ����          ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �⺻���� �׸�(C$, D$)�� �������� �ʰ� AutoShareServer ������Ʈ�� ���� 0�� ��� ��ȣ           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� �ϵ��ũ �⺻ ���� Ȯ��                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net share | FIND /V "IPC$" | FIND /V "command PRINT$ FAX$" | FIND "$" | findstr /I "^[A-Z]"  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net share | FIND /V "IPC$" | FIND /V "command PRINT$ FAX$" | FIND "$" | findstr /I "^[A-Z]" > nul
if %ERRORLEVEL% EQU 1 (
echo �⺻ ���� ������ ���� ���� �ʽ��ϴ�.													>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� Registry ����								                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################              2.03 ���ʿ��� ���� ����             ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �ý��ۿ��� �ʿ����� �ʴ� ����� ���񽺰� �����Ǿ� ���� ��� ��ȣ                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (1) Alerter(�������� Ŭ���̾�Ʈ�� ���޼����� ����)                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (2) Clipbook(������ Clipbook�� �ٸ� Ŭ���̾�Ʈ�� ����)                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (3) Messenger(Net send ��ɾ �̿��Ͽ� Ŭ���̾�Ʈ�� �޽����� ����)          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (4) Simple TCP/IP Services(Echo, Discard, Character, Generator, Daytime, ��)  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | findstr "Alerter ClipBook Messenger"                                             > %tnd%\service.txt
net start | find "Simple TCP/IP Services"                                                    >> %tnd%\service.txt

net start | findstr /I "Alerter ClipBook Messenger TCP/IP" service.txt > NUL
IF ERRORLEVEL 1 ECHO �� ���ʿ��� ���񽺰� �������� ����.                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
IF NOT ERRORLEVEL 1 (
echo �� �Ʒ��� ���� ���ʿ��� ���񽺰� �߰ߵǾ���.                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################             2.04 IIS ���� ���� ����             ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : IIS ���񽺰� ���ʿ��ϰ� �������� �ʴ� ��� ��ȣ(����� ���ͺ�)                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                
if exist iis-enable.txt (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-04-enable
) else (
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=Disabled																		>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-04-end
)


:2-04-enable

echo [IIS Version Ȯ��]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type iis-version.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [��� ����Ʈ]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ###################           2.05 IIS ���丮 ������ ����           ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : �⺻ ���� �� ����Ʈ�� "���͸� �˻�" ������ False �̸� ��ȣ                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-05-enable
) else (
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-05-end
)

:2-05-enable

echo [��� ����Ʈ]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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

echo [�⺻ ����]                                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo *** ����Ʈ�� ���� Ȯ��                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
			echo * �⺻ ������ ����Ǿ� ����.                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ###################               2.06 IIS CGI ���� ����              ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : C:\inetpub\scripts �� C:\inetpub\cgi-bin ���͸��� ������� �ʴ� ��� ��ȣ     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : ��� �� Everyone�� ������, ��������, ��������� �ο��Ǿ� ���� ���� ��� ��ȣ  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
	echo C:\inetpub\scripts ���͸��� �������� ����.                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

IF EXIST C:\inetpub\cgi-bin (
	cacls C:\inetpub\cgi-bin                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cacls C:\inetpub\cgi-bin                                                                >> %tnd%\result.txt
) ELSE (
	echo C:\inetpub\cgi-bin ���͸��� �������� ����.                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ###################          2.07 IIS ���� ���丮 ���� ����         ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : "���� ��� ���" �ɼ��� üũ�Ǿ� ���� ���� ��� ��ȣ                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : (asp enableParentPaths="false" �� ��� ��ȣ)                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-07-enable
) else (
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-07-end
)

:2-07-enable
echo [��� ����Ʈ]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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

echo [�⺻ ����]                                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	%systemroot%\System32\inetsrv\appcmd list config /section:asp | find /i "enableParentPaths" > nul
	IF NOT ERRORLEVEL 1 (
		%systemroot%\System32\inetsrv\appcmd list config /section:asp | find /i "enableParentPaths" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%systemroot%\System32\inetsrv\appcmd list config /section:asp | find /i "enableParentPaths" > %tnd%\result.txt
	) ELSE (
		echo * ������ ���� * �⺻���� : enableParentPaths=false                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	cscript %script%\adsutil.vbs get W3SVC/AspEnableParentPaths  | find /i /v "Microsoft"    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cscript %script%\adsutil.vbs get W3SVC/AspEnableParentPaths  | find /i /v "Microsoft"    > %tnd%\result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo *** ����Ʈ�� ���� Ȯ��                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
			echo * ������ ���� * �⺻���� : enableParentPaths=false                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
			echo AspEnableParentPaths : * �⺻ ������ ����Ǿ� ����.                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ###################            2.08 IIS ���ʿ��� ���� ����            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : IISSamples, IISHelp ������͸��� �������� ���� ��� ��ȣ                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo 		 (IIS 7.0 �̻� ���� �ش� ���� ����)						                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-08-enable
) else (
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-08-end
)

:2-08-enable
echo [���� ���͸� ���� ��Ȳ]                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	echo �� IIS 7.0 �̻� ���� �ش� ���� ����							                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

::20160114 ������(�ش���� �������� ������)
::if %iis_ver_major% geq 7 (
	::%systemroot%\System32\inetsrv\appcmd list config -section:system.applicationHost/sites | find /i "virtualdirectory" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
::)

::20160114 ������(IISSample �� ������ �Ǵܰ����ϰ� ������)
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
		ECHO * ���˰��: IISSamples, IISHelp ������͸��� �������� ����.                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt		
	)	ELSE (
		ECHO * ���˰��: IISSamples, IISHelp ������͸��� ������.                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ###################          2.09 IIS �� ���μ��� ���� ����           ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : IIS ���� ���� ������ ������ �������� ��ϵǾ� ���� ������ ��ȣ                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2.09-end
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [World Wide Web Publishing Service ���� ����]                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\ObjectName"                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\ObjectName"                 >> %tnd%\result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [IIS Admin Service ���� ����]                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ###################               2.10 IIS ��ũ ������              ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : �� ����Ʈ Ȩ���͸��� �ɺ��� ��ũ, aliases, *.lnk ������ �������� ������ ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-10-enable
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-10-end
)

:2-10-enable
echo [��� ����Ʈ]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
	echo [Ȩ���丮 ���� - WEB/FTP ���п�]                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%systemroot%\System32\inetsrv\appcmd list config -section:system.applicationHost/sites | findstr /i "name protocol physicalpath" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo *** ����Ʈ�� ���ʿ� ���� üũ                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo �� ��� ���� �������� ������ ��ȣ                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ###################       2.11 IIS ���� ���ε� �� �ٿ�ε� ����       ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : �� ������ ���� �ڿ������� ���� ���ε� �� �ٿ�ε� �뷮�� ������ ��� ��ȣ     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : 7.0�̻�(maxAllowedContentLength: ������ �뷮 ���� ���� /Default: 30MB)                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : 7.0�̻�(MaxRequestEntityAllowed: ���� ���ε� �뷮 ���� ���� /Default: 200000 bytes)    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : 7.0�̻�(bufferingLimit: ���� �ٿ�ε� �뷮 ���� ���� /Default: 4MB(4194304 bytes))     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : 6.0����(AspMaxRequestEntityAllowed : ���ε� �뷮 ���� ���� /Default: 200KB(204800 byte)) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : 6.0����(AspBufferingLimit : �ٿ�ε� �뷮 ���� ���� /Default: 4MB(4194304 byte)) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-11-enable
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt	
	goto 2-11-end
)

:2-11-enable
echo [��� ����Ʈ]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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

echo [�⺻ ����]                                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	%systemroot%\System32\inetsrv\appcmd list config | findstr /i "maxAllowedContentLength maxRequestEntityAllowed bufferingLimit" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: iis ver <= 6
if %iis_ver_major% leq 6 (
	cscript %script%\adsutil.vbs enum W3SVC | findstr /i "AspMaxRequestEntityAllowed AspBufferingLimit" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo * ���� ���� ��� �⺻ ������ ����Ǿ� ����.                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo *** ����Ʈ�� ���� Ȯ��                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ver_major% geq 7 (
	for /f "delims=" %%a in (website-name.txt) do (
		echo [WebSite Name] %%a                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%systemroot%\System32\inetsrv\appcmd list config %%a | findstr /i "maxAllowedContentLength maxRequestEntityAllowed bufferingLimit" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo * ���� ���� ��� �⺻ ������ ����Ǿ� ����.                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
			echo AspMaxRequestEntityAllowed : * �⺻ ������ ����Ǿ� ����.                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
		cscript %script%\adsutil.vbs enum %%i | find /i "AspBufferingLimit" > nul
		if not errorlevel 1 (
			cscript %script%\adsutil.vbs enum %%i | find /i "AspBufferingLimit"           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		) else (
			echo AspBufferingLimit          : * �⺻ ������ ����Ǿ� ����.                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ###################           2.12 IIS DB ���� ����� ����            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : 7.0�̻�- ��û ���͸����� .asa, .asax Ȯ���ڰ� False�� �����Ǿ� ������ ��ȣ     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo                   ��û ���͸����� .asa, .asax Ȯ���ڰ� True�� �����Ǿ� ���� ���        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo                   .asa, .asax ������ ��ϵǾ� �־�� ��ȣ                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo                   (����, Global.asa ������ ������� �ʴ� ��� �ش� ���� ����.)           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo                 > (1) fileExtension=".asa" allowed="false" �̸� ��ȣ                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo                 > (2) fileExtension=".asa" allowed="true" �̸�, .asa ���� Ȯ��           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo   	    : 6.0����- .asa ������ ������ ��� ��ȣ                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo                   (���� ��) ".asa,C:\WINDOWS\system32\inetsrv\asp.dll,5,GET,HEAD,POST,TRACE" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo                    GET,HEAD,POST,TRACE ����: �������� ����								 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-12-enable
) else (
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt	
	goto 2-12-end
)

:2-12-enable
echo [��� ����Ʈ]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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

echo [�⺻ ����]                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo *** ����Ʈ�� ���� Ȯ��                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
				echo .asa ������ ��ϵǾ� ���� ����. [���]                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
				echo.                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			) else (
				echo * �⺻ ������ ����Ǿ� ����.                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ###################            2.13 IIS ���� ���丮 ����            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : �ش� ������Ʈ�� IIS Admin, IIS Adminpwd ���� ���͸��� �������� ���� ��� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo        : IIS 6.0 �̻� ���� �ش� ���� ���� 												 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-13-enable
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-13-end
)

:2-13-enable
echo [���� ���͸� ���� ��Ȳ]                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
rem ##########20160114 6.0 �̻� �ش� ���� �������� �ҽ� ���� ����##########
:: iis ver >= 6
if %iis_ver_major% geq 6 (
echo �� IIS 6.0 �̻� ���� �ش� ���� ���� 												 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt	
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
rem ##########20160114 6.0 �̻� �ش� ���� �������� �ҽ� ���� ��##########


rem ##########20160114 6.0 �̻� �ش� ���� �������� �ҽ� ���� ����##########
:: iis ver >= 7
::if %iis_ver_major% geq 7 (
	::%systemroot%\System32\inetsrv\appcmd list config -section:system.applicationHost/sites | find /i "virtualdirectory" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
::)
:: iis ver <= 6
::if %iis_ver_major% leq 6 (
	::%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\Virtual Roots" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
::)
rem ##########20160114 6.0 �̻� �ش� ���� �������� �ҽ� ���� ��##########
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
echo ###################           2.14 IIS ������ ���� ACL ����           ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : Ȩ ���͸� ���� �ִ� ���ϵ鿡 ���� Everyone ������ �������� ���� ��� ��ȣ   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : (��������Ʈ ������ Read ���Ѹ�)                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Enable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-14-enable
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-14-end
)

:2-14-enable
echo [��� ����Ʈ]                                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo *** ����Ʈ�� ���� Everyone ���� üũ                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo �� ��� ���� �������� ������ ��ȣ                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ###################         2.15 IIS �̻�� ��ũ��Ʈ ���� ����        ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : �Ʒ��� ���� ����� ������ �������� ���� ��� ��ȣ(Windows 20003 ���� ������ ��ġ�� �Ǿ� ��ȣ��)                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : (.htr .idc .stm .shtm .shtml .printer .htw .ida .idq)                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-15-enable
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-15-end
)

:2-15-enable
if %WinVer% geq 2 (
	echo �� Windows 2003 ���� ������ ��ġ�� �Ǿ� �ش���� ����							>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-15-end
) else (
	echo [��� ����Ʈ]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
		echo [�̻�� ��ũ��Ʈ ���� Ȯ��]                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%systemroot%\System32\inetsrv\appcmd list config | find /i "scriptprocessor" | findstr /i ".htr .idc .stm .shtm .shtml .printer .htw .ida .idq" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo �� ��� ���� �������� ������ ��ȣ                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)

	:: iis ver <= 6
	if %iis_ver_major% leq 6 (
		echo [�⺻ ����]                                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo -----------------------------------------------------                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		cscript %script%\adsutil.vbs enum W3SVC | findstr /i ".htr .idc .stm .shtm .shtml .printer .htw .ida .idq" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		cscript %script%\adsutil.vbs enum W3SVC | findstr /i ".htr .idc .stm .shtm .shtml .printer .htw .ida .idq" >> %tnd%\result.txt
		echo �� ��� ���� �������� ������ ��ȣ                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

		echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo *** ����Ʈ�� ���� Ȯ��                                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
					echo * ����� ������ ��ϵǾ� ���� ����. [��ȣ]                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
					echo.                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
				) else (
					echo * �⺻ ������ ����Ǿ� ����.                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ###################         2.16 IIS Exec ��ɾ� �� ȣ�� ����         ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : �ش� ������ ������Ʈ�� ���� 0�� ��� ��ȣ                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : (����1) IIS 5.0 �������� �ش� ������Ʈ�� ���� ���� ��� ��ȣ                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : (����2) IIS 6.0 �̻� ��ȣ                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-16-enable
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-16-end
)

:2-16-enable
:: iis ver >= 6
if %iis_ver_major% geq 6 (
	echo �� IIS 6.0 �̻� ��ȣ			                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-16-end
)

:: iis ver < 6
if %iis_ver_major% lss 6 (
	echo [Registry ����] 			                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ###################             2.17 IIS WebDAV ��Ȱ��ȭ              ##################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : ���� �� �� ������ �ش�Ǵ� ��� ��ȣ                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : 1. IIS �� ������� ���� ���                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : 2. DisableWebDAV ���� 1�� �����Ǿ� �������                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : 3. Windows NT, 2000�� ������ 4 �̻��� ��ġ�Ǿ� ���� ���                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : 4. Windows 2003, Windows 2008�� WebDAV �� ���� �Ǿ� ���� ���                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : "0,C:\WINDOWS\system32\inetsrv\httpext.dll,0,WEBDAV,WebDAV" (WebDAV ����-��ȣ) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : "1,C:\WINDOWS\system32\inetsrv\httpext.dll,0,WEBDAV,WebDAV" (WebDAV ���-���) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : 2008 �̻��� ��� allowed="false"   (WebDAV ����-��ȣ) 						>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : 2008 �̻��� ��� allowed="True"    (WebDAV ���-���) 						 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-17-enable
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-17-end
)

:2-17-enable

:: winver = 2000
if %WinVer% equ 1 (
	ECHO �� Win 2000�� ��� ������ 4 �̻� ��ȣ                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
	echo [WebDAV ���� Ȯ��]                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\adsutil.vbs enum W3SVC | find /i "webdav" | find /v "WebDAV;WEBDAV"            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\adsutil.vbs enum W3SVC | find /i "webdav" | find /v "WebDAV;WEBDAV"            > %tnd%\result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2.17-2003
)


:: iis ver >=7
if %iis_ver_major% geq 6 (
	echo [WebDAV ���� Ȯ��]                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo [���� - Registry ����(DisableWebDAV)]                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\registry\DisableWebDAV" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\DisableWebDAV"  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��� ���� �������� ���� ��� �ٸ� �������� ����                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [���� - OS Version, Service Pack]                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################         2.18 NetBIOS ���ε� ���� ���� ����       ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: TCP/IP�� NetBIOS ���� ���ε��� ���� �Ǿ��ִ� ��� ��ȣ                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (NetBIOS ��� ���� ����: NetbiosOptions 0x2 ��ȣ)                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (NetBIOS ��� ����: NetbiosOptions 0x1 ���)                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (�⺻ ��: NetbiosOptions 0x0 ���)                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (�������� ���) ���ͳ� ��������(TCP/IP)�� ������� �� ��� �� Wins ���� TCP/IP���� NetBIOS ��� ���� (139��Ʈ����) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" | findstr /iv "listing" > 2-18-netbios-list.txt
	for /f "tokens=1 delims=[" %%a in (2-18-netbios-list.txt) do echo %%a >> 2-18-netbios-list-1.txt
	for /f "tokens=1 delims=]" %%a in (2-18-netbios-list-1.txt) do echo %%a >> 2-18-netbios-list-2.txt
	FOR /F %%a IN (2-18-netbios-list-2.txt) do echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\%%a\NetbiosOptions >> 2-18-netbios-query.txt
	FOR /F %%a IN (2-18-netbios-query.txt) do %script%\reg query %%a >> 2-18-netbios-result.txt
	echo [NetBIOS over TCP/IP ���� ��Ȳ]                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo #########################        2.19 FTP ���� ���� ����          ######################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : FTP ���񽺸� ������� �ʴ� ��� ��ȣ (�̿� ������ ��������ͺ�)                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist ftp-enable.txt (
	echo �� FTP Service Enable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	net start | findstr /i "ftp"                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-19-enable
) else (
	echo �� FTP Service Disable                                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-19-end
)

:2-19-enable


echo [��� ����Ʈ]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo #####################        2.20 FTP ���丮 ���ٱ��� ����          ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : FTP Ȩ ���͸��� Everyone�� ���� ������ �������� ������ ��ȣ				              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist ftp-enable.txt (
	echo �� FTP Service Enable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	net start | findstr /i "ftp"                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-20-enable
) else (
	echo �� FTP Service Disable                                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-20-end
)


:2-20-enable
:: iis ver = 0
if %iis_ftp_ver_major%==0 (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� ������ �⺻ FTP�� Ÿ FTP ���� ����� (����Ȯ��^)                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-20-end
)
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [��� ����Ʈ]                                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
	echo [Ȩ���丮 ���� - WEB/FTP ���п�]                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%systemroot%\System32\inetsrv\appcmd list config -section:system.applicationHost/sites | findstr /i "name protocol physicalpath" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo *** ����Ʈ�� Ȩ���丮 ���ٱ��� Ȯ��                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ###########################         2.21 Anonymous FTP ����          ####################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : FTP�� ������� �ʰų� "�͸� ���� ���"�� üũ�Ǿ� ���� ���� ��� ��ȣ(Default : ��� �� ��)          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : metabase.xml ���� ���� ����        											 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : IIsFtpService	Location ="/LM/MSFTPSVC" �� FTP ����Ʈ �⺻ ����                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : FTP ����Ʈ�� ���� ���� �� �ش� �⺻ ������ ���� ����.							 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : IIsFtpServer	Location ="/LM/MSFTPSVC/ID"�� FTP ����Ʈ�� ��ϵ� ���� ����Ʈ ���� >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : ���� ����Ʈ�� AllowAnonymous ������ ������ FTP ����Ʈ �⺻ ������ ���� ����   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : IIsFtpServer	Location ="/LM/MSFTPSVC/~/Public FTP Site"�� ���� �� ������� ���� >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist ftp-enable.txt (
	echo �� FTP Service Enable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	net start | findstr /i "ftp"                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-21-enable
) else (
	echo �� FTP Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-21-end
)

:2-21-enable
:: iis ver = 0
if %iis_ftp_ver_major%==0 (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� ������ �⺻ FTP�� Ÿ FTP ���� �����                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-21-end
)

echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [��� ����Ʈ]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: iis ver >= 7
if %iis_ftp_ver_major% geq 7 (


	type ftpsite-list.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo [FTP ���� ���� Ȯ��]                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%systemroot%\System32\inetsrv\appcmd list config -section:system.applicationHost/sites | findstr /i "name protocol anonymousAuthentication enabled" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%systemroot%\System32\inetsrv\appcmd list config -section:system.applicationHost/sites | findstr /i "name protocol anonymousAuthentication enabled" > %tnd%\result.txt
	echo.                                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-218-enable	
) 
	type ftpsite-name.txt                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo [�⺻ ����]                                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo -----------------------------------------------------                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cscript %script%\adsutil.vbs enum MSFTPSVC | find /i "AllowAnonymous"                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cscript %script%\adsutil.vbs enum MSFTPSVC | find /i "AllowAnonymous"                   > %tnd%\result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo *** ����Ʈ�� ���� Ȯ��                                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
			echo AllowAnonymous : �⺻ ������ ����Ǿ� ����.                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo AllowAnonymous : �⺻ ������ ����Ǿ� ����.                                 > %tnd%\result.txt
			echo.                                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 2-213-enable
	)


::7�̻�
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
::6�̸�
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
echo ###########################        2.22 FTP ���� ���� ����          ######################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : FTP ���񽺿� �������� ������ �Ǿ� �ִ� ��� ��ȣ				                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� : metabase.xml ���� ���� ����        												 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : IIsFtpService	Location ="/LM/MSFTPSVC" �� FTP ����Ʈ �⺻ ����               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : IIsFtpVirtualDir	Location ="/LM/MSFTPSVC/ID/ROOT"�� FTP ���� ����Ʈ ����      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : ���� ����Ʈ�� IPSecurity ������ ������ FTP ����Ʈ �⺻ ������ ���� ����       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : IPSecurity="" �������� ����, IPSecurity="0102~" �������� ���� ����.           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : �������� ����Ʈ���� ���� ���� ���� ������ ���˽� ��� ����.                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : 2008�̻� ipSecurity allowUnlisted ������ False�� �Ǿ�� ��ȣ                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��      : ipSecurity allowUnlisted True��� �׼��� ��� / False ��� �׼��� �ź�         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist ftp-enable.txt (
	echo �� FTP Service Enable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	net start | findstr /i "ftp"                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-22-enable
) else (
	echo �� FTP Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-22-end
)

:2-22-enable
:: iis ver = 0
if %iis_ftp_ver_major%==0 (
	echo �� ������ �⺻ FTP�� Ÿ FTP ���� ����� (����Ȯ��^)                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2-22-end
)
echo [��� ����Ʈ]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
	echo *** ����Ʈ�� FTP �������� ���� Ȯ��                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
			echo * �������� ���� ����                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			echo.                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
			)
		)
)
:: iis ver <= 6
if %iis_ftp_ver_major% leq 6 (
	echo [FTP �������� ����]                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################             2.23 DNS Zone Transfer ����            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: DNS ���� ������ �Ʒ� ���� �� �ϳ��� �ش�Ǵ� ��� ��ȣ(SecureSecondaries 2) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (1) DNS ���񽺸� ������� ���� ���                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (2) ���� ���� ����� ���� ���� ���                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (3) Ư�� �����θ� ���� ������ ����ϴ� ���                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : * ������Ʈ����(�������� ������:3, �ƹ������γ�:0, �̸������ǿ������� �����θ�:1, ���������θ�:2 ) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : [����]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : ��� ���� ���� ��� DNS ������ ��ϵ� ��/������ ��ȸ ������ ���� ������,      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : DNS ���񽺸� ������� ���� ��� ���񽺸� ������ ���� �ǰ�                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "DNS Server" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO �� DNS Service Enable                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)	ELSE (
	ECHO �� DNS Service Disable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################         2.24 RDS (Remote Data Services) ����       ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ������ �� �Ѱ����� �ش�Ǵ� ��� ��ȣ                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (1) IIS �� ������� �ʴ� ���                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (2) Windows 2000 sp4, Windows 2003 sp2, Windows 2008 �̻� ��ȣ  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (3) ����Ʈ ������Ʈ�� MSADC ���� ���͸��� �������� ���� ���                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (4) �ش� ������Ʈ�� ���� �������� ���� ���                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

if exist iis-enable.txt (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 2.24-end
)

:: OS Version, Service Pack ���� üũ
echo [OS Version Ȯ��]                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo -----------------------------------------------------                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt	
:: winver = 2000
if %WinVer% equ 1 (
	ECHO �� Win 2000�� ��� ������ 4 �̻� ��ȣ                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
	ECHO �� Windows 2003 sp2 �̻�, Windows 2008 �̻� ��ȣ                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
		ECHO * ���˰��: MSADC ������͸��� �������� ����.                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
		ECHO * ���˰��: ��ϵ� REG���� �������� ����.                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
		ECHO * ���˰��: MSADC ������͸��� �������� ����.                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
		ECHO * ���˰��: ��ϵ� REG���� �������� ����.                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################               2.25 �ֽ� ������ ����              ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �ֽ� �������� ��ġ�Ǿ� ���� ��� ��ȣ                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (Windows NT 6a, Windows 2000 SP4, Windows 2003 SP2, Windows 2008 SP2)         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (Windows 2008R2 SP1, Windows 2012, 2012r2�� SP�� ����) 						 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type systeminfo.txt | find "Microsoft"                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type systeminfo.txt | find "Pack"                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo [OS Version Ȯ��]                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################         2.26 �͹̳� ���� ��ȣȭ ���� ����        ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �͹̳� ���񽺸� ������� �ʴ� ��� ��ȣ                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : �͹̳� ���񽺸� ��� �� ��ȣȭ ������ "Ŭ���̾�Ʈ�� ȣȯ����(�߰�)" �̻����� ������ ��� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (MinEncryptionLevel	2 �̻��̸� ��ȣ)                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
		echo �� Remote Desktop Services Enable                                          	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo �� ���� �͹̳� ���� ��ȣȭ ���� ���� Ȯ��                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo --------------------------------------------------------------------------------- >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel" | %script%\awk -F" " {print$3}	> %tnd%\result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                     
		)
	IF ERRORLEVEL 1 (
		echo �� Remote Desktop Services Disable                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=2												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)

goto 2-26-end

:2-268-enable
NET START | FIND "Terminal Service" > NUL
	IF NOT ERRORLEVEL 1 (
		echo �� Terminal Service Enable                                          			>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo �� ���� �͹̳� ���� ��ȣȭ ���� ���� Ȯ��                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo --------------------------------------------------------------------------------- >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel" | %script%\awk -F" " {print$3}	> %tnd%\result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		)
	IF ERRORLEVEL 1 (
		echo �� Terminal Service Disable                                             		 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################             2.27 IIS ������ ���� ����            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ��ϵ� �� ����Ʈ�� [����� ���� ����] �ǿ���                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : 400, 401, 403, 404, 500 ������ ���� ������ �������� �����Ǿ� �ִ� ��� ��ȣ   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
::echo ��       : (��� ����) prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="401.htm" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
rem �⺻ �����̱� ������ �� ������ �����.
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "World Wide Web Publishing Service" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO �� IIS Service Enable                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 1-45-enable
)	ELSE (
	ECHO �� IIS Service Disable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 46
)

:1-45-enable
echo [��� ����Ʈ]                                                                        	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo [�⺻ ����]                                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo *** ����Ʈ�� ���� Ȯ��                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
			echo �⺻ ������ ����Ǿ� ����.                                                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################             2.28 SNMP ���� ���� ����             ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: SNMP ���񽺸� ���ʿ��ϰ� ������� ������ ��ȣ                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : SNMP ���񽺴� �����ǰ� ������ SNMP ������ ���� ��� ���ʿ��ϰ� ���۵ǰ� �ִ� ������ �Ǵܵ�. >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "SNMP Service" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO �� SNMP Service Enable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=M/T												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)	ELSE (
	ECHO �� SNMP Service Disable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=O												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [SNMP ValidCommunities ����]                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" | findstr . >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [SNMP Trap ����]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################    2.29 SNMP ���� Ŀ�´�Ƽ��Ʈ���� ���⼺ ����   ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: SNMP Community �̸��� public, private �� �ƴ� �����ϱ� ��ư� �����Ǿ� ������ ��� ��ȣ                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (����1) REG_DWORD Community String ����                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (����2) ����: 2=�˸�, 4=�б�����, 8=�б�� ����, 16=�б�� �����             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "SNMP Service" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO �� SNMP Service Enable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)	ELSE (
	ECHO �� SNMP Service Disable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 29-end
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [SNMP ValidCommunities ����]                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" | findstr . >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" | findstr . >> %tnd%\result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type result.txt | findstr /i "REG_DWORD" > nul
if %ERRORLEVEL% neq 0 (
	echo "string ���� �����Ǿ� ���� ����(N/A)"                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo "���� ���� �ǰ�"                                                						   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo [SNMP Trap Commnunities ����]                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\TrapConfiguration" /s | findstr . >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 29-end
	)


echo [SNMP Trap Commnunities ����]                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################            2.30 SNMP Access Control ����           ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: Ư�� ȣ��Ʈ�� SNMP ��Ŷ�� ���� �� �ֵ��� SNMP Access Control�� ������ ��� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (PermittedManagers ������ ������ ��ȣ)                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (PermittedManagers ������ ������ ��� ȣ��Ʈ���� SNMP ��Ŷ�� ���� �� �־� ���) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "SNMP Service" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO �� SNMP Service Enable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)	ELSE (
	ECHO �� SNMP Service Disable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 30-end
	)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [SNMP ValidCommunities ����]                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" | findstr . >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" | findstr . >> %tnd%\result.txt
type %tnd%\result.txt | findstr /i "REG_DWORD" > nul
if %ERRORLEVEL% neq 0 (
	echo "string ���� �����Ǿ� ���� ����(N/A)"                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo "���� ���� �ǰ�"                                                						   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 30-end
	)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [SNMP Access Control ����]                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################              2.31 DNS ���� ���� ����             ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: DNS ���񽺸� ��� ���� �ʰų� ���� ������Ʈ ������ "����"���� ������ ��� ��ȣ  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (AllowUpdate	0 �̸� ��ȣ)                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : [����]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : ��� ���� ���� ��� DNS ������ ��ϵ� ��/������ ��ȸ ������ ���� ������,      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : DNS ���񽺸� ������� ���� ��� ���񽺸� ������ ���� �ǰ�                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : ������2008�̻󿡼� ��� ���� ���� ��� ����Ʈ�� �������� ����                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "DNS Server" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO �� DNS Service Enable                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto dns-enable
)	ELSE (
	ECHO �� DNS Service Disable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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


:: 2003 �̻� �˻�
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
echo ##################             2.32 HTTP/FTP/SMTP ��� ����           ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: HTTP/FTP/SMTP ��ʿ� �ý��� ������ ǥ�õ��� �ʴ� ��� ��ȣ                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "World Wide Web Publishing Service" > NUL
IF NOT ERRORLEVEL 1 (
echo ---------------------------------HTTP Banner-------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cscript %script%\http_banner.vbs >nul
	type http_banner.txt								>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 2>nul
echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	del http_banner.txt 2>nul
)	ELSE (
	ECHO �� IIS Service Disable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
	ECHO �� FTP Service Disable                                                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
	ECHO �� SMTP Service Disable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################                2.33 Telnet ���� ����               ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: Telnet ���񽺰� ���� �ǰ� ���� �ʰų�, ��������� NTLM �� ��� ��ȣ             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : [����]                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (SecurityMechanism 2. NTLM)                                            	 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (SecurityMechanism 6. NTLM, Password)                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (SecurityMechanism 4. Password)                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find /i "telnet" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO �� TELNET Service Enable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto telnet-enable
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	) ELSE (
	ECHO �� TELNET Service Disable 																	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ################# 2.34 ���ʿ��� ODBC/OLE-DB ������ �ҽ��� ����̺� ���� #################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �ý��� DSN �κ��� Data Source�� ���� ����ϰ� �ִ� ��� ��ȣ                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : �ý��� DSN �κ��� Data Source�� ������� �ʴµ� ��ϵǾ� ���� ��� ���       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources" | find "REG_SZ"           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
reg query "HKLM\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources" | find "REG_SZ"                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��� ���� ���� ��� ���ʿ��� ODBC/OLE-DB�� �������� ���� 							               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################          2.35 �����͹̳� ���� Ÿ�Ӿƿ� ����        ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ���� �͹̳��� ������� �ʰų�, ��� �� Session Timeout�� �����Ǿ� �ִ� ��� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (MaxIdleTime ���� Ȯ�� ���: 60000=1��, 300000=5��)                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
		echo �� Terminal Service Enable                                          			>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo �� ���� �͹̳� Session Timeout ����                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /s | findstr "MaxIdleTime" > %tnd%\idletime.txt
		type idletime.txt | findstr /v "fInheritMaxIdleTime"                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		type %tnd%\idletime.txt | findstr /v "fInheritMaxIdleTime" | find "REG_DWORD" | %script%\awk -F" " {print$3}        > %tnd%\result.txt
		for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.
		) else (
		echo �� Terminal Service Disable                                             		 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=1												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 35-end		
		)
goto 35-end



:35-2008R2
net start > netstart.txt
type netstart.txt | find /i "Remote Desktop Services" > nul
	IF %ERRORLEVEL% neq 1 (
		echo �� Remote Desktop Services Enable                                          	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo �� ���� �͹̳� Session Timeout ����                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /s | findstr "MaxIdleTime" > %tnd%\idletime.txt
		type idletime.txt | findstr /v "fInheritMaxIdleTime"                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		type %tnd%\idletime.txt | findstr /v "fInheritMaxIdleTime" | find "REG_DWORD" | %script%\awk -F" " {print$3}        > %tnd%\result.txt
		for /f %%r in (result.txt) do echo Result=%%r												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.        
		) else (
		echo �� Remote Desktop Services Disable                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=1												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 35-end		
		)
goto 35-end	


:35-2012
net start > netstart.txt
type netstart.txt | find /i "Remote Desktop Services" > nul
	IF %ERRORLEVEL% neq 1 (
		echo �� Remote Desktop Services Enable                                          	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo �� ���� �͹̳� Session Timeout ����                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo ---------------------------------------------------------------------------------       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		%script%\reg query "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /s | findstr "MaxIdleTime" > %tnd%\idletime.txt
		type idletime.txt | findstr /v "fInheritMaxIdleTime"                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		) else (
		echo �� Remote Desktop Services Disable                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo Result=1												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 35-end		
		)
		
	type %tnd%\idletime.txt | findstr /v "fInheritMaxIdleTime" | find "REG_DWORD"	
		if %ERRORLEVEL% neq 0 (
		echo IdleTime ������ �Ǿ� ���� �ʽ��ϴ�.					>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ############### 2.36 ����� �۾��� �ǽɽ����� ����� ��ϵǾ� �ִ��� ���� ################## >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ����� �۾��� �ǽɽ����� ����� ��ϵǾ� ���� ���� ��� ��ȣ                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver >= 2003
if %WinVer% geq 2 (
	echo �� ����� �۾� Ȯ��                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	schtasks | findstr [0-9][0-9][0-9][0-9]      	                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� at ��ɾ�� ����� �۾� Ȯ��                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
at                                                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver >= 2003
if %WinVer% geq 2 (
	echo [����] schtasks ��ü                                                      				 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################                3.01 �ֽ� HOT FIX ����              ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �ֽ�Hotfix �Ǵ� PMS(Patch Management System) Agent�� ��ġ�Ǿ� ���� ��� ��ȣ    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################             3.02 ��� ���α׷� ������Ʈ            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ���̷��� ��� ���α׷��� �ֽ� ���� ������Ʈ�� ��ġ�Ǿ� �ִ� ��� ��ȣ           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� ���� (��� ������Ʈ ���� Ȯ��)                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################          3.03 ��å�� ���� �ý��� �α� ����         ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �̺�Ʈ ���� ������ �Ʒ��� ���� �����Ǿ� �ִ� ��� ��ȣ                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (1) �α׿� �̺�Ʈ, ���� �α׿� �̺�Ʈ, ��å ���� : ����/���� ����             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (2) ���� ����, ���͸� ���� �׼���, ���� ��� : ���� ����                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################           4.01 �α��� ������ ���� �� ����          ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �αױ�Ͽ� ���� ������ ����, �м�, ����Ʈ �ۼ� �� ���� ���� ��ġ�� �̷������ ��� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� ���� (����� ���ͺ� ����)                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################   4.02 �������� �׼����� �� �ִ� ������Ʈ�� ���   ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: Remote Registry Service �� �����Ǿ� ���� ��� ��ȣ                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | find "Remote Registry" > NUL
IF NOT ERRORLEVEL 1 (
	ECHO �� Remote Registry Service Enable                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=F												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)	ELSE (
	ECHO �� Remote Registry Service Disable                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################              4.03 �̺�Ʈ �α� ���� ����            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �ִ� �α� ũ�� 10240KB (10MB) �̻��̰�, Retention 7776000(90��) �̻��̸� ��ȣ   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : "90�� ���� �̺�Ʈ ���"���� �����Ǿ� ���� ��� ��ȣ(Windows2008 �̻��� ����)                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (MaxSize 10485760 �̻�, Retention 7776000 �̻�)                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : Retention 0       = �ʿ��� ��� �̺�Ʈ �����                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : Retention 7776000 = �������� ������ �̺�Ʈ ����� (7776000 90��)            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : Retention -1      = �̺�Ʈ ����� ����(�������� �α� �����)                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
		echo �� Windows2008 �̻��� ����� ��¥ ���� �Ұ�			   	     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################      4.04 ���ݿ��� �̺�Ʈ �α� ���� ���� ����      ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �α� ���͸��� ���ѿ� Everyone �� ���� ��� ��ȣ                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (1) �ý��� �α� ���͸�: %systemroot%\system32\config                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (2) IIS �α� ���͸�: %systemroot%\system32\LogFiles                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
cacls %systemroot%\system32\config                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
cacls %systemroot%\system32\config                                                           > %tnd%\result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
if exist iis-enable.txt (
	echo �� IIS Service Enable                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cacls %systemroot%\system32\logfiles                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	cacls %systemroot%\system32\logfiles                                                         >> %tnd%\result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
) else (
	echo �� IIS Service Disable                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 0404-end
	echo.                                                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
type %tnd%\result.txt | find /I "everyone" > nul
	if %errorlevel% neq 0 (
	echo Everyone ������ �������� �ʽ��ϴ�.                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################               5.01 ��� ���α׷� ��ġ              ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ���̷��� ��� ���α׷��� ��ġ�Ǿ� �ִ� ��� ��ȣ                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
set vaccine="kaspersky norton bitdefender turbo avast v3"

echo �� Process List                                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
for %%a IN (%vaccine%) DO (
type tasklist.txt | findstr /i %%a 															>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type tasklist.txt | findstr /i %%b >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type tasklist.txt | findstr /i %%c >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type tasklist.txt | findstr /i %%d >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type tasklist.txt | findstr /i %%e >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type tasklist.txt | findstr /i %%f >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

echo. 																						 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� Service list                                                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
for %%a IN (%vaccine%) DO (
net start | findstr /i %%a >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | findstr /i %%b >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | findstr /i %%c >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | findstr /i %%d >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | findstr /i %%e >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
net start | findstr /i %%f >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)

echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����� ���� ��� ���μ��� ��� �� ���ͺ並 ���� Ȯ�� �ʿ�                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

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
echo ##################            5.02 SAM ���� ���� ���� ����            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: SAM ���� ���ٱ��ѿ� Administrator, System �׷츸 ���������� ��ϵ� ��� ��ȣ  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################                5.03 ȭ�麸ȣ�� ����                ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ȭ�� ��ȣ�⸦ �����ϰ�, ��ȣ�� ����ϸ�, ��� �ð��� 10���� ��� ��ȣ            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ������Ʈ�� ���� ���� ��� AD �Ǵ� OS��ġ �� ������ ���� ���� �����             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKCU\Control Panel\Desktop\ScreenSaveActive"                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKCU\Control Panel\Desktop\ScreenSaverIsSecure"                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKCU\Control Panel\Desktop\ScreenSaveTimeOut"                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [AD(Active Directory)�� ��� ������]                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################        5.04 �α׿����� �ʰ� �ý��� ���� ���       ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "�α׿� ���� �ʰ� �ý��� ���� ���"�� "������"���� �����Ǿ� �ִ� ��� ��ȣ    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (ShutdownWithoutLogon	0 �̸� ��ȣ)                                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################     5.05 ���� �ý��ۿ��� �ý��� ���� ���� ����     ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "���� �ý��ۿ��� ������ �ý��� ����" ��å�� "Administrators"�� ������ ��� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (Administrators = *S-1-5-32-544)                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ################# 5.06 ���� ���縦 �α��� �� ���� ��� ��� �ý��� ���� #################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "���� ���縦 �α��� �� ���� ��� ��� �ý��� ����" ��å�� "������"���� �����Ǿ� �ִ� ��� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (CrashOnAuditFail = 4,0 �̸� ��ȣ)                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt 
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################     5.07 SAM ������ ������ �͸� ���� ��� �� ��    ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "SAM ������ ������ �͸� ���� ��� ����" ��å�� "���"�̰�,                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : "SAM ������ �͸� ���� ��� ����" ��å�� "���"���� �����Ǿ� �ִ� ��� ��ȣ    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (restrictanonymous	1 �̰�, RestrictAnonymousSAM	1 �̸� ��ȣ)                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [SAM ������ ������ �͸� ���� ��� ���� ����]                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SYSTEM\CurrentControlSet\Control\LSA\restrictanonymous"             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [SAM ������ �͸� ���� ��� ���� ����]                                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################              5.08 Autologon ��� ����              ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: AutoAdminLogon ���� ���ų�, AutoAdminLogon 0���� �����Ǿ� �ִ� ��� ��ȣ        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (DefaultPassword ��Ʈ���� �����Ѵٸ� ������ ���� �ǰ�)                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################       5.09 �̵��� �̵�� ���� �� ������ ���       ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "�̵��Ĺ̵�� ���� �� ������ ���" ��å�� "Administrators"���� �Ǿ� �ְų�, ����� ���� ��� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (����� ������ �ƹ� �׷쵵 ���ǵ��� ����: Default Administrators�� ��� ���� ��ȣ) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (AllocateDASD=1,"0" �̸� Administrators ��ȣ)                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (AllocateDASD=1,"1" �̸� Administrators �� Power Users)                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (AllocateDASD=1,"2" �̸� Administrators �� Interactive Users)                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
type Local_Security_Policy.txt | Find /I "AllocateDASD"                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����� ���� ��� Default�� Administrators �� ��� ������ 							>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################             5.10 ��ũ���� ��ȣȭ ����            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "������ ��ȣ�� ���� ������ ��ȣȭ" ��å�� ���� �� ��� ��ȣ                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	FOR /F "tokens=1 delims=\" %%a IN ("%cd%") DO (
		echo %%a\ 																			 > %tnd%\inf_using_drv.txt
	)
	echo �� current using drive volume														 > %tnd%\inf_Encrypted_file_check.txt
	type inf_using_drv.txt 																	 >> %tnd%\inf_Encrypted_file_check.txt
	FOR /F "tokens=1" %%a IN (inf_using_drv.txt) DO (
		echo.								 												 >> %tnd%\inf_Encrypted_file_check.txt
		echo �� Search within the %%a drive...  											 >> %tnd%\inf_Encrypted_file_check.txt
		cipher /s:%%a | find "E "        												 	 >> %tnd%\inf_Encrypted_file_check.txt 2> nul
		if errorlevel 1 echo Encrypted file is not exist 									 >> %tnd%\inf_Encrypted_file_check.txt
		echo.								 												 >> %tnd%\inf_Encrypted_file_check.txt
	)
	type inf_Encrypted_file_check.txt 														 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: winver = 2003
if %WinVer% equ 2 (
	echo �� Current using drive volume 														 > %tnd%\inf_Encrypted_file_check.txt
	type inf_using_drv.txt 																	 >> %tnd%\inf_Encrypted_file_check.txt

	FOR /F "tokens=1" %%a IN (inf_using_drv.txt) DO (
		echo.								 												 >> %tnd%\inf_Encrypted_file_check.txt
		echo �� Search within the %%a drive...  											 >> %tnd%\inf_Encrypted_file_check.txt
		cipher /s:%%a | find "E " | findstr "^E"											 >> %tnd%\inf_Encrypted_file_check.txt 2> nul
		if errorlevel 1 echo Encrypted file is not exist 									 >> %tnd%\inf_Encrypted_file_check.txt
		echo.								 												 >> %tnd%\inf_Encrypted_file_check.txt
	)
	type inf_Encrypted_file_check.txt 														 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
:: winver <= 2008
if %WinVer% geq 3 (
	echo �� Windows 2008 �̻� �ش���� ���� 													 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################          5.11 Dos���� ��� ������Ʈ�� ����         ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: Dos ���ݿ� ���� ��� ������Ʈ���� �����Ǿ� �ִ� ��� ��ȣ                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (1) SynAttackProtect = REG_DWORD 0 �� 1 �� ���� �� ��ȣ                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (2) EnableDeadGWDetect = REG_DWORD 1(True) �� 0 ���� ���� �� ��ȣ             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (3) KeepAliveTime = REG_DWORD 7,200,000(2�ð�) �� 300,000(5��)���� ���� �� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (4) NoNameReleaseOnDemand = REG_DWORD 0(False) �� 1 �� ���� �� ��ȣ           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver >= 2008
if %WinVer% geq 3 (
	echo �� Windows 2008 �̻� �ش���� ����                             			 				>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 5.11-end
) else (
	echo [SynAttackProtect ����]                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\SynAttackProtect" /s >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo [EnableDeadGWDetect ����]                                                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableDeadGWDetect" /s >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo [KeepAliveTime ����]                                                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo --------------------------------------------------------                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	%script%\reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime" /s >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo [NoNameReleaseOnDemand ����]                                                            >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################  5.12 ����ڰ� ������ ����̹��� ��ġ�� �� ���� �� ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "����ڰ� ������ ����̹��� ��ġ�� �� ���� ��" ��å�� "���"���� ������ ��� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (AddPrinterDrivers=4,1 �̸� ��ȣ)                                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################   5.13 ���� ������ �ߴ��ϱ� ���� �ʿ��� ���޽ð�   ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "�α׿� �ð��� ����Ǹ� Ŭ���̾�Ʈ ���� ����" ��å�� "���"���� �����ϰ�,       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : "���� ������ �ߴ��ϱ� ���� �ʿ��� ���� �ð�" ��å�� "15��"���� ������ ��� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (EnableForcedLogOff	1 �̰�, AutoDisconnect	15 �̸� ��ȣ)                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################                5.14 ��� �޽��� ����               ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �ý����� �ҹ����� ��뿡 ���� ��� �޽���/������ �����Ǿ� �ִ� ��� ��ȣ        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [Win NT]                                                            					 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\LegalNoticeCaption" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
%script%\reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\LegalNoticeText" >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo [Win 2000�̻�]                                                            				>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################         5.15 ����ں� Ȩ ���͸� ���� ����        ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ����� ������ Ȩ ���͸��� Eveyone ������ ���� ��� ��ȣ                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo. > %tnd%\home-directory.txt
dir "C:\Users\*" | find "<DIR>" | findstr /V "All Defalt ."                                  >> %tnd%\home-directory.txt
FOR /F "tokens=5" %%i IN (home-directory.txt) DO cacls "C:\Users\%%i" | find /I "Everyone" > nul
IF %ERRORLEVEL% equ 1 (
echo �� Everyone ������ �Ҵ�� Ȩ���͸��� �߰ߵ��� �ʾ���.                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################              5.16 LAN Manager ���� ����            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "LAN Manager ���� ����" ��å�� "NTLMv2 ���丸 ����"���� �����Ǿ� �ִ� ��� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����  : (LM NTML ���� ����: LmCompatibilityLevel=4,0)                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (LM NTML NTLMv2���� ���� ���(����� ���): LmCompatibilityLevel=4,1)         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (NTLM ���� ����: LmCompatibilityLevel=4,2)                                    >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (NTLMv2 ���丸 ����: LmCompatibilityLevel=4,3)                                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (NTLMv2 ���丸 ����WLM�ź�: LmCompatibilityLevel=4,4)                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (NTLMv2 ���丸 ����WLM�ź� NTLM �ź�: LmCompatibilityLevel=4,5)               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : ���� ���� ��� �ƹ��͵� ������ �� �� ������                                   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �ش� ������ �����ϸ� Ŭ���̾�Ʈ�� ���� �Ǵ� ���� ���α׷����� ȣȯ���� ������ ��ĥ �� ����. >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ���� ���� ���� ����                                                                     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################   5.17 ���� ä�� ������ ������ ��ȣȭ �Ǵ� ����    ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: �Ʒ� 3���� ��å�� "���" ���� �Ǿ� ���� ��� ��ȣ                               >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: (1) ������ ������: ���� ä�� �����͸� ������ ��ȣȭ �Ǵ� ����(�׻�)           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��     : (2) ������ ������: ���� ä�� �����͸� ������ ��ȣȭ(������ ���)              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��     : (3) ������ ������: ���� ä�� �����͸� ������ ����(������ ���)                >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��     : (4,1)���, (4,0)��� �� ��                							  		 	>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################             5.18 ���� �� ���丮 ��ȣ             ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ���Ͻý����� ���� ����� ���� ���ִ� NTFS�� ��� ��ȣ                           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo [����]                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo C: ����̺� ���� Ȯ��(NTFS�� ��� ������ ���� �ο� ������ ��µ�)                       >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################        5.19 ��ǻ�� ���� ��ȣ �ִ� ��� �Ⱓ        ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: "��ǻ�� ���� ��ȣ ���� ��� ����" ��å "������"���� ���� �Ǿ� �ְ�,           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : "��ǻ�� ���� ��ȣ �ִ� ��� �Ⱓ" ��å�� "90��"�� �����Ǿ� �ִ� ��� ��ȣ     >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (DisablePasswordChange=4,0 �̰�, MaximumPasswordAge=4,90 �̸� ��ȣ)           >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	echo Win 2000 �ش���� ����                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################             5.20 �������α׷� ��� �м�            ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: ���� ���α׷����� ���ʿ��� ���񽺰� ��ϵǾ� ���� �ʰ�, �ֱ������� �����ϴ� ��� ��ȣ >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (����� ���ͺ� �� ���� ���α׷� ���˰��� ���� Ȯ��)                         >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ���� ���α׷� Ȯ��(HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run)  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo �� ���� ���α׷� Ȯ��(HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run) >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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
echo ##################           6.01 Windows ���� ��� ���             ###################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ����: Windows ���� ���� �����Ǿ� �ִ� ��� ��ȣ (LoginMode 1 �̸� ��ȣ)             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (1) LoginMode 1 �̸� Windows ���� ���                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��       : (2) LoginMode 2 �̸� SQL Server �� Windows ���� ���                          >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �� ��Ȳ                                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
:: winver = 2000
if %WinVer% equ 1 (
	echo Win 2000 �ش���� ����                                                              >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	echo Result=N/A												>> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	goto 6.01-end
)

:: winver >= 2003
if %WinVer% geq 2 (
	net start | find "SQL Server" > NUL
	IF NOT ERRORLEVEL 1 (
		ECHO �� SQL Server Enable                                                                  >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
		goto 6.01-start
		echo.                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
	)	ELSE (
		ECHO �� SQL Server Disable                                                                 >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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

::�ý��� ���� ��� ����
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
	echo C:\WINDOWS\system32\inetsrv\MetaBase.xml �������� ����.                             >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
)
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt

echo ####################################################################################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ###############                      ���� ����                     #################### >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
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

::�ý��� ���� ��� ��



::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::::::::::::::::::::::: ���� �κ� ����2::::::::::::::::::::::::::::::::::::::::::
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


rem Netbios ����
del %tnd%\2-18-netbios-list-1.txt 2> nul
del %tnd%\2-18-netbios-list-2.txt 2> nul
del %tnd%\2-18-netbios-list.txt 2> nul
del %tnd%\2-18-netbios-query.txt 2> nul
del %tnd%\2-18-netbios-result.txt 2> nul


rem DB ���� ����
del %tnd%\unnecessary-user.txt 2>nul
del %tnd%\password-null.txt 2>nul


rem IIS ���� del
del %tnd%\iis-enable.txt 2>nul
del %tnd%\iis-version.txt 2>nul
del %tnd%\website-list.txt 2>nul
del %tnd%\website-name.txt 2>nul
del %tnd%\website-physicalpath.txt 2>nul
del %tnd%\sample-app.txt 2>nul


rem FTP ���� del
del %tnd%\ftp-enable.txt 2>nul
del %tnd%\ftpsite-list.txt 2>nul
del %tnd%\ftpsite-name.txt 2>nul
del %tnd%\ftpsite-physicalpath.txt 2>nul
del %tnd%\ftp-ipsecurity.txt 2>nul


rem ���� ����̺� ��� ���� del
del %tnd%\inf_using_drv_temp3.txt 2>nul
del %tnd%\inf_using_drv_temp2.txt 2>nul
del %tnd%\inf_using_drv_temp1.txt 2>nul
del %tnd%\inf_using_drv.txt 2>nul



echo.                                                                                        >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo �������������������������������������   END Time  �������������������������������������   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
date /t                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
time /t                                                                                      >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt


echo.
echo ��������������������������������������   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ����                                                              ����   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ����       Windows %WinVer_name% Security Check is Finished       ����   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ����                                                              ����   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo ��������������������������������������   >> %tnd%\%COMPUTERNAME%.WINDOWS.%WinVer_name%.result.txt
echo.
echo [+] Windows Security Check is Finished
pause

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::::::::::::::::::::::: ���� �κ� ��2::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

