@if not defined _echo echo off
setlocal EnableDelayedExpansion

:: ENV variables respected:
::  - JAVA_HOME
::  - CC
::  - USE_EXT_MSCNG
::  - DEBUG

:: See if we are cleaning.
if "%1" == "clean" (
  echo ** cleaning
  del *.dll *.exp *.lib *.obj
  exit
)

set TAB=	


:: Determine arch.
reg Query "HKLM\Hardware\Description\System\CentralProcessor\0" | find /i "x86" > NUL 2>&1 && (set ARCH=32& set ARCH_S=x86& set ARCH_VS=x86) || (set ARCH=64& set ARCH_S=x64& set ARCH_VS=amd64)

echo ** ARCH%TAB%%TAB%%ARCH_S%


:: Find a working visual studio environment.
set found=0
set vsw_path="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

set vs_path=
for /f "usebackq delims=" %%i in (`%vsw_path% -nologo -prerelease -latest -property installationPath`) do (
  if exist "%%i\Common7\Tools\vsdevcmd.bat" (
	echo ** VsDevCmd%TAB%%TAB%%%i\Common7\Tools\vsdevcmd.bat
    call "%%i\Common7\Tools\vsdevcmd.bat" -no_logo -arch=%ARCH_VS%
	if ERRORLEVEL 1 (
	  echo nope.
	) else (
	  set found=1
	  set vs_path=%%i
	  break	
	)
  )
)

:: Test if we have a visual studio env.
if %found% EQU 0 (
  echo Working VsDevCmd not found.
  exit /b 2
)

echo ** VS_PATH%TAB%%TAB%%vs_path%


:: Try to find vcruntime.
set vc_base=%vs_path%\VC\Tools\MSVC\
if exist %vc_base% (
  set vc_version=
  for /f "delims=" %%i in ('dir /b /on "!vc_base!"') do (
    set vc_version=%%i
  )
  echo ** VC_VERSION%TAB%!vc_version!
  set vc_include=%vc_base%!vc_version!\include
  set vc_lib=%vc_base%!vc_version!\lib\%ARCH_S%
)


:: Get the paths to Microsoft CNG SDK.
set root_rel=..\..\..\..\..\..\..\
set mscng_rel_include=ext\mscng\10\Include
set mscng_rel_lib=ext\mscng\10\Lib

pushd %root_rel%
pushd %mscng_rel_include%
set mscng_include=%CD%
popd
pushd %mscng_rel_lib%
set mscng_lib=%CD%
popd
popd

set mscng_lib_arch=%mscng_lib%\X%ARCH%

echo ** CNG_INCLUDE%TAB%%mscng_include%
echo ** CNG_LIB%TAB%%TAB%%mscng_lib_arch%


:: Get the paths to Java JNI.
if not defined JAVA_HOME (
  set jva=
  for /f "delims=" %%i in ('where javac') do (
    set jva=%%~dpi
  )
  pushd !jva!\..
  set JAVA_HOME=!CD!
  popd
)

echo ** JAVA_HOME%TAB%%JAVA_HOME%

set JNI_INCLUDEDIR=%JAVA_HOME%\include
set JNI_PLATFORMINCLUDEDIR=%JNI_INCLUDEDIR%\win32
set JNI_LIBDIR=%JAVA_HOME%\lib


:: Setup binaries.
if not defined CC (
  set CC=cl.exe
)

echo ** CC%TAB%%TAB%%CC%


:: Try to find uCRT.
set ucrt_base=%ProgramFiles(x86)%\Windows Kits\10\
if exist %ucrt_base% (
  set ucrt_version=
  for /f "delims=" %%i in ('dir /b /on "!ucrt_base!\Include"') do (
    set ucrt_version=%%i
  )
  echo ** uCRT%TAB%%TAB%!ucrt_version!
  set ucrt_include=%ucrt_base%Include\!ucrt_version!\ucrt
  set ucrt_lib=%ucrt_base%Lib\!ucrt_version!
  set ucrt_lib_arch=!ucrt_lib!\ucrt\%ARCH_S%
)


:: Setup INCLUDE paths.
set INCLUDE_CLI=/I. /I"%JNI_INCLUDEDIR%" /I"%JNI_PLATFORMINCLUDEDIR%"

if defined USE_EXT_MSCNG (
  set INCLUDE_CLI=!INCLUDE_CLI! /I"%mscng_include%"
)

echo ** INCLUDE%TAB%%TAB%%INCLUDE%
echo ** INCLUDE_CLI%TAB%%INCLUDE_CLI%


:: Setup LIB paths.
set LIBPATH=/LIBPATH:"%JNI_LIBDIR%"

if defined USE_EXT_MSCNG (
  set LIBPATH=!LIBPATH! /LIBPATH:"%mscng_lib_arch%"
)

echo ** LIB%TAB%%TAB%%LIB%
echo ** LIBPATH%TAB%%TAB%%LIBPATH%


:: Setup DEBUB options.
set OTHER_CLI=
if defined DEBUG (
  set OTHER_CLI=/Od /Z7
) else (
  set OTHER_CLI=/O2
)

echo ** OTHER_CLI%TAB%%OTHER_CLI%
echo.

echo ^>^> %CC% /W2 /EHsc %OTHER_CLI% %INCLUDE_CLI% mscng.c c_utils.c c_timing.c bcrypt.lib jvm.lib kernel32.lib /Femscng_provider.dll /LD /link %LIBPATH% /nologo
echo.

%CC% /W2 /EHsc %OTHER_CLI% %INCLUDE_CLI% mscng.c c_utils.c c_timing.c bcrypt.lib jvm.lib kernel32.lib /Femscng_provider.dll /LD /link %LIBPATH% /nologo
