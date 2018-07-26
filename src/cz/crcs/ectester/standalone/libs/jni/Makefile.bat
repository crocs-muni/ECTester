@if not defined _echo echo off
setlocal EnableDelayedExpansion

:: See if we are cleaning.
if "%1" == "clean" (
  echo ** cleaning
  del mscng_provider.dll
  exit
)


:: Determine arch.
reg Query "HKLM\Hardware\Description\System\CentralProcessor\0" | find /i "x86" > NUL && (set ARCH=32& set ARCH_S=x86& set ARCH_VS=x86) || (set ARCH=64& set ARCH_S=x64& set ARCH_VS=amd64)

echo ** ARCH %ARCH_S%


:: Find a working visual studio environment.
set found=0
set vsw_path="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

set vs_path=
for /f "usebackq delims=" %%i in (`%vsw_path% -nologo -prerelease -latest -property installationPath`) do (
  if exist "%%i\Common7\Tools\vsdevcmd.bat" (
	echo ** VsDevCmd at %%i\Common7\Tools\vsdevcmd.bat
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

echo ** VS_PATH %vs_path%


:: Try to find vcruntime.
set vc_base=%vs_path%\VC\Tools\MSVC\
if exist %vc_base% (
  set vc_version=
  for /f "delims=" %%i in ('dir /b /on "!vc_base!"') do (
    set vc_version=%%i
  )
  echo ** VC_VERSION !vc_version!
  set vc_include=%vc_base%!vc_version!\include
  set vc_lib=%vc_base%!vc_version!\lib\%ARCH_S%
)


:: Get the paths to Microsoft CNG SDK.
set root_rel=..\..\..\..\..\..\..\
set mscng_rel_include=ext\mscng\Include
set mscng_rel_lib=ext\mscng\Lib

pushd %root_rel%
pushd %mscng_rel_include%
set mscng_include=%CD%
popd
pushd %mscng_rel_lib%
set mscng_lib=%CD%
popd
popd

set mscng_lib_arch=%mscng_lib%\X%ARCH%

echo ** CNG_INCLUDE !mscng_include!
echo ** CNG_LIB !mscng_lib!


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

echo ** JAVA_HOME !JAVA_HOME!

set JNI_INCLUDEDIR=%JAVA_HOME%\include
set JNI_PLATFORMINCLUDEDIR=%JNI_INCLUDEDIR%\win32
set JNI_LIBDIR=%JAVA_HOME%\lib


:: Setup binaries.
if not defined CC (
  set CC=cl.exe
)
if not defined LINK (
  set LINK=link.exe
)

echo ** CC !CC!
echo ** LINK !LINK!


:: Try to find uCRT.
set ucrt_base=%ProgramFiles(x86)%\Windows Kits\10\
if exist %ucrt_base% (
  set ucrt_version=
  for /f "delims=" %%i in ('dir /b /on "!ucrt_base!\Include"') do (
    set ucrt_version=%%i
  )
  echo ** uCRT !ucrt_version!
  set ucrt_include=%ucrt_base%Include\!ucrt_version!\ucrt
  set ucrt_lib=%ucrt_base%Lib\!ucrt_version!
  set ucrt_lib_arch=!ucrt_lib!\ucrt\%ARCH_S%
)

:: Setup INCLUDE paths.
set INCLUDE_CLI=/I. /I"%JNI_INCLUDEDIR%" /I"%JNI_PLATFORMINCLUDEDIR%" /I"%mscng_include%"

echo ** INCLUDE %INCLUDE%
echo ** INCLUDE_CLI %INCLUDE_CLI%

:: Setup LIB paths.
set LIBPATH=/LIBPATH:"%JNI_LIBDIR%" /I"%mscng_lib_arch%"

echo ** LIB %LIB%
echo ** LIBPATH %LIBPATH%
echo.


%CC%  /EHsc %INCLUDE_CLI% mscng.c /LD /Femscng_provider.dll