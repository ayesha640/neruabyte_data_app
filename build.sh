#!/usr/bin/sh

# Prepare build options based on OS type detection
if [[ $OSTYPE == "msys" ]]; then
    # Static linking flags for SDL, SDL_ttf, and FreeType libraries on Windows (MSYS)
    SDL_STATIC_LINK_FLAGS="-Lsdl2/lib -lmingw32 -lmingwex -lmsvcrt -lSDL2 -lSDL2main -LC:/NEW/SDL2_ttf/lib -lSDL2_ttf -LC:/msys64/mingw64/lib -lfreetype -lsqlite3    -LC:/NEW/libsodium-win64/lib -lsodium  -LC:/NEW/OpenSSL-Win64/lib/VC/x64/MDd -LC:/NEW/OpenSSL-Win64/lib/VC/x64/MT -LC:/NEW/OpenSSL-Win64/lib/VC/x64/MTd -LC:/NEW/OpenSSL-Win64/lib/VC/x64/MD -lssl -lcrypto -lws2_32 -lcrypt32 -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va -lm -ldinput8 -ldxguid -ldxerr8 -luser32 -lgdi32 -lwinmm -limm32 -lole32 -loleaut32 -lshell32 -lsetupapi -lversion -luuid -lrpcrt4 -static -Dmain=SDL_main"

    # Additional GCC options for Windows (MSYS)
    GCC_OPTS="-Wno-overflow -fwrapv"
    
    # If a release build is requested, add optimization and window mode flags
    if [ $1 ]; then
        GCC_OPTS="$GCC_OPTS -O3 -mwindows -DRELEASE=$1"
    fi
    
    # Check if Mingw64 is installed, download and extract if not
    if [ ! -d /c/mingw64 ]; then
        echo -e "\033[33mDownloading mingw64...\nINFO: This differs from MinGW in that it expects and produces x64 (64 bit) rather than x86 (32 bit)\n32 bit builds may be supported in the future\033[m"
        curl -L https://github.com/brechtsanders/winlibs_mingw/releases/download/14.1.0posix-18.1.5-11.0.1-ucrt-r1/winlibs-x86_64-posix-seh-gcc-14.1.0-llvm-18.1.5-mingw-w64ucrt-11.0.1-r1.7z > mingw64.7z
        7z x mingw64.7z -o/c/mingw64
        rm mingw64.7z
        echo -e "\033[33mIMPORTANT: If windows defender detects a threat, this is a false positive. Allow it if you want to make use of all of mingw64's features, however this is not required to build successfully\033[m"
    fi
    
else
    # Static linking flags for SDL, SDL_ttf, and FreeType libraries on other platforms
    SDL_STATIC_LINK_FLAGS="-Lsdl2/lib -lSDL2 -lSDL2main -LC:/NEW/SDL2_ttf/lib -lSDL2_ttf -LC:/msys64/mingw64/lib -lfreetype -lsqlite3  -LC:/NEW/libsodium-win64/lib -lsodium  -LC:/NEW/OpenSSL-Win64/lib/VC/x64/MDd -LC:/NEW/OpenSSL-Win64/lib/VC/x64/MT -LC:/NEW/OpenSSL-Win64/lib/VC/x64/MTd -LC:/NEW/OpenSSL-Win64/lib/VC/x64/MD -lssl -lcrypto -lws2_32 -lcrypt32  -Dmain=SDL_main"
    # Additional GCC options for other platforms
    GCC_OPTS="-Wno-overflow -fwrapv -Wno-narrowing"

    # If a release build is requested, add optimization flag
    if [ $1 ]; then
        GCC_OPTS="$GCC_OPTS -O3 -DRELEASE=$1"
    fi
fi

# Build preparation
clear

# Check if icon.ico exists; if yes, include it in the build process
if [ ! -f icon.ico ]; then
    echo -e "\033[mWarning: no icon.ico found. Building without an icon...\033[m"
else
    echo "id ICON icon.ico" > .rc
    /c/mingw64/bin/windres.exe .rc -O coff -o .icon.res
    rm .rc
    GCC_OPTS=".icon.res $GCC_OPTS"
fi

# Build process
/c/mingw64/bin/g++.exe src/main.cpp  -Wl,--strip-all -ffunction-sections -I/c/NEW/include -I/c/NEW/include/boost -I/c/NEW/include/rapidjson -IC:/NEW/sdl2/include  -I/c/NEW/SDL2_ttf/include -I/C:/msys64/mingw64/include/sqlite3  -I/C:/msys64/mingw64/include/freetype2  -I/C:/NEW/libsodium-win64/include -I/C:/NEW/OpenSSL-Win64/include $GCC_OPTS $SDL_STATIC_LINK_FLAGS -Wl,--gc-sections -o main

A=$?

# Clean up icon resource file if it was created
if [ -f .icon.res ]; then
    rm .icon.res
fi

# Run executable after a successful build
if [ $A -eq 0 ]; then
    echo -e "\033[32mBuild successful. Enter argv and hit enter to run\033[m"
    read A; clear
    ./main $A
fi
