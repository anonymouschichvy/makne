cmake_minimum_required(VERSION 3.15)
project(MetamorphicEngine LANGUAGES CXX)

# Set C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add Include Directories
include_directories(include)

# Source Files
set(SOURCES
    src/main.cpp
    src/CodeReorderer.cpp
    src/ControlFlowObfuscator.cpp
    src/DataEncoder.cpp
    src/DecryptorGenerator.cpp
    src/ImportObfuscator.cpp
    src/InstructionSubstitutor.cpp
    src/JunkCodeInserter.cpp
    src/MetamorphicEngine.cpp
    src/PayloadEncryptor.cpp
    src/PolymorphicEngine.cpp
    src/RegisterRandomizer.cpp
    src/SectionRandomizer.cpp
    src/Utils.cpp
)

# Headers (for IDE visibility)
set(HEADERS
    include/PEStructs.h
    include/CodeReorderer.h
    include/ControlFlowObfuscator.h
    include/DataEncoder.h
    include/DecryptorGenerator.h
    include/ImportObfuscator.h
    include/InstructionSubstitutor.h
    include/JunkCodeInserter.h
    include/MetamorphicEngine.h
    include/PayloadEncryptor.h
    include/PolymorphicEngine.h
    include/RegisterRandomizer.h
    include/SectionRandomizer.h
    include/Utils.h
)

# Executable Target
add_executable(MetamorphicEngine ${SOURCES} ${HEADERS})

# Fetch Zycore
include(FetchContent)
FetchContent_Declare(
    zycore
    URL https://github.com/zyantific/zycore-c/archive/refs/tags/v1.5.0.zip
)
FetchContent_MakeAvailable(zycore)

# Fetch Zydis
set(ZYAN_ZYCORE_PATH "${zycore_SOURCE_DIR}" CACHE PATH "The path to look for Zycore" FORCE)
FetchContent_Declare(
    zydis
    URL https://github.com/zyantific/zydis/archive/refs/tags/v4.0.0.zip
)
FetchContent_MakeAvailable(zydis)

# Link Zydis
target_link_libraries(MetamorphicEngine PRIVATE Zydis)

# Compiler-specific settings
if(MSVC)
    target_compile_options(MetamorphicEngine PRIVATE /W4 /WX- /Od /EHsc)
else()
    target_compile_options(MetamorphicEngine PRIVATE -Wall -Wextra -O2)
endif()
