cmake_minimum_required(VERSION 3.16)
project(NetworkTrafficAnalyzer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS system)

if(WIN32)
    set(NPCAP_SDK "C:/npcap-sdk")
    include_directories(${NPCAP_SDK}/Include)
    link_directories(${NPCAP_SDK}/Lib/x64)

    add_executable(pcap_reader src/pcap_reader.cpp)
    target_link_libraries(pcap_reader wpcap Packet ws2_32)

    add_executable(live_capture src/live_capture.cpp)
    target_link_libraries(live_capture wpcap Packet ws2_32)

    add_executable(async_capture src/async_capture.cpp)
    target_include_directories(async_capture PRIVATE ${Boost_INCLUDE_DIRS})
    target_link_libraries(async_capture wpcap Packet ws2_32 ${Boost_LIBRARIES})
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)

    add_executable(pcap_reader src/pcap_reader.cpp)
    target_include_directories(pcap_reader PRIVATE ${PCAP_INCLUDE_DIRS})
    target_link_libraries(pcap_reader PRIVATE ${PCAP_LIBRARIES})

    add_executable(live_capture src/live_capture.cpp)
    target_include_directories(live_capture PRIVATE ${PCAP_INCLUDE_DIRS})
    target_link_libraries(live_capture PRIVATE ${PCAP_LIBRARIES})

    add_executable(async_capture src/async_capture.cpp)
    target_include_directories(async_capture PRIVATE ${PCAP_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS})
    target_link_libraries(async_capture PRIVATE ${PCAP_LIBRARIES} ${Boost_LIBRARIES} pthread)
endif()
