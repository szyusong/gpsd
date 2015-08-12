
cmake_minimum_required(VERSION 2.6)

project(gpsd)

SET(CMAKE_SYSTEM_NAME Linux)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FILE_OFFSET_BITS=64 -ffunction-sections -fdata-sections")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -rdynamic")
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-gc-sections -rdynamic")
#CMAKE_SHARED_LINKER_FLAGS
#CMAKE_MODULE_LINKER_FLAGS

# http://dev.mysql.com/doc/refman/5.0/en/c-api-building-clients.html
# mysql_config --cflags
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I/usr/include/mysql -DBIG_JOINS=1 -fno-strict-aliasing -DUNIV_LINUX -DUNIV_LINUX")
# mysql_config --libs
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -rdynamic -L/usr/lib/mysql -lmysqlclient")

find_package(PkgConfig)

pkg_check_modules(GIOUNIX gio-unix-2.0)
include_directories(${GIOUNIX_INCLUDE_DIRS})
link_directories(${GIOUNIX_LIBRARY_DIRS})

pkg_check_modules(GTHREAD gthread-2.0)
include_directories(${GTHREAD_INCLUDE_DIRS})
link_directories(${GTHREAD_LIBRARY_DIRS})

pkg_check_modules(GLIB glib-2.0)
include_directories(${GLIB_INCLUDE_DIRS})
link_directories(${GLIB_LIBRARY_DIRS})

pkg_check_modules(GIO gio-2.0)
include_directories(${GIO_INCLUDE_DIRS})
link_directories(${GIO_LIBRARY_DIRS})

pkg_check_modules(GOBJECT gobject-2.0)
include_directories(${GOBJECT_INCLUDE_DIRS})
link_directories(${GOBJECT_LIBRARY_DIRS})

pkg_check_modules(LIBDAEMON libdaemon)
include_directories(${LIBDAEMON_INCLUDE_DIRS})
link_directories(${LIBDAEMON_LIBRARY_DIRS})

pkg_check_modules(LIBSQLITE3 sqlite3)
include_directories(${LIBSQLITE3_INCLUDE_DIRS})
link_directories(${LIBSQLITE3_LIBRARY_DIRS})

pkg_check_modules(LIBZMQ libzmq)
include_directories(${LIBZMQ_INCLUDE_DIRS})
link_directories(${LIBZMQ_LIBRARY_DIRS})

pkg_check_modules(LIBCZMQ libczmq)
include_directories(${LIBCZMQ_INCLUDE_DIRS})
link_directories(${LIBCZMQ_LIBRARY_DIRS})

pkg_check_modules(LIBUV libuv)
include_directories(${LIBUV_INCLUDE_DIRS})
link_directories(${LIBUV_LIBRARY_DIRS})

SET(LIBS ${GIOUNIX_LIBRARIES}
   ${GTHREAD_LIBRARIES}
   ${GLIB_LIBRARIES}
   ${GIO_LIBRARIES}
   ${GOBJECT_LIBRARIES}
   ${LIBDAEMON_LIBRARIES}
   ${LIBSQLITE3_LIBRARIES}
   ${LIBZMQ_LIBRARIES}
   ${LIBCZMQ_LIBRARIES}
   zlog
   ${LIBUV_LIBRARIES}
)

include_directories(${PROJECT_SOURCE_DIR} 
  ${PROJECT_SOURCE_DIR}/pt
)

#-------------------------------------------------------------------------------

add_executable(gpsd gpsd.c utils.c)
target_link_libraries(gpsd ${LIBS})

#-------------------------------------------------------------------------------

install(
  TARGETS gpsd
  DESTINATION /usr/bin/
)

install(
  FILES 
    ${gpsd_SOURCE_DIR}/zlog.conf
  DESTINATION /etc/gpsd/
)
