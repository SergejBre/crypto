#-------------------------------------------------
#
# Project created by QtCreator 2019-07-25T23:40:58
#
#-------------------------------------------------

QT       += testlib
QT       -= gui

TARGET = cryptotest
CONFIG   += console debug
CONFIG   -= app_bundle

TEMPLATE = app

#SRCPATH = $$PWD/..
SRCPATH = $$PWD/../../CryptFileDevice/src

INCLUDEPATH += $$SRCPATH

SOURCES += cryptotest.cpp \
    $$SRCPATH/cryptfiledevice.cpp

HEADERS  += \
    $$SRCPATH/cryptfiledevice.h

#openssl libraly
win32 {
INCLUDEPATH += c:/OpenSSL-Win32/include
LIBS += -Lc:/OpenSSL-Win32/bin -llibeay32
}
linux|macx {
LIBS += -lcrypto
QMAKE_LFLAGS += "-Wl,-rpath,\'\$$ORIGIN/lib\'"
}

DEFINES += SRCDIR=\\\"$$PWD/\\\"
