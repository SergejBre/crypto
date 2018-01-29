#------------------------------------------------------------------------------
#  Home Office
#  Nürnberg, Germany
#  E-Mail: sergej1@email.ua
#
#  Copyright (C) 2017/2018 free Project Crypto. All rights reserved.
#------------------------------------------------------------------------------
#  Project: Crypto - Advanced File Encryptor, based on simple XOR and
#           reliable AES methods
#-------------------------------------------------
#
# Project created by QtCreator 2017-12-12T20:56:29
#
#-------------------------------------------------

QT       += core gui
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
CONFIG += c++11
CONFIG += debug_and_release

TEMPLATE = app
MOC_DIR = moc
QMAKE_CFLAGS_RELEASE += -O3
QMAKE_CXXFLAGS_RELEASE += -O3
CONFIG(debug, debug|release) {
    TARGET = cryptod
    CONFIG += debug
    DEFINES += DEBUG_OUTPUT
} else {
    TARGET = crypto
    CONFIG += release
    DEFINES += QT_NO_DEBUG_OUTPUT
}

DEPENDPATH += .
INCLUDEPATH += .

SOURCES += main.cpp\
        mainwindow.cpp \
    settingsdialog.cpp \
    cryptfiledevice.cpp

HEADERS  += mainwindow.h \
    settingsdialog.h \
    settings.h \
    cryptfiledevice.h

FORMS    += mainwindow.ui \
    settingsdialog.ui \
    settingstabdialog.ui

RESOURCES = crypto.qrc
win32 {
VERSION = 1.0.1.0
QMAKE_TARGET_COMPANY = Free Project
QMAKE_TARGET_PRODUCT = Crypto
QMAKE_TARGET_DESCRIPTION = Advanced File Encryptor
QMAKE_TARGET_COPYRIGHT = (c) 2018 sergej1@email.ua
RC_ICONS = images/icon.ico
}

#openssl libraly
win32 {
INCLUDEPATH += c:/OpenSSL-Win32/include
LIBS += -Lc:/OpenSSL-Win32/bin -llibeay32
}
linux|macx {
LIBS += -lcrypto
#LIBS += -L/usr/local/ssl/lib -lcrypto
QMAKE_LFLAGS += "-Wl,-rpath,\'\$$ORIGIN/lib\'"
}

DISTFILES +=

DEFINES += USE_MY_STUFF

target.path = /usr/local/crypto
INSTALLS += target
