//------------------------------------------------------------------------------
//  Home Office
//  Nürnberg, Germany
//  E-Mail: sergej1@email.ua
//
//  Copyright (C) 2017/2018 free Project Crypto. All rights reserved.
//------------------------------------------------------------------------------
//  Project: Crypto - Advanced File Encryptor, based on simple XOR and
//           reliable AES methods
//------------------------------------------------------------------------------
#ifndef SETTINGS
#define SETTINGS

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------
#include <QString>

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------
struct Settings
{
    // path to the ConfigFile (XML)
    QString configFile;
    // is logging enabled?
    bool enableLog;
    // path to logFile
    QString pathToLog;
    // maximum size of log File (in Kb)
    quint32 maxSizeLog;
};

#endif // SETTINGS

