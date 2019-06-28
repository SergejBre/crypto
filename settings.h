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
/**
 * @file settings.h
 *
 * @brief This file contains the declaration of the structure Settings
 */
#ifndef SETTINGS
#define SETTINGS

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------
#include <QString>

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------
/**
 * @struct Settings
 *
 * @brief The Settings structure
 *
 * The structure contains specific fields for storing logging/debugging parameters.
 * Motivation. This structure is necessary for storing user settings of the debugging system.
 * It differs from the main system of user settings in that it allows you to save
 * settings in a separate file. This is required for compatibility with other platforms.
 */
struct Settings
{
    //! Path to the configuration file.
    QString configFile;
    //! Enables / disables the logging procedure
    bool enableLog;
    //! Path to the log/debug file
    QString pathToLog;
    //! This field determines the maximum size of the log file (in Kb)
    quint32 maxSizeLog;
};

#endif // SETTINGS

