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
 * @file settingsdialog.h
 *
 * @brief This file contains the declaration of the class SettingsDialog
 */
#ifndef SETTINGSDIALOG_H
#define SETTINGSDIALOG_H

#include <QDialog>
#include "settings.h"

namespace Ui {
class SettingsDialog;
}

/**
 * @class SettingsDialog
 *
 * @brief The SettingsDialog class
 *
 *  The SettingsDialog class provides the user with a number of Back-End functions
 *  that handle user events and reactions to these events.
 */
class SettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SettingsDialog(QWidget *parent = 0);
    ~SettingsDialog();

    Settings *getSettings( void );
    void fillSettingsUi( void );

private slots:

    void on_buttonBox_accepted( void );

    void on_enableLog_clicked( bool checked );

private:
    Ui::SettingsDialog *ui;
    Settings currentSettings;

    void fillSettings( void );
    void updateSettings( void );
};

#endif // SETTINGSDIALOG_H
