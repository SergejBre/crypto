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
 * @file settingsdialog.cpp
 *
 * @brief This file contains the definition of methods and interfaces of the SettingsDialog class.
 */

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------
#include "settingsdialog.h"
#include "ui_settingsdialog.h"
#include <QLoggingCategory>

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------
Q_LOGGING_CATEGORY(logSettingsDialog, "settings")

/**
 * @brief The constructor of the class SettingsDialog
 *
 * Sets default user interface parameters or uses saved values as parameters.
 *
 * @param parent of the type QWidget*
 */
SettingsDialog::SettingsDialog( QWidget *parent ) :
    QDialog( parent ),
    ui( new Ui::SettingsDialog )
{
    Q_ASSERT( parent != nullptr );
    ui->setupUi( this );

    this->fillSettings();
    ui->logBrowser->setLineWrapMode(QTextEdit::NoWrap);
    ui->logBrowser->setStyleSheet( QString("font: 14px; color: blue") );
}

/**
 * @brief The destructor of the class SettingsDialog
 */
SettingsDialog::~SettingsDialog()
{
    delete ui;
}

/**
 * @brief get-function for the settings
 *
 * @return *currentSettings of the type Settings*
 */
Settings* SettingsDialog::getSettings( void )
{
    return &(this->currentSettings);
}

/**
 * @brief The updateSettings function.
 *
 * This function updates the settings from the user interface in the Settings.
 */
void SettingsDialog::updateSettings( void )
{
    //! @todo Alternative method to set default data!
    this->currentSettings.enableLog = ui->enableLog->isChecked();
    this->currentSettings.pathToLog = ui->logFile->text();
    this->currentSettings.maxSizeLog = ui->maxSizeLog->text().toULong();
}

/**
 * @brief The fillSettings function.
 *
 * @note Filling data from the configuration file. Alternative approach. Now it is disabled.
 */
void SettingsDialog::fillSettings( void )
{
    //! @todo The method of checking and reading from the configuration file.
}

/**
 * @brief The fillSettingsUi function.
 *
 * The function fills the Ui parameters that it takes from the Settings.
 */
void SettingsDialog::fillSettingsUi( void )
{
    //! @todo Validation method for configuration data.
    ui->enableLog->setChecked( currentSettings.enableLog );
    ui->logFile->setText( currentSettings.pathToLog );
    ui->logFile->setEnabled( currentSettings.enableLog );
    ui->maxSizeLog->setText( QString::number(currentSettings.maxSizeLog) );
    ui->maxSizeLog->setEnabled( currentSettings.enableLog );
    ui->logBox->setTitle( QString( "Log file %1").arg( currentSettings.pathToLog ));
    ui->logBrowser->setEnabled( currentSettings.enableLog );
    if ( ui->logBrowser->source().isEmpty())
    {
        ui->logBrowser->setSource( QUrl::fromLocalFile( currentSettings.pathToLog ));
    }
    else if ( currentSettings.enableLog )
    {
        ui->logBrowser->reload();
    }
}

/**
 * @brief Slot on_buttonBox_accepted for confirmation and acceptance of changes in settings.
 */
void SettingsDialog::on_buttonBox_accepted( void )
{
    if ( !ui->enableLog->isChecked() && currentSettings.enableLog )
    {
        qInfo( logSettingsDialog ) << "logging disabled";
    }
    else if ( ui->enableLog->isChecked() && !currentSettings.enableLog )
    {
        qInfo( logSettingsDialog ) << "logging enabled";
    }
    this->updateSettings();
    this->hide();
}

/**
 * @brief The on_enableLog_clicked slot for controlling user interface parameters.
 *
 * The other setting parameters are then hidden.
 *
 * @param checked of type bool. Checks whether logging is enabled.
 */
void SettingsDialog::on_enableLog_clicked( bool checked )
{
    ui->logFile->setEnabled( checked );
    ui->logBrowser->setEnabled( checked );
    ui->maxSizeLog->setEnabled( checked );
}
