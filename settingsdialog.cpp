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
 * @brief SettingsDialog::updateSettings
 */
void SettingsDialog::updateSettings( void )
{
    // TODO
    this->currentSettings.enableLog = ui->enableLog->isChecked();
    this->currentSettings.pathToLog = ui->logFile->text();
    this->currentSettings.maxSizeLog = ui->maxSizeLog->text().toULong();
}

/**
 * @brief SettingsDialog::fillSettings
 */
void SettingsDialog::fillSettings( void )
{
    // TODO
}

/**
 * @brief SettingsDialog::fillSettingsUi
 */
void SettingsDialog::fillSettingsUi( void )
{
    // TODO
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
 * @brief SettingsDialog::on_buttonBox_accepted
 */
void SettingsDialog::on_buttonBox_accepted( void )
{
    this->updateSettings();
    this->hide();
}

/**
 * @brief SettingsDialog::on_enableLog_clicked
 * @param checked
 */
void SettingsDialog::on_enableLog_clicked( bool checked )
{
    ui->logFile->setEnabled( checked );
    ui->logBrowser->setEnabled( checked );
    ui->maxSizeLog->setEnabled( checked );
    qInfo( logSettingsDialog ) << "Enabled Logging: " << checked;
}
