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
 * @file mainwindow.h
 *
 * @brief This file contains the declaration of the class MainWindow.
 */
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------
#include <QMainWindow>

class QLabel;
class QHeaderView;

namespace Ui {
class MainWindow;
}

class Settings;
class SettingsDialog;
class CryptFileDevice;

/**
 * @class MainWindow
 *
 * @brief The MainWindow class is a back-end user interface.
 *
 *  The MainWindow class provides the user with a number of Back-End functions
 *  that handle user events and reactions to these events.
 */
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    //! The ProcessStatus type is used to handle errors that occur during encryption and data processing.
    typedef enum
    {
        //! Execution has been successful.
        PROCESS_STATUS_SUCCESS,
        //! Provided file path(s) are invalid.
        PROCESS_STATUS_CONTINUE,
        //! I/O Error or not enough storage space.
        PROCESS_STATUS_BREAK,
        //! Bad allocation memory, etc.
        PROCESS_STATUS_STATE_ERROR
    } ProcessStatus;

    //! The DataType type is used to distinguish data types in user selection dialogs.
    enum DataType
    {
        //! The data type is single file.
        File,
        //! The data type is a directory.
        Dir
    };

    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    Settings *getSettings( void ) const;

public slots:
    void wErrorMessage( const QVariant &message );

protected:
    void closeEvent(QCloseEvent *event) Q_DECL_OVERRIDE;

private slots:
    // Adding new file(s)
    void on_addFile_clicked( void );
    void on_actionAdd_file_s_triggered( void );
    // Adding new Directory
    void on_addDir_clicked( void );
    void on_actionAdd_Directory_triggered( void );
    // Exiting the program
    void on_actionQuit_triggered( void );
    // Encrypt data
    void on_execButton_clicked( void );
    void on_actionEncryption_triggered( void );
    // Program settings
    void on_actionSettings_triggered( void );
    // About Qt...
    void on_actionAbout_Qt_triggered( void );
    // About this program...
    void on_actionAbout_crypto_triggered( void );
    // Edit a item from the list
    void editItem( void );
    void on_editEntry_clicked( void );
    // Delete a item from the list
    void deleteItem( void );
    void on_deleteEntry_clicked( void );
    // Help for this application
    void on_actionContents_triggered( void );
    // Changed a cell from the list?
    void on_targetsList_currentCellChanged(int, int, int, int);
    // switch to hidden mode for the Password
    void on_hidPassMode_clicked( bool checked );
    // compare between passwordLine and confirmLine
    void on_passLine_textChanged( const QString &arg );
    void on_passConfirmLine_textChanged( const QString &arg );
    // Clear the entire list in one click
    void on_clearList_clicked( void );
    // Process all subdirectories recursively
    void on_recurseDirs_clicked( void );
    // Selection of the screen font
    void on_actionFont_triggered( void );

private:
    Ui::MainWindow *ui;
    QLabel *status;
    Settings *currentSettings;
    SettingsDialog *settings;
    CryptFileDevice *encryptFile;

    QAction *editItemAction;
    QAction *deleteItemAction;

    qint64 fullSize;
    qint64 getSize( const QString &obj, DataType type ) const;
    QString getTextSize( const qint64 size ) const;

    qint64 getCount( void ) const;

    void updateStatusBar( void ) const;

    QStringList getDirFiles( const QString &dirPath ) const;

    QList<QPair<DataType, qint64>> targets;
    QHeaderView *headview;

    QString lastUsedPath;
    QString lastUsedDir;

    bool processError;
    ProcessStatus fileProcessing( const QString &file );

    void readSettings( void );
    void writeSettings( void ) const;
    void clearList( void ) const;
    void addFiles( void );
    void addDirs( void );
    void execute( void );
    void about( void );
};

#endif // MAINWINDOW_H
