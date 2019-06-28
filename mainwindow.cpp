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
 * @file mainwindow.cpp
 *
 * @brief This file contains the definition of methods and interfaces of the MainWindow class.
 */

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------
#include <QtGui>
#include <QTextCodec>
#include <QMessageBox>
#include <QFileDialog>
#include <QFontDialog>
#include <QtDebug>
#include <limits>
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "settingsdialog.h"
#include "cryptfiledevice.h"

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------
Q_LOGGING_CATEGORY(logMainWindow, "MainWin")
#define COEFF 1048576
#define ONEKB 1024

/**
 * @brief The constructor of the class MainWindow.
 *
 * Sets default user interface parameters or uses saved values as parameters.
 *
 * @param parent of the type QWidget*
 */
MainWindow::MainWindow( QWidget *parent ) :
    QMainWindow( parent ),
    ui( new Ui::MainWindow ),
    fullSize( 0LL )
{
    ui->setupUi( this );
    this->settings = new SettingsDialog( this );
    this->currentSettings = settings->getSettings();

    QTextCodec *codec = QTextCodec::codecForName( "UTF-8" );
    QTextCodec::setCodecForLocale( codec );

    QStringList header;
    header << QObject::tr( "Path to Data" ) << QObject::tr( "Size" );
    ui->targetsList->setHorizontalHeaderLabels( header );
    this->headview = new QHeaderView( Qt::Horizontal, ui->targetsList );
    ui->targetsList->setHorizontalHeader( headview );
    this->headview->setSectionResizeMode(0, QHeaderView::Stretch);
    this->headview->setSectionResizeMode(1, QHeaderView::Fixed);
    ui->targetsList->setContextMenuPolicy( Qt::ActionsContextMenu );
    // Allow selection of only one item
    ui->targetsList->setSelectionMode(QAbstractItemView::SingleSelection);
    // Enable selection line by line
    ui->targetsList->setSelectionBehavior(QAbstractItemView::SelectRows);

    this->editItemAction = new QAction( QObject::tr("Edit path"), this );
    this->editItemAction->setStatusTip( QObject::tr("Edit this entry") );
    this->editItemAction->setEnabled( false );
    this->deleteItemAction = new QAction( QObject::tr("Delete from list"), this );
    this->deleteItemAction->setStatusTip( QObject::tr("Delete this entry") );
    this->deleteItemAction->setEnabled( false );

    ui->execButton->setStatusTip( QObject::tr("Execute encryption or decryption of the data") );
    ui->addFile->setStatusTip( QObject::tr("Add the file(s) to the list") );
    ui->addDir->setStatusTip( QObject::tr("Add a Directory to the list") );
    ui->editEntry->setStatusTip( QObject::tr("Edit an selected entry from the the list") );
    ui->deleteEntry->setStatusTip( QObject::tr("Delete an selected entry from the list") );
    ui->clearList->setStatusTip( QObject::tr("Clear the entire list in one click") );
    ui->overwriteData->setStatusTip( QObject::tr("Overwrite the selected data in encrypted form"));
    ui->recurseDirs->setStatusTip( QObject::tr("Process all subdirectories recursively"));
    ui->bufferSize->setStatusTip( QObject::tr("Set the size of the buffer for processing"));
    ui->xorCrypt->setStatusTip( QObject::tr("Simple XOR encryption method (less reliable)"));
    ui->aesCrypt->setStatusTip( QObject::tr("AES encryption method (more reliable)"));
    ui->passLine->setStatusTip( QObject::tr("Permitted only main letters(Aa-Zz) and numbers"));

    ui->targetsList->addAction(editItemAction);
    ui->targetsList->addAction(deleteItemAction);
    QObject::connect(editItemAction, SIGNAL(triggered()),
                     this, SLOT(editItem()));
    QObject::connect(deleteItemAction, SIGNAL(triggered()),
                     this, SLOT(deleteItem()));

    this->readSettings();

    if( ui->hidPassMode->isChecked() )
    {
        ui->passLine->setEchoMode( QLineEdit::Password );
        ui->passConfirmLine->setEchoMode( QLineEdit::Password );
    }
    QRegExp regExp("[a-zA-Z0-9_,.!?]{0,}");
    ui->passLine->setValidator(new QRegExpValidator(regExp, this));
    ui->passConfirmLine->setValidator(new QRegExpValidator(regExp, this));
    ui->lockEncrypt->setChecked( false );

    this->status = new QLabel( this );
    this->status->setStyleSheet( QString("color: blue") );
    ui->statusBar->addPermanentWidget( status, 0 );
    this->updateStatusBar();
}

/**
 * @brief The destructor of the class MainWindow.
 */
MainWindow::~MainWindow()
{
    delete ui;
}

/**
 * @brief get-function for the settings
 * @return currentSettings of the type Settings*
 */
Settings *MainWindow::getSettings() const
{
    return currentSettings;
}

/**
 * @brief Critical error message in a separate window.
 * @param message of the type QString, error message.
 */
void MainWindow::wErrorMessage(const QVariant &message)
{
    this->processError = true;
    QMessageBox::critical( this, QObject::tr("Error"), message.toString() );
}

/**
 * @brief Handle program completion event.
 *
 * Before exiting the program, the user interface parameters are automatically saved.
 *
 * @param event of type QCloseEvent*
 */
void MainWindow::closeEvent( QCloseEvent *event )
{
    this->writeSettings();
    event->accept();
}

/**
 * @brief The function reads the list of files of a given directory and all files of its subdirectories.
 *
 * @param dirPath of the type QString&
 *
 * @return fileNames of the type QStringList a list of the files
 */
QStringList MainWindow::getDirFiles( const QString &dirPath ) const
{
    Q_ASSERT( !dirPath.isEmpty() );
    QDir dir( dirPath );
    Q_ASSERT( dir.exists() );
    QStringList fileNames;
    QStringList fileList = dir.entryList(QDir::Files | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);
    foreach( const QString &fit, fileList )
    {
        fileNames.append(dir.absolutePath() + QDir::separator() + fit );
    }
    QStringList dirList = dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    foreach( const QString &dit, dirList )
    {
        QDir curDir = dir;
        curDir.cd( dit );
        QStringList curList = getDirFiles(curDir.absolutePath());
        foreach( const QString &item, curList )
        {
            fileNames.append(QFileInfo( item ).absoluteFilePath());
        }
    }
    return fileNames;
}

/**
 * @brief The function reads the parameters necessary for the user interface that were saved in the previous session.
 *
 * Such important parameters will be read as
 * - the position of the window on the screen and window size,
 * - interface font and its size,
 * - the user interface settings (overwrite of the data, recurse of dir's, etc.)
 * - error and event logging options.
 */
void MainWindow::readSettings( void )
{
    QSettings settings;
    settings.beginGroup("Geometry");
    QPoint pos = settings.value("pos", QPoint(200, 200)).toPoint();
    QSize size = settings.value("size", QSize(580, 480)).toSize();
    this->resize( size );
    this->move( pos );
    settings.endGroup();

    settings.beginGroup("Font");
    QFont font;
    font.fromString(settings.value("font", QFont()).toString());
//    this->setFont(font);
    qApp->setFont(font);
    settings.endGroup();

    settings.beginGroup("ULayot");
    bool overwriteData = settings.value("overwriteData", false).toBool();
    ui->overwriteData->setChecked(overwriteData);
    bool recurseDirs = settings.value("recurseDirs", true).toBool();
    ui->recurseDirs->setChecked(recurseDirs);
    int bufferSize = settings.value("bufferSize", 5).toInt();
    ui->bufferSize->setValue(bufferSize);
    bool xorCrypt = settings.value("xorCrypt", false).toBool();
    ui->xorCrypt->setChecked(xorCrypt);
    ui->aesCrypt->setChecked(!xorCrypt);
    QString lastUsedPath = settings.value("lastUsedPath", QStandardPaths::writableLocation(QStandardPaths::HomeLocation)).toString();
    this->lastUsedPath = lastUsedPath;
    QString lastUsedDir = settings.value("lastUsedDir", QStandardPaths::writableLocation(QStandardPaths::HomeLocation)).toString();
    this->lastUsedDir = lastUsedDir;
    settings.endGroup();

    settings.beginGroup("Logging");
    bool enableLog = settings.value("enableLog", true).toBool();
    this->getSettings()->enableLog = enableLog;
    QString pathToLog = settings.value("pathToLog", "crypto.log").toString();
    this->getSettings()->pathToLog = pathToLog;
    quint32 maxSizeLog = settings.value("maxSizeLog", 10U).toUInt();
    this->getSettings()->maxSizeLog = maxSizeLog;
    settings.endGroup();
}

/**
 * @brief The function saves the user interface parameters that have been changed by the user in the current session.
 *
 * Such parameters will be updated as
 * - the position of the window on the screen and window size,
 * - interface font and its size,
 * - the user interface settings (overwrite of the data, recurse of dir's, etc.)
 * - error and event logging options.
 */
void MainWindow::writeSettings( void ) const
{
    QSettings settings;
    settings.beginGroup("Geometry");
    settings.setValue("pos", pos());
    settings.setValue("size", size());
    settings.endGroup();

    settings.beginGroup("Font");
    settings.setValue("font", this->font().toString());
    settings.endGroup();

    settings.beginGroup("ULayot");
    settings.setValue("overwriteData", ui->overwriteData->isChecked());
    settings.setValue("recurseDirs", ui->recurseDirs->isChecked());
    settings.setValue("bufferSize", ui->bufferSize->value());
    settings.setValue("xorCrypt", ui->xorCrypt->isChecked());
    settings.setValue("lastUsedPath", this->lastUsedPath);
    settings.setValue("lastUsedDir", this->lastUsedDir);
    settings.endGroup();

    settings.beginGroup("Logging");
    settings.setValue("enableLog", this->getSettings()->enableLog);
    settings.setValue("pathToLog", this->getSettings()->pathToLog);
    settings.setValue("maxSizeLog", this->getSettings()->maxSizeLog);
    settings.endGroup();
}

/**
 * @brief The function solves the total size of the data selected for encryption.
 *
 * @param obj of the type QString&, path to the data
 * @param type of the type enum DataType {File, Dir}
 * @return size of the type qint64, the size of the data.
 */
qint64 MainWindow::getSize( const QString &obj, DataType type ) const
{
    Q_ASSERT( !obj.isEmpty() );
    if( type == File )
    {
        return QFileInfo( obj ).size();
    }
    else if( type == Dir )
    {
        QStringList objectsList;
        if( !ui->recurseDirs->isChecked() )
        {
            QStringList fDirList = QDir(obj).entryList(QDir::Files | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);
            foreach( const QString &fdit, fDirList )
            {
                objectsList.append( obj + QDir::separator() + fdit );
            }
        }
        else
        {
            objectsList = getDirFiles( obj );
        }
        qint64 size = 0LL;
        foreach( const QString &path, objectsList )
        {
            size += QFileInfo( path ).size();
        }

        return size;
    }
    return 0LL;
}

/**
 * @brief The function converts data size to text format (bytes/Kb/Mb/Gb)
 * @param size of the type qint64, the size of the data
 * @return string, as the text.
 */
QString MainWindow::getTextSize( const qint64 size ) const
{
    Q_ASSERT( size >= 0LL );
    if( size > 1024 * 1024 * 1024 )
    {
        return QLocale::system().toString( static_cast<double>(size) / (1024 * 1024 * 1024), 'f', 3).append(QObject::tr(" Gb") );
    }
    else if (size > 1024 * 1024)
    {
        return QLocale::system().toString( static_cast<double>(size) / (1024 * 1024), 'f', 3).append(QObject::tr(" Mb") );
    }
    else if (size > 1024)
    {
        return QLocale::system().toString( static_cast<double>(size) / 1024, 'f', 3).append(QObject::tr(" Kb") );
    }
    else
    {
        return QLocale::system().toString( static_cast<double>(size), 'f', 0).append(QObject::tr(" bytes") );
    }
}

/**
 * @brief The function return value is the number of data list items(files).
 *
 * @return number of data list files
 */
qint64 MainWindow::getCount( void ) const
{
    QStringList objectsList;
    objectsList.clear();

    for (int i = 0; i < ui->targetsList->rowCount(); i++)
    {
        if( this->targets.at(i).first == File )
        {
            objectsList.append(ui->targetsList->item(i, 0)->text());
        }
        else if( this->targets.at(i).first == Dir )
        {
            if (!ui->recurseDirs->isChecked())
            {
                QStringList fDirList = QDir(ui->targetsList->item(i, 0)->text()).entryList(QDir::Files | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);
                foreach( const QString &fdit, fDirList )
                {
                    objectsList.append( ui->targetsList->item(i, 0)->text() + QDir::separator() + fdit );
                }
            }
            else
            {
                objectsList = objectsList+getDirFiles(ui->targetsList->item(i, 0)->text());
            }
        }
    }

    return objectsList.size();
}

/**
 * @brief The function displays on the status bar of the main window the number of list items and their total size.
 */
void MainWindow::updateStatusBar( void ) const
{
    this->status->setText( QObject::tr( "Selected items %1, Overall size %2" ).arg( getCount() ).arg( getTextSize( this->fullSize ) ));
}

/**
 * @brief The function adds the selected file to the list of items.
 */
void MainWindow::addFiles( void )
{
    QString dir = ( QDir( this->lastUsedPath ).exists() ) ?
                this->lastUsedPath :
                QStandardPaths::writableLocation(QStandardPaths::HomeLocation);
    QFileDialog *dlg = new QFileDialog( this );
    QStringList filePaths;
    filePaths = dlg->getOpenFileNames( this,
                                       QObject::tr("Crypto: Select the file(s)"),
                                       dir,
                                       QObject::tr("All files (*)") );
    if (filePaths.size() <= 0)
    {
        return;
    }

    // Get upper directory
    QDir upperDir( filePaths.last() );
    if ( upperDir.cdUp() )
    {
        this->lastUsedPath = upperDir.path();
    }
    for (long i = 0; i < filePaths.size(); i++)
    {
        ui->targetsList->setRowCount(ui->targetsList->rowCount() + 1);

        QTableWidgetItem *item = new QTableWidgetItem( filePaths.at(i) );
        item->setFlags( Qt::ItemIsSelectable|Qt::ItemIsEnabled );
        item->setIcon( QIcon(":/images/insert-file.png") );
        item->setToolTip( filePaths.at(i) );
        ui->targetsList->setItem( ui->targetsList->rowCount() - 1, 0, item );

        qint64 size = getSize( filePaths.at(i), File );
        item = new QTableWidgetItem( getTextSize(size) );
        item->setFlags( Qt::ItemIsSelectable|Qt::ItemIsEnabled );
        ui->targetsList->setItem( ui->targetsList->rowCount() - 1, 1, item );
        this->fullSize += size;
        this->targets.append(qMakePair(File, size));
        qInfo(logMainWindow) << QObject::tr( "Added to the list a new file: %1" ).arg( filePaths.at(i) );
    }

    this->headview->resizeSections(QHeaderView::ResizeToContents);
    this->headview->setSectionResizeMode(1, QHeaderView::Fixed);
    this->updateStatusBar();

    ui->execButton->setEnabled(!(ui->targetsList->rowCount() == 0));
    ui->actionEncryption->setEnabled(!(ui->targetsList->rowCount() == 0));
}

/**
 * @brief The function adds the selected file directory to the list of items.
 */
void MainWindow::addDirs( void )
{
    QString dir = ( QDir( this->lastUsedDir ).exists() ) ?
                this->lastUsedDir :
                QStandardPaths::writableLocation(QStandardPaths::HomeLocation);
    QFileDialog *dlg = new QFileDialog( this );
    QString dirPath;
    dirPath = dlg->getExistingDirectory( this,
                                         QObject::tr( "Crypto: Select a Directory" ),
                                         dir );

    if( dirPath.isEmpty() )
    {
        return;
    }

    // Get upper directory
    QDir upperDir( dirPath );
    if ( upperDir.cdUp() )
    {
        this->lastUsedDir = upperDir.path();
    }

    ui->targetsList->setRowCount( ui->targetsList->rowCount() + 1);

    QTableWidgetItem *item = new QTableWidgetItem( dirPath );
    item->setFlags(Qt::ItemIsSelectable|Qt::ItemIsEnabled);
    item->setIcon( QIcon(":/images/insert-directory.png") );
    item->setToolTip( dirPath );
    ui->targetsList->setItem( ui->targetsList->rowCount() - 1, 0, item);

    qint64 size = getSize(dirPath, Dir);

    item = new QTableWidgetItem( this->getTextSize( size ));
    item->setFlags(Qt::ItemIsSelectable|Qt::ItemIsEnabled);
    ui->targetsList->setItem( ui->targetsList->rowCount() - 1, 1, item);
    this->fullSize += size;
    this->targets.append(qMakePair(Dir, size));

    this->headview->resizeSections(QHeaderView::ResizeToContents);
    this->headview->setSectionResizeMode(1, QHeaderView::Fixed);

    this->updateStatusBar();

    ui->execButton->setEnabled(!(ui->targetsList->rowCount() == 0));
    ui->actionEncryption->setEnabled(!(ui->targetsList->rowCount() == 0));
    qInfo(logMainWindow) << QObject::tr( "Added a new directory to the list: %1" ).arg( dirPath );
}

/**
 * @brief The function encrypts / decrypts data.
 * @param f of the type QString&, path to the file.
 * @return status of the coding/encoding process.
 */
MainWindow::ProcessStatus MainWindow::fileProcessing( const QString &f )
{
    QFile file(f);
    if ( !file.open( QIODevice::ReadOnly ) )
    {
        int ret = QMessageBox::critical( this,
                                         QObject::tr( "Critical" ),
                                         QObject::tr( "Cannot open file %1\n"
                                                      "Do you want to continue execution for next data?").arg( file.fileName() ),
                                         QMessageBox::Abort | QMessageBox::Ok );
        qCritical(logMainWindow) << QObject::tr( "Cannot open file: %1" ).arg( file.fileName() );
        if ( ret == QMessageBox::Abort )
        {
            return PROCESS_STATUS_BREAK;
        }
        return PROCESS_STATUS_CONTINUE;
    }

    //! \todo Make an extension for encrypted files! ( ".enc" )
    QString extension( ".enc" );
    if ( ui->overwriteData->isChecked() )
    {
        qsrand( QDateTime::currentDateTime().toTime_t() );
        extension.clear();
        extension = ".tmp" + QString::number(qrand() % 65535);
    }
    Q_ASSERT_X( encryptFile != nullptr, Q_FUNC_INFO, "Null pointer" );
    encryptFile->setFileName( f + extension );
    if ( !encryptFile->open( QIODevice::WriteOnly | QIODevice::Truncate ) )
    {
        int ret = QMessageBox::critical( this,
                                         QObject::tr("Critical"),
                                         QObject::tr("Unable to write encrypted file %1\n"
                                                     "Do you want to continue execution for next data?" ).arg( encryptFile->fileName() ),
                                         QMessageBox::Abort | QMessageBox::Ok );
        qCritical(logMainWindow) << QObject::tr( "Unable to write encrypted file: %1" ).arg( encryptFile->fileName() );
        file.close();
        if ( ret == QMessageBox::Abort )
        {
            return PROCESS_STATUS_BREAK;
        }
        return PROCESS_STATUS_CONTINUE;
    }

    ui->progressFileBar->reset();
    ui->progressFileBar->setRange( 1, file.size() );

    const qint64 bufferSize = static_cast<qint64>(ui->bufferSize->value()) * COEFF;
    qint64 ret, sum = 0LL;
    do {
        try
        {
            ret = encryptFile->write(file.read(bufferSize));
        }
        catch ( std::bad_alloc &ba )
        {
            qCritical(logMainWindow) << QObject::tr( "Bad allocation memory, execution terminating: %1" ).arg( ba.what() );
            QMessageBox::critical( this, QObject::tr("Error"), QObject::tr( "Bad allocation memory, execution terminating: %1\n"
                                                                            "Advice: try to reduce the size of the buffer!" ).arg( ba.what() ));
            ret = -1;
        }
        if ( processError || ret < 0 )
        {
            file.close();
            encryptFile->close();
            encryptFile->remove();
            ui->progressFileBar->reset();
            return PROCESS_STATUS_BREAK;
        }
        sum += ret;
        ui->progressFileBar->setValue(sum);
        qApp->processEvents( QEventLoop::ExcludeUserInputEvents );

    } while ( sum < file.size() );

    file.close();
    encryptFile->close();
    if ( ui->overwriteData->isChecked() )
    {
        file.remove();
        encryptFile->rename( f );
    }

    qInfo(logMainWindow) << QObject::tr( "Encryption was successfully complete file: %1" ).arg( file.fileName() );
    return PROCESS_STATUS_SUCCESS;
}

/**
 * @brief The helper performs the data encryption / decryption.
 *
 * @note In the body of this function, a password is getting for encryption and an additional salt to the password is set.
 *
 * @warning Password salt is taken from the release time of the program, taken in microseconds.
 *  Therefore, different editions of the program will not be fully compatible with each other!
 *  Encoded data from one release will not be decrypted by another release of the program,
 *  even if the password is known.
 */
void MainWindow::execute( void )
{
    if ( ui->passLine->text().isEmpty() )
    {
        QMessageBox::critical( this, QObject::tr("Error"), QObject::tr("Password not entered!") );
        return;
    }
    if ( ui->passConfirmLine->text().isEmpty() )
    {
        QMessageBox::critical( this, QObject::tr("Error"), QObject::tr("No password confirmation entered!") );
        return;
    }
    if ( ui->passLine->text().compare( ui->passConfirmLine->text(), Qt::CaseSensitive ) != 0 )
    {
        QMessageBox::critical( this, QObject::tr("Error"), QObject::tr("Passwords do not match!") );
        return;
    }
    if ( ui->lockEncrypt->isChecked() )
    {
        QMessageBox::information( this, QObject::tr("Info"), QObject::tr("The encryption process is locked, the list may already contain encrypted data!\n"
                                                                         "Remove the hook from Lock encrypt or clear the list.") );
        return;
    }
    ui->lockEncrypt->setChecked( true );

    QList<QStringList> fileLists;

    for (int i = 0; i < ui->targetsList->rowCount(); i++)
    {
        if ( this->targets.at(i).first == File )
        {
            fileLists.append( QStringList( ui->targetsList->item(i, 0)->text()) );
        }
        else if ( this->targets.at(i).first == Dir )
        {
            if ( !ui->recurseDirs->isChecked() )
            {
                QStringList fDirList = QDir( ui->targetsList->item(i, 0)->text()).entryList(QDir::Files | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);
                fileLists.append(fDirList);
            }
            else
            {
                fileLists.append( getDirFiles( ui->targetsList->item(i, 0)->text() ));
            }
        }
    }

    ui->progressFullBar->reset();
    ui->progressFullBar->setRange(0, ( (this->fullSize > INT_MAX) ? this->fullSize/ONEKB : this->fullSize) );
    ui->progressFullBar->setValue(0);

    ProcessStatus errorFlag = PROCESS_STATUS_SUCCESS;
    this->processError = false;
    CryptFileDevice encryptedFile;
    this->encryptFile = &encryptedFile;
    encryptedFile.setPassword( ui->passLine->text().toLatin1() );
    //! \todo Password salt is taken from the release time of the program, taken in microseconds.
    encryptedFile.setSalt( __TIME__ );
    encryptedFile.setEncryptionMethod( (ui->aesCrypt->isChecked() ? CryptFileDevice::AesCipher : CryptFileDevice::XorCipher ) );
    QObject::connect(&encryptedFile, SIGNAL(errorMessage(QVariant)),
                     this, SLOT(wErrorMessage(QVariant)));
    QTime timer;
    timer.start();

    int counterTargets = 0;
    foreach( const QStringList &flist, fileLists )
    {
        if ( errorFlag == PROCESS_STATUS_BREAK )
        {
            break;
        }
        ProcessStatus retVal = PROCESS_STATUS_SUCCESS;
        foreach( const QString &f, flist )
        {
            retVal = fileProcessing( f );
            if ( retVal == PROCESS_STATUS_SUCCESS )
            {

            }
            else if ( retVal == PROCESS_STATUS_CONTINUE )
            {
                errorFlag = retVal;
                continue;
            }
            else if ( retVal == PROCESS_STATUS_BREAK )
            {
                errorFlag = retVal;
                break;
            }
            else if ( retVal == PROCESS_STATUS_STATE_ERROR )
            {
                ui->progressFullBar->reset();
                return;
            }
            const qint64 size = QFileInfo( f ).size();
            ui->progressFullBar->setValue( ui->progressFullBar->value() + ( (this->fullSize > INT_MAX) ? (int)((double)size/ONEKB+0.5) : size ) );
            qApp->processEvents( QEventLoop::ExcludeUserInputEvents );
        }

        Q_ASSERT_X( counterTargets <= ui->targetsList->rowCount(), Q_FUNC_INFO, "Index out of range");
        if ( retVal == PROCESS_STATUS_SUCCESS )
        {
            ui->targetsList->item(counterTargets, 0)->setIcon( QIcon(":/images/check.png") );
            ui->targetsList->item(counterTargets, 0)->setTextColor( QColor( "green" ) );
        }
        else
        {
            ui->targetsList->item(counterTargets, 0)->setIcon( QIcon(":/images/error.png") );
            ui->targetsList->item(counterTargets, 0)->setTextColor( QColor( "red" ) );
        }
        qApp->processEvents( QEventLoop::ExcludeUserInputEvents );
        counterTargets++;
    }

    int time = timer.elapsed();
    if ( errorFlag == PROCESS_STATUS_SUCCESS )
    {
        QMessageBox::information( this,
                                  QObject::tr("Info" ),
                                  QObject::tr("Data encryption was successfully completed\n"
                                              "Process duration: %1 ( mm:ss.ms )\n"
                                              "Performance: %2 Mb/s").arg(QTime::fromMSecsSinceStartOfDay(time).toString("mm:ss.zzz")).arg((static_cast<double>(this->fullSize)/time)*1000/COEFF));
    }
    else if( errorFlag == PROCESS_STATUS_CONTINUE )
    {
        QMessageBox::warning( this,
                              QObject::tr("Warning" ),
                              QObject::tr("The process is completed with some errors!\n"
                                          "Process duration: %1 ( mm:ss.ms )").arg(QTime::fromMSecsSinceStartOfDay(time).toString("mm:ss.zzz")));
    }

    ui->progressFileBar->reset();
    ui->progressFullBar->reset();
}

/**
 * @brief The function of editing an item from the list.
 */
void MainWindow::editItem( void )
{
    if ( ui->targetsList->currentRow() < 0 )
    {
        return;
    }
    // Get upper directory
    QDir upperDir( ui->targetsList->item( ui->targetsList->currentRow(), 0 )->text() );
    if ( !upperDir.cdUp() )
    {
        return;
    }

    if ( this->targets.at( ui->targetsList->currentRow() ).first == File )
    {
        QFileDialog *dlg = new QFileDialog( this );
        QString filePath;
        filePath = dlg->getOpenFileName(this, QObject::tr("Crypto: Select the file(s)"), upperDir.path(), QObject::tr("all data (*.*)"));

        if ( filePath.isEmpty() )
        {
            return;
        }

        // Get upper directory
        QDir upperDir( filePath );
        if ( upperDir.cdUp() )
        {
            this->lastUsedPath = upperDir.path();
        }

        this->fullSize -= this->targets.at( ui->targetsList->currentRow() ).second;
        ui->targetsList->item(ui->targetsList->currentRow(), 0)->setText( filePath );
        ui->targetsList->item(ui->targetsList->currentRow(), 0)->setTextColor( QColor("black") );

        qint64 size = getSize( filePath, File );
        ui->targetsList->item(ui->targetsList->currentRow(), 1)->setText( this->getTextSize(size) );

        this->targets[ui->targetsList->currentRow()].second = size;
        this->fullSize += size;

        this->headview->resizeSections( QHeaderView::ResizeToContents );
        this->headview->setSectionResizeMode(1, QHeaderView::Fixed);
        qInfo(logMainWindow) << QObject::tr( "Edit a path to the file: 51" ).arg( filePath );
    }
    else
    {
        QFileDialog *dlg = new QFileDialog( this );
        QString dirPath;
        dirPath = dlg->getExistingDirectory( this, QObject::tr("Crypto: Select a Directory"), upperDir.path() );

        if ( dirPath.isEmpty() )
        {
            return;
        }

        // Get upper directory
        QDir upperDir( dirPath );
        if ( upperDir.cdUp() )
        {
            this->lastUsedDir = upperDir.path();
        }

        this->fullSize -= this->targets.at( ui->targetsList->currentRow() ).second;
        ui->targetsList->item(ui->targetsList->currentRow(), 0)->setText( dirPath );
        ui->targetsList->item(ui->targetsList->currentRow(), 0)->setTextColor( QColor("black") );

        qint64 size = this->getSize( dirPath, Dir );
        ui->targetsList->item(ui->targetsList->currentRow(), 1)->setText( this->getTextSize(size) );

        this->targets[ui->targetsList->currentRow()].second = size;
        this->fullSize += size;

        this->headview->resizeSections( QHeaderView::ResizeToContents );
        this->headview->setSectionResizeMode(1, QHeaderView::Fixed);
        qInfo(logMainWindow) << QObject::tr( "Edit a path to the dir: %1" ).arg( dirPath );
    }

    this->updateStatusBar();
}

/**
 * @brief The function removes an item from the list.
 */
void MainWindow::deleteItem( void )
{
    if ( ui->targetsList->currentRow() < 0 )
    {
        return;
    }

    this->fullSize -= this->targets.at( ui->targetsList->currentRow() ).second;
    this->targets.removeAt( ui->targetsList->currentRow() );
    ui->targetsList->removeRow( ui->targetsList->currentRow() );
    ui->targetsList->setCurrentCell( -1, 0 );

    this->updateStatusBar();

    ui->execButton->setEnabled( !(ui->targetsList->rowCount() == 0) );
    ui->actionEncryption->setEnabled( !(ui->targetsList->rowCount() == 0) );
    qInfo(logMainWindow) << QObject::tr( "Delete a item from the list" );
}

/**
 * @brief Information about the program.
 *
 * - Brief description of features.
 * - The date and release number of the program.
 * - Licensing restrictions and distribution of the program.
 * - Links to third-party libraries.
 */
void MainWindow::about( void )
{
    QMessageBox::about(this,
                       QObject::tr("About program"),
                       QObject::tr("<h2>Crypto</h2><br />"
                                   "<b>Advanced File Encryptor</b>, based on simple XOR and reliable AES methods.<br />"
                                   "The Advanced Encryption Standard (AES) is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST).<br />"
                                   "Certification AES by: CRYPTREC, NESSIE, NSA.<br /><b>Version</b> %1<br /><b>Copyright</b> © 2018 sergej1@email.ua<br /><br />"
                                   "The program is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.<br /><br />"
                                   "This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (<a href=\"http://www.openssl.org/\">http://www.openssl.org/</a>)").arg(qApp->applicationVersion()));
}

/**
 * @brief Slot to exit the program.
 */
void MainWindow::on_actionQuit_triggered( void )
{
    MainWindow::close();
}

/**
 * @brief Slot for adding the new files to the list.
 */
void MainWindow::on_actionAdd_file_s_triggered( void )
{
    this->addFiles();
}

/**
 * @brief Slot for adding a new directory to the list.
 */
void MainWindow::on_actionAdd_Directory_triggered( void )
{
    this->addDirs();
}

/**
 * @brief Slot for data encryption procedure.
 */
void MainWindow::on_actionEncryption_triggered( void )
{
    this->execute();
}

/**
 * @brief A slot for issuing information about the Qt-Framework used.
 */
void MainWindow::on_actionAbout_Qt_triggered( void )
{
    qApp->aboutQt();
}

/**
 * @brief Slot for displaying information about the program.
 */
void MainWindow::on_actionAbout_crypto_triggered( void )
{
    this->about();
}

/**
 * @brief Slot for calling the user interface of the system settings.
 */
void MainWindow::on_actionSettings_triggered( void )
{
    this->settings->fillSettingsUi();
    this->settings->show();
}

/**
 * @brief Slot for adding a new file to the list.
 */
void MainWindow::on_addFile_clicked( void )
{
    this->addFiles();
}

/**
 * @brief Slot for adding a new directory to the list.
 */
void MainWindow::on_addDir_clicked( void )
{
    this->addDirs();
}

/**
 * @brief Slot for data encryption procedure.
 */
void MainWindow::on_execButton_clicked( void )
{
    this->execute();
}

/**
 * @brief Slot for editing an item from the list.
 */
void MainWindow::on_editEntry_clicked( void )
{
    this->editItem();
}

/**
 * @brief Slot to remove an item from the list.
 */
void MainWindow::on_deleteEntry_clicked( void )
{
    this->deleteItem();
}

/**
 * @brief Slot for calling assistance to the user of the program.
 */
void MainWindow::on_actionContents_triggered( void )
{
    //! \todo Add help for the program!
    qApp->aboutQt();
}

/**
 * @brief Slot for changing the current cell from the list.
 */
void MainWindow::on_targetsList_currentCellChanged(int, int, int, int )
{
    ui->editEntry->setEnabled( !( ui->targetsList->currentRow() < 0) );
    ui->deleteEntry->setEnabled( !( ui->targetsList->currentRow() < 0) );
    editItemAction->setEnabled( !( ui->targetsList->currentRow() < 0) );
    deleteItemAction->setEnabled( !( ui->targetsList->currentRow() < 0) );
}

/**
 * @brief Slot for changing the password entry format.
 *
 * Slot switch to hidden mode for the Password.
 *
 * @param checked of type bool
 */
void MainWindow::on_hidPassMode_clicked( bool checked )
{
    if( checked )
    {
        ui->passLine->setEchoMode( QLineEdit::Password );
        ui->passConfirmLine->setEchoMode( QLineEdit::Password );
    }
    else
    {
        ui->passLine->setEchoMode( QLineEdit::Normal );
        ui->passConfirmLine->setEchoMode( QLineEdit::Normal );
    }
}

/**
 * @brief Slot for compare between passwordLine and confirmLine.
 *
 * @param arg of type QString&
 */
void MainWindow::on_passConfirmLine_textChanged( const QString &arg )
{
    if( ui->passLine->text().compare( arg, Qt::CaseSensitive ) == 0 )
    {
        ui->passLine->setStyleSheet("QLineEdit{lineedit-password-character: 9679; color: green;}");
        ui->passConfirmLine->setStyleSheet("QLineEdit{lineedit-password-character: 9679; color: green;}");
    }
    else
    {
        ui->passLine->setStyleSheet("QLineEdit{lineedit-password-character: 9679; color: black;}");
        ui->passConfirmLine->setStyleSheet("QLineEdit{lineedit-password-character: 9679; color: red;}");
    }
}

/**
 * @brief Slot for compare between passwordLine and confirmLine.
 *
 * @param arg of type QString&
 */
void MainWindow::on_passLine_textChanged( const QString &arg )
{
    if( ui->passConfirmLine->text().compare( arg, Qt::CaseSensitive ) == 0 )
    {
        ui->passLine->setStyleSheet("QLineEdit{lineedit-password-character: 9679; color: green;}");
        ui->passConfirmLine->setStyleSheet("QLineEdit{lineedit-password-character: 9679; color: green;}");
    }
    else
    {
        ui->passLine->setStyleSheet("QLineEdit{lineedit-password-character: 9679; color: black;}");
        ui->passConfirmLine->setStyleSheet("QLineEdit{lineedit-password-character: 9679; color: red;}");
    }
}

/**
 * @brief Slot to clear the entire list in one click.
 */
void MainWindow::on_clearList_clicked( void )
{
    this->clearList();
    this->fullSize = 0LL;
    this->targets.clear();

    this->updateStatusBar();

    ui->execButton->setEnabled( !(ui->targetsList->rowCount() == 0) );
    ui->actionEncryption->setEnabled( !(ui->targetsList->rowCount() == 0) );
    ui->lockEncrypt->setChecked( false );
    qInfo(logMainWindow) << QObject::tr( "Clear list" );
}

/**
 * @brief The function to clear the file list.
 *
 * @warning The function uses a recursive call!
 */
void MainWindow::clearList( void ) const
{
    if ( ui->targetsList->rowCount() <= 0 )
    {
        return;
    }
    ui->targetsList->removeRow( ui->targetsList->rowCount()-1 );
    clearList();
}

/**
 * @brief Slot for calculate the size of the data in the directory.
 *
 * Process all subdirectories recursively.
 */
void MainWindow::on_recurseDirs_clicked( void )
{
    if ( ui->targetsList->rowCount() <= 0 )
    {
        return;
    }
    for ( int i = 0; i < ui->targetsList->rowCount(); i++ )
    {
        if ( this->targets.at( i ).first == Dir )
        {
            qint64 newSize = getSize( ui->targetsList->item(i, 0)->text(), Dir );
            if ( this->targets.at( i ).second != newSize )
            {
                ui->targetsList->item(i, 1)->setText( this->getTextSize(newSize) );
                this->fullSize -= this->targets.at( i ).second;
                this->fullSize += this->targets[i].second = newSize;
            }
        }
    }

    this->headview->resizeSections( QHeaderView::ResizeToContents );
    this->headview->setSectionResizeMode(1, QHeaderView::Fixed);
    this->updateStatusBar();
}

/**
 * @brief Slot for the font selection dialog.
 *
 * Selection of the screen font.
 *
 * @warning The font is installed immediately for the entire program, i.e. for all graphic forms!
 */
void MainWindow::on_actionFont_triggered( void )
{
    bool selected;
    QFont font = QFontDialog::getFont( &selected, qApp->font(), this );

    if ( selected )
    {
//        this->setFont( font );
        qApp->setFont( font );
    }
}
