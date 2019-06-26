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
* @mainpage Data encryption program Crypto.
*
* Crypto - Advanced File Encryptor, based on simple XOR and reliable AES methods
*
* @author SergejBre sergej1@email.ua
*/

/**
 * @file main.cpp
 *
 * @brief The file contains two important functions, main and logMessageOutput.
 *
 *  The main function executes an instance of a GUI Qt application,
 *  sets it up with the specified special parameters, and installs
 *  a Qt message handler defined in the logMessageOutput function.
 *  In addition, a log journal of the application messages is set up.
 */

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------
#include "mainwindow.h"
#include "settings.h"
#include <QApplication>
#include <QLoggingCategory>
#include <QDateTime>
#include <QFile>

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------
#define ONEKB 1024
Q_LOGGING_CATEGORY(logMain, "main")

// Smart pointer an the log-file
static QScopedPointer<QFile> m_logFile;

//------------------------------------------------------------------------------
// Function Prototypes
//------------------------------------------------------------------------------
void logMessageOutput( const QtMsgType type, const QMessageLogContext &context, const QString &msg );

/**
 * @brief main function
 *
 * In this function, an instance of a GUI Qt application app is executed and
 * set up with the parameters entered.
 *
 * @param argc this parameter is ignored because it is a GUI application.
 * @param argv this parameter is ignored because it is a GUI application.
 *
 * @return value of the function QApplication::exec()
 * Enters the main event loop and waits until exit() is called.
 * Returns the value that was set to exit() (which is 0 if exit() is called
 * via quit()).
 *
 * @note
 * The program parameters (argc, argv) are ignored.
 * @warning
 * none
 */
int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    app.setOrganizationName( "FreeProject" );
    app.setOrganizationDomain( "free.project.org" );
    app.setApplicationName( "Crypto" );
    app.setApplicationDisplayName( "Crypto - Advanced File Encryptor." );
    app.setApplicationVersion( "1.0.1.0, built on: " + QString(__DATE__).simplified() );

    MainWindow w;
    w.show();

    bool errorFlag = false;
    if( w.getSettings()->enableLog )
    {
        // Set the log file in the work directory
        m_logFile.reset( new QFile( w.getSettings()->pathToLog ) );

        if ( m_logFile.data()->size() < w.getSettings()->maxSizeLog * ONEKB )
        {
            errorFlag = m_logFile.data()->open( QIODevice::Append | QIODevice::Text );
        }
        else
        {
            errorFlag = m_logFile.data()->open( QIODevice::WriteOnly | QIODevice::Text );
        }

        if ( errorFlag )
        {
            qInstallMessageHandler( logMessageOutput );
        }
        else
        {
            qInstallMessageHandler( 0 );
            qCritical( logMain ) << QObject::tr( "To the log file %1 can not be added." ).arg( m_logFile.data()->fileName() );
            w.wErrorMessage( QObject::tr( "To the log file %1 can not be added." ).arg( m_logFile.data()->fileName() ) );
            m_logFile.reset();
        }
    }

    qInfo( logMain ) << QObject::tr( "App Crypto is running, ver%1" ).arg( app.applicationVersion() );

    return app.exec();
}

/**
 * @brief The function logMessageOutput is a message handler.
 *
 * This function redirects the messages by their category (QtDebugMsg,
 * QtInfoMsg, QtWarningMsg, QtCriticalMsg, QtFatalMsg) to the log file (m_logFile).
 * The message handler is a function that prints out debug messages,
 * warnings, critical and fatal error messages. The Qt library (debug mode)
 * contains hundreds of warning messages that are printed when internal errors
 * (usually invalid function arguments) occur. Qt built in release mode
 * also contains such warnings unless QT_NO_WARNING_OUTPUT and/
 * or QT_NO_DEBUG_OUTPUT have been set during compilation.
 * If you implement your own message handler, you get total control of these messages.
 *
 * @param[in] type of the type QtMsgType
 * @param[in] context of type QMessageLogContext
 * @param[in] msg of the type QString
 *
 * @note
 * - The output of messages is also output to the terminal console. This is for debugging purposes.
 * - Additional information, such as a line of code, the name of the source file, function names
 * cannot be displayed for the release of the program.
 *
 * @warning
 * - The default message handler prints the message to the standard output
 * under X11 or to the debugger under Windows. If it is a fatal message,
 * the application aborts immediately.
 * - Only one message handler can be defined, since this is usually done on
 * an application-wide basis to control debug output.
 */
void logMessageOutput( const QtMsgType type, const QMessageLogContext &context, const QString &msg )
{
    QTextStream out( m_logFile.data() );
    // Write the date of the recording
    out << QDateTime::currentDateTime().toString( "yyyy-MM-dd hh:mm:ss.zzz " );

    QByteArray localMsg = msg.toLocal8Bit();
    switch ( type )
    {
    case QtDebugMsg:
        out << "DBG ";
        break;
    case QtInfoMsg:
        out << "INF ";
        break;
    case QtWarningMsg:
        out << "WRN ";
        break;
    case QtCriticalMsg:
        out << "CRT ";
        break;
    case QtFatalMsg:
        out << "FTL ";
        break;
    default :
        out << "ERR ";
    }
#ifdef DEBUG_OUTPUT
    out << context.category << ": " << msg << " (" << context.file << ":" << context.line << ", " << context.function << ")" << "<br />" << endl;
#else // only for release
    out << context.category << ": " << msg << "<br />" << endl;
#endif
    out.flush();
    // Output messages to the terminal console. Only for debugging purposes.
    fprintf( stdout, "%s\n", localMsg.constData() );
}
