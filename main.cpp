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
 * @brief main
 * @param argc
 * @param argv
 * @return
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
 * @brief logMessageOutput
 * @param[in] type of the type QtMsgType
 * @param[in] context of type QMessageLogContext
 * @param[in] msg of the type QString
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
        out << "??? ";
    }
#ifdef DEBUG_OUTPUT
    out << context.category << ": " << msg << " (" << context.file << ":" << context.line << ", " << context.function << ")" << "<br />" << endl;
#else
    out << context.category << ": " << msg << "<br />" << endl;
#endif
    out.flush();
    // Output messages to the terminal console. Only for debugging purposes.
    fprintf( stdout, "%s\n", localMsg.constData() );
}
