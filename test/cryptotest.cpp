#include <QString>
#include <QtTest>
#include "../../CryptFileDevice/src/cryptfiledevice.h"
#include <QFile>
#include <QDebug>
#include <QDateTime>
#include <QDataStream>

class CryptoTest : public QObject
{
    Q_OBJECT

public:
    CryptoTest();

private Q_SLOTS:
    void testCase01();
    void testCase02();
    void testCase03();
    void testCase04();
    void testCase05();
    void testCase06();
    void testCase07();
    void testCase08();
    void testCase09();
    void testCase10();
    void testCase11();
    void testCase12();
    void testCase13();
    void testCase14();
    void testCase15();
    void testCase16();
    void testCase17();
    void testCase18();
};

static QTime timer;
// Create files for the tests
static QFile plainFile( QDir::currentPath() + "/testfile.plain" );
static QFile encryptedFile( QDir::currentPath() + "/testfile.encrypted" );
static CryptFileDevice cryptFileDevice( &encryptedFile,
                                        "01234567890123456789012345678901",
                                        "0123456789012345" );

CryptoTest::CryptoTest()
{
    uint seed = QDateTime::currentDateTimeUtc().toTime_t();
    qDebug() << "Seed:" << seed;
    qsrand( seed );
    timer.restart();
}

static QByteArray generateRandomData( const int size );
static bool openDevicePair(QIODevice &device1, QIODevice &device2, QIODevice::OpenMode mode );
static bool compare( const QString &pathToEnc, const QString &pathToPlain );
static QByteArray calculateXor( const QByteArray &data, const QByteArray &key );

/**
 * @brief CryptoTest::testCase01
 *
 * Preparation of the test data: testfile.plain and testfile.encrypted.
 */
void CryptoTest::testCase01()
{
    bool ok = true;

    // Creating (rewriting files)
    qDebug() << "Creating test files";
    ok = openDevicePair( plainFile, cryptFileDevice, QIODevice::WriteOnly | QIODevice::Truncate );
    QVERIFY2( ok, "Creating test files failed" );
    if ( ok == false )
    {
        return;
    }

    qDebug() << "Writing random content";
    for (int i = 0; i < 200; i++)
    {
        QByteArray data = generateRandomData( qrand() % 256 ).toBase64() + "\r\n";
        plainFile.write( data );
        cryptFileDevice.write( data );
    }
    plainFile.close();
    cryptFileDevice.close();
    QVERIFY2( true, "Failure" );
}

/**
 * @brief CryptoTest::testCase02
 */
void CryptoTest::testCase02()
{
    bool ok = true;

    qDebug() << "Comparing files's size (sould be the same)";
    ok = openDevicePair( plainFile, cryptFileDevice, QIODevice::ReadOnly );
    QVERIFY2( ok, "Open test files failed" );
    if ( !ok )
        return;

    ok = ( cryptFileDevice.size() == plainFile.size() );

    QVERIFY2( ok, "Size is different" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Size is different" );
}

/**
 * @brief CryptoTest::testCase03
 */
void CryptoTest::testCase03()
{
    bool ok = true;

    qDebug() << "Comparing content (should be the same)";
    ok = compare( encryptedFile.fileName(), plainFile.fileName() );
    QVERIFY2( ok, "Content is different" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Content is different");
}

/**
 * @brief CryptoTest::testCase04
 */
void CryptoTest::testCase04()
{
    bool ok = true;

    qDebug() << "Reading from random position";
    if (!openDevicePair( plainFile, cryptFileDevice, QIODevice::ReadOnly ) )
        return;
    ok = true;
    for (int i = 0; i < 200; i++)
    {
        qint64 pos = qrand() % plainFile.size(); // size is the same
        qint64 maxlen = qrand() % 256;

        cryptFileDevice.seek(pos);
        Q_ASSERT(cryptFileDevice.pos() == pos);
        plainFile.seek(pos);
        Q_ASSERT(plainFile.pos() == pos);

        QByteArray data1 = plainFile.read(maxlen);
        QByteArray data2 = cryptFileDevice.read(maxlen);

        if (data1 != data2)
        {
            ok = false;
            break;
        }
    }
    QVERIFY2( ok, "Random read content is different" );
    Q_ASSERT_X(ok, Q_FUNC_INFO, "Random read content is different");
}

/**
 * @brief CryptoTest::testCase05
 */
void CryptoTest::testCase05()
{
    bool ok = true;

    qDebug() << "Reading line by line";
    if ( !openDevicePair( plainFile, cryptFileDevice, QIODevice::ReadOnly ) )
        return;

    Q_ASSERT( plainFile.pos() == 0 );
    Q_ASSERT( cryptFileDevice.pos() == 0 );

    ok = true;
    QByteArray seed = generateRandomData( 300 );
    QByteArray chk1 = seed, chk2 = seed;

    while (!plainFile.atEnd())
    {
        QByteArray line = plainFile.readLine();
        if ( line.isEmpty() )
            break;
        chk1 = calculateXor( chk1, line );
    }

    while ( !cryptFileDevice.atEnd() )
    {
        QByteArray line = cryptFileDevice.readLine();
        if ( line.isEmpty() )
            break;
        chk2 = calculateXor( chk2, line );
    }

    ok = ( chk1 == chk2 );
    QVERIFY2( ok, "Reading lines is failed" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Reading lines is failed" );
}

/**
 * @brief CryptoTest::testCase06
 */
void CryptoTest::testCase06()
{
    bool ok = true;

    qDebug() << "Appending data";
    if ( !openDevicePair( plainFile, cryptFileDevice, QIODevice::Append ) )
        return;

    for ( int i = 0; i < 200; i++ )
    {
        QByteArray data = generateRandomData( qrand() % 256 ).toBase64() + "\r\n";
        qint64 plainBytesWritten = plainFile.write( data );
        Q_ASSERT( plainBytesWritten == data.size() );
        qint64 cryptBytesWritten = cryptFileDevice.write( data );
        Q_ASSERT( cryptBytesWritten == data.size() );
    }
    plainFile.close();
    cryptFileDevice.close();

    ok = compare( encryptedFile.fileName(), plainFile.fileName() );

    QVERIFY2( ok, "Content is different" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Content is different" );
}

/**
 * @brief CryptoTest::testCase07
 */
void CryptoTest::testCase07()
{
    bool ok = true;

    qDebug() << "Rewriting file (truncate)";
    if ( !openDevicePair( plainFile, cryptFileDevice, QIODevice::WriteOnly | QIODevice::Truncate ) )
        return;
    for ( int i = 0; i < 200; i++ )
    {
        QByteArray data = generateRandomData( qrand() % 256).toBase64() + "\r\n";
        plainFile.write(data);
        cryptFileDevice.write(data);
    }
    plainFile.close();
    cryptFileDevice.close();
    ok = compare( encryptedFile.fileName(), plainFile.fileName() );

    QVERIFY2( ok, "Content is different" );
    Q_ASSERT_X(ok, Q_FUNC_INFO, "Content is different");

}

/**
 * @brief CryptoTest::testCase08
 */
void CryptoTest::testCase08()
{
    bool ok = true;

    qDebug() << "Flushing";
    qDebug() << "Rewriting file (truncate)";
    if (!openDevicePair( plainFile, cryptFileDevice, QIODevice::WriteOnly | QIODevice::Truncate ) )
        return;

    for (int i = 0; i < 200; i++)
    {
        QByteArray data = generateRandomData( qrand() % 256 ).toBase64() + "\r\n";
        plainFile.write( data );
        plainFile.flush();
        cryptFileDevice.write( data );
        cryptFileDevice.flush();
    }

    plainFile.close();
    cryptFileDevice.close();
    ok = compare(encryptedFile.fileName(), plainFile.fileName());

    QVERIFY2( ok, "Content is different" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Content is different" );
}

/**
 * @brief CryptoTest::testCase09
 */
void CryptoTest::testCase09()
{
    bool ok = true;

    qDebug() << "Sizing Flushing";
    qDebug() << "Rewriting file (truncate)";
    if ( !openDevicePair( plainFile, cryptFileDevice, QIODevice::WriteOnly | QIODevice::Truncate ) )
        return;

    for ( int i = 0; i < 200; i++ )
    {
        QByteArray data = generateRandomData( qrand() % 256 ).toBase64() + "\r\n";
        plainFile.write( data );
        qint64 plainSize = plainFile.size();
        cryptFileDevice.write( data );
        qint64 cryptSize = cryptFileDevice.size();
        Q_ASSERT( plainSize == cryptSize );
    }

    plainFile.close();
    cryptFileDevice.close();
    ok = compare( encryptedFile.fileName(), plainFile.fileName() );

    QVERIFY2( ok, "Content is different" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Content is different" );
}

/**
 * @brief CryptoTest::testCase10
 */
void CryptoTest::testCase10()
{
    bool ok = false;

    qDebug() << "Rewriting random data in file";
    if ( !openDevicePair( plainFile, cryptFileDevice, QIODevice::WriteOnly | QIODevice::Truncate ) )
        return;
    for ( int i = 0; i < 200; i++ )
    {
        QByteArray data = generateRandomData( qrand() % 256).toBase64() + "\r\n";
        plainFile.write( data );
        cryptFileDevice.write( data );
    }
    plainFile.close();
    cryptFileDevice.close();
    if ( compare( encryptedFile.fileName(), plainFile.fileName() ) )
    {
        if ( !openDevicePair( plainFile, cryptFileDevice, QIODevice::ReadWrite ) )
            return;

        for ( int i = 0; i < 200; i++ )
        {
            qint64 pos = qrand() % plainFile.size(); // size is the same

            cryptFileDevice.seek( pos );
            Q_ASSERT( cryptFileDevice.pos() == pos );
            plainFile.seek( pos );
            Q_ASSERT( plainFile.pos() == pos );

            QByteArray data = generateRandomData( qrand() % 256).toBase64() + "\r\n";
            plainFile.write( data );
            cryptFileDevice.write( data );
        }
    }
    plainFile.close();
    cryptFileDevice.close();
    ok = compare( encryptedFile.fileName(), plainFile.fileName() );

    QVERIFY2( ok, "Content is different" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Content is different" );
}

/**
 * @brief CryptoTest::testCase11
 */
void CryptoTest::testCase11()
{
    bool ok = false;

    qDebug() << "Writing using QDataStream (operator <<)";
    if ( !openDevicePair( plainFile, cryptFileDevice, QIODevice::WriteOnly | QIODevice::Truncate ) )
        return;

    QDataStream plainStream( &plainFile );
    QDataStream cryptStream( &cryptFileDevice );
    for ( int i = 0; i < 200; i++ )
    {
        QByteArray data = generateRandomData( qrand() % 256).toBase64() + "\r\n";

        plainStream << data;
        cryptStream << data;
    }
    plainFile.close();
    cryptFileDevice.close();
    ok = compare( encryptedFile.fileName(), plainFile.fileName() );

    QVERIFY2( ok, "Content is different" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Content is different" );
}

/**
 * @brief CryptoTest::testCase12
 */
void CryptoTest::testCase12()
{
    bool ok = false;

    qDebug() << "Writing using QDataStream (writeRawData)";
    if ( !openDevicePair( plainFile, cryptFileDevice, QIODevice::WriteOnly | QIODevice::Truncate ) )
        return;

    QDataStream plainStream( &plainFile );
    QDataStream cryptStream( &cryptFileDevice );
    for (int i = 0; i < 200; i++)
    {
        QByteArray data = generateRandomData( qrand() % 256 ).toBase64() + "\r\n";

        int plainBytesWritten = plainStream.writeRawData( data.constData(), data.length() );
        int cryptBytesWritten = cryptStream.writeRawData( data.constData(), data.length() );
        Q_ASSERT( plainBytesWritten == cryptBytesWritten );
    }
    plainFile.close();
    cryptFileDevice.close();
    ok = compare( encryptedFile.fileName(), plainFile.fileName() );

    QVERIFY2( ok, "Content is different" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Content is different" );
}

/**
 * @brief CryptoTest::testCase13
 */
void CryptoTest::testCase13()
{
    bool ok = false;

    qDebug() << "Reading using QDataStream (operator >>)";
    if ( !openDevicePair( plainFile, cryptFileDevice, QIODevice::ReadOnly ) )
        return;

    QDataStream plainStream( &plainFile );
    QDataStream cryptStream( &cryptFileDevice );

    QByteArray dataFromPlainFile;
    QByteArray dataFromCryptDevice;
    plainStream >> dataFromPlainFile;
    cryptStream >> dataFromCryptDevice;
    plainFile.close();
    cryptFileDevice.close();
    ok = ( dataFromPlainFile == dataFromCryptDevice );

    QVERIFY2( ok, "Content is different" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Content is different" );
}

/**
 * @brief CryptoTest::testCase14
 */
void CryptoTest::testCase14()
{
    bool ok = true;

    qDebug() << "Reading using QDataStream (readRawData)";
    if ( !openDevicePair( plainFile, cryptFileDevice, QIODevice::ReadOnly ) )
        return;

    QDataStream plainStream( &plainFile );
    QDataStream cryptStream( &cryptFileDevice );

    for ( int i = 0; i < 200; ++i )
    {
        int size = qrand() % 256;
        QByteArray dataFromPlainFile( size, ' ' );
        QByteArray dataFromCryptDevice( size, ' ' );

        int plainBytesRead = plainStream.readRawData( dataFromPlainFile.data(), size );
        int cryptBytesRead = cryptStream.readRawData( dataFromCryptDevice.data(), size );
        Q_ASSERT( plainBytesRead == cryptBytesRead );

        if ( dataFromPlainFile != dataFromCryptDevice )
        {
            ok = false;
            break;
        }
    }
    plainFile.close();
    cryptFileDevice.close();

    QVERIFY2( ok, "Content is different" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Content is different" );
}

/**
 * @brief CryptoTest::testCase15
 */
void CryptoTest::testCase15()
{
    bool ok = true;

    qDebug() << "Reading from random position using QTextStream";
    if ( !openDevicePair( plainFile, cryptFileDevice, QIODevice::ReadOnly ) )
        return;

    QTextStream plainStream( &plainFile );
    QTextStream cryptStream( &cryptFileDevice );

    for (int i = 0; i < 200; ++i)
    {
        int pos = qrand() % plainFile.size();
        int size = qrand() % 256;

        plainStream.seek( pos );
        Q_ASSERT( plainStream.pos() == pos );
        cryptStream.seek( pos );
        Q_ASSERT( cryptStream.pos() == pos );

        QString plainData = plainStream.read( size );
        QString cryptData = cryptStream.read( size );

        if ( plainData != cryptData )
        {
            ok = false;
            break;
        }
    }
    plainFile.close();
    cryptFileDevice.close();

    QVERIFY2( ok, "Content is different" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Content is different" );
}

/**
 * @brief CryptoTest::testCase16
 */
void CryptoTest::testCase16()
{
    bool ok = true;

    qDebug() << "Reading line by line using QTextStream";
    if (!openDevicePair( plainFile, cryptFileDevice, QIODevice::ReadOnly ) )
        return;

    QTextStream plainStream( &plainFile );
    QTextStream cryptStream( &cryptFileDevice );

    QByteArray seed = generateRandomData( 300 );
    QByteArray chk1 = seed, chk2 = seed;

    while ( !plainStream.atEnd() )
    {
        QString line = plainStream.readLine();
        if ( line.isEmpty() )
            break;
        chk1 = calculateXor( chk1, line.toUtf8() );
    }

    while ( !cryptStream.atEnd() )
    {
        QString line = cryptStream.readLine();
        if ( line.isEmpty() )
            break;
        chk2 = calculateXor( chk2, line.toUtf8() );
    }

    plainFile.close();
    cryptFileDevice.close();

    ok = (chk1 == chk2);

    QVERIFY2( ok, "Reading lines is failed" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Reading lines is failed" );
}

/**
 * @brief CryptoTest::testCase17
 */
void CryptoTest::testCase17()
{
    bool ok = false;

    qDebug() << "Open CryptFileDevice with wrong password";
    CryptFileDevice cryptFileDevice( &encryptedFile,
                                     "1234567890123456789012",
                                     "123456789012" );

    if ( !cryptFileDevice.open( QIODevice::ReadOnly ) )
    {
        ok = true;
    }

    QVERIFY2( ok, "Open CryptFileDevice with wrong password is failed" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Open CryptFileDevice with wrong password is failed" );
}

/**
 * @brief CryptoTest::testCase18
 */
void CryptoTest::testCase18()
{
    bool ok = true;

    qDebug() << "Removing";
    ok = cryptFileDevice.remove() && !encryptedFile.exists();

    QVERIFY2( ok, "Cannot remove file" );
    Q_ASSERT_X( ok, Q_FUNC_INFO, "Cannot remove file" );

    qDebug() << "<< << <<";
    qDebug() << "The complete test duration: " << timer.elapsed() << " ms";
    qDebug() << ">> >> >>";
}

// ----------------------------------------------------------------------
/**
 * @brief generateRandomData
 * @param size
 * @return
 */
static QByteArray generateRandomData( const int size )
{
    QByteArray data;
    while ( data.size() < size )
    {
        data += char( qrand() % 256 );
    }

    return data;
}

/**
 * @brief openDevicePair
 * @param device1
 * @param device2
 * @param mode
 * @return
 */
static bool openDevicePair( QIODevice &device1, QIODevice &device2, QIODevice::OpenMode mode )
{
    if ( device1.isOpen() )
    {
        device1.close();
    }
    if ( device2.isOpen() )
    {
        device2.close();
    }

    if ( !device1.open( mode ) )
    {
        Q_ASSERT_X(false, Q_FUNC_INFO, "Cannot create test file1");
        return false;
    }

    if ( !device2.open( mode ) )
    {
        Q_ASSERT_X(false, Q_FUNC_INFO, "Cannot create test file2");
        return false;
    }
    return true;
}

/**
 * @brief compare
 * @param pathToEnc
 * @param pathToPlain
 * @return
 */
static bool compare( const QString &pathToEnc, const QString &pathToPlain )
{
    // Create files
    QFile plainFile( pathToPlain );

    QFile encryptedFile( pathToEnc );
    CryptFileDevice cryptFileDevice( &encryptedFile,
                                     "01234567890123456789012345678901",
                                     "0123456789012345" );

    if ( !plainFile.open( QIODevice::ReadOnly ) )
    {
        return false;
    }

    if ( !cryptFileDevice.open( QIODevice::ReadOnly ) )
    {
        plainFile.close();
        return false;
    }

    QByteArray plainData = plainFile.readAll();
    QByteArray decryptData = cryptFileDevice.readAll();

    bool result = ( plainData == decryptData );

    plainFile.close();
    cryptFileDevice.close();

    return result;
}

/**
 * @brief calculateXor
 * @param data
 * @param key
 * @return
 */
static QByteArray calculateXor( const QByteArray &data, const QByteArray &key )
{
    if ( key.isEmpty() )
        return data;

    QByteArray result;
    for ( int i = 0 , j = 0; i < data.length(); ++i , ++j )
    {
        if ( j == key.length() )
            j = 0; // repeat the key if key.length() < data.length()
        result.append( data.at(i) ^ key.at(j) );
    }
    return result;
}

QTEST_APPLESS_MAIN(CryptoTest)

#include "cryptotest.moc"
