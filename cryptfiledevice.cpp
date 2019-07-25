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
 * @file cryptfiledevice.cpp
 *
 * @brief This file contains the definition of methods and interfaces of the CryptFileDevice class.
 */

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------
#include "cryptfiledevice.h"
#include <openssl/evp.h>
#include <limits>
#include <QtEndian>
#include <QFileDevice>
#include <QFile>
#include <QCryptographicHash>
#include <QLoggingCategory>

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------
/// file header size. in bytes
static int const kHeaderLength = 128;
/// restriction on the length of the salt.
static int const kSaltMaxLength = 8;
Q_LOGGING_CATEGORY(cryptFileDev, "CryptDev")

/**
 * @brief The default constructor of the class CryptFileDevice
 *
 * The constructor sets default I/O interface parameters.
 *
 * @param parent of the type QObject*, sets a parent
 */
CryptFileDevice::CryptFileDevice( QObject *parent ) :
    QIODevice( parent )
{

}

/**
 * @brief The constructor of the class CryptFileDevice
 *
 * The constructor accepts a read/write device as a parameter.
 *
 * @param device of the type QFileDevice*, a read/write device
 * @param parent of the type QObject*, sets a parent
 */
CryptFileDevice::CryptFileDevice( QFileDevice *device, QObject *parent ) :
    QIODevice( parent ),
    m_device( device ),
    m_deviceOwner( false )
{

}

/**
 * @brief The constructor of the class CryptFileDevice
 *
 * The constructor accepts a read/write device as a parameter, as well as a password and a salt.
 *
 * @param device of the type QFileDevice*, a read/write device
 * @param password of the type QByteArray &, sets a password
 * @param salt of the type QByteArray &, sets a salt
 * @param parent of the type QObject*, sets a parent
 */
CryptFileDevice::CryptFileDevice( QFileDevice *device,
                                  const QByteArray &password,
                                  const QByteArray &salt,
                                  QObject *parent ) :
    QIODevice( parent ),
    m_device( device ),
    m_deviceOwner( false ),
    m_password( password ),
    m_salt( salt.mid( 0, kSaltMaxLength ) ),
    m_encMethod( AesCipher )
{

}

/**
 * @brief The constructor of the class CryptFileDevice
 *
 * The constructor accepts a name of the file as a parameter, as well as a password and a salt.
 *
 * @param fileName of the type QString &, name of the file
 * @param password of the type QByteArray &, sets a password
 * @param salt of the type QByteArray &, sets a salt
 * @param parent of the type QObject*, sets a parent
 */
CryptFileDevice::CryptFileDevice( const QString &fileName,
                                  const QByteArray &password,
                                  const QByteArray &salt,
                                  QObject *parent ) :
    QIODevice( parent ),
    m_device( new QFile( fileName ) ),
    m_deviceOwner( true ),
    m_password( password ),
    m_salt( salt.mid( 0, kSaltMaxLength ) ),
    m_encMethod( AesCipher )
{

}

/**
 * @brief The destructor of the class CryptFileDevice
 */
CryptFileDevice::~CryptFileDevice()
{
    this->close();

    if ( m_deviceOwner )
    {
        delete m_device;
    }
}

/**
 * @brief set-function for the Password
 * @param password of the type QByteArray &
 */
void CryptFileDevice::setPassword( const QByteArray &password )
{
    m_password = password;
}

/**
 * @brief set-function for the Salt
 * @param salt of the type QByteArray &
 */
void CryptFileDevice::setSalt( const QByteArray &salt )
{
    m_salt = salt.mid( 0, kSaltMaxLength );
}

/**
 * @brief set-function for the keyLength
 * @param keyLength of the type CryptFileDevice::AesKeyLength
 */
void CryptFileDevice::setKeyLength( CryptFileDevice::AesKeyLength keyLength )
{
    m_aesKeyLength = keyLength;
}

/**
 * @brief set-function for the numRounds
 * @param numRounds of the type int
 */
void CryptFileDevice::setNumRounds( int numRounds )
{
    m_numRounds = numRounds;
}

/**
 * @brief set-function for the encryptionMethod
 * @param enc of the type CryptFileDevice::EncryptionMethod
 */
void CryptFileDevice::setEncryptionMethod(CryptFileDevice::EncryptionMethod enc)
{
    m_encMethod = enc;
}

/**
 * @brief CryptFileDevice::open
 *
 * Opens the device and sets its OpenMode to mode.
 * Returns true if successful; otherwise returns false.
 *
 * @param mode of the flags QIODevice::OpenMode (ReadOnly, WriteOnly, ReadWrite, etc)
 * @retval true if successful,
 * @retval false otherwise.
 */
bool CryptFileDevice::open( OpenMode mode )
{
    if ( m_device == nullptr )
    {
        return false;
    }

    if ( this->isOpen() )
    {
        return false;
    }

    if ( mode & WriteOnly )
    {
        mode |= ReadOnly;
    }

    if ( mode & Append )
    {
        mode |= ReadWrite;
    }

    OpenMode deviceOpenMode;
    if ( mode == ReadOnly )
    {
        deviceOpenMode = ReadOnly;
    }
    else
    {
        deviceOpenMode = ReadWrite;
    }

    if ( mode & Truncate )
    {
        deviceOpenMode |= Truncate;
    }

    bool ok;
    if ( m_device->isOpen() )
    {
        ok = (m_device->openMode() == deviceOpenMode);
    }
    else
    {
        ok = m_device->open(deviceOpenMode);
    }

    if (!ok)
    {
        return false;
    }

    if ( m_password.isEmpty() )
    {
        this->setOpenMode( mode );
        return true;
    }

    if ( (m_encMethod == AesCipher) && (!initCipher()) )
    {
        return false;
    }

    m_encrypted = true;
    this->setOpenMode( mode );
// TODO
    qint64 size = m_device->size();
    if ( size == 0 && mode != ReadOnly )
    {
//        this->insertHeader();
    }

    if ( size > 0 )
    {
        if ( !this->tryParseHeader() )
        {
            m_encrypted = false;
            m_device->seek(0);
            m_device->close();
            return false;
        }
    }

    if ( mode & Append )
    {
        seek( m_device->size() - kHeaderLength );
    }

    return true;
}

/**
 * @brief CryptFileDevice::insertHeader
 *
 * The method CryptFileDevice::insertHeader allow you to provide the files
 * being encoded with a special 1024 bit header (variable kHeaderLength).
 * Which contains AES encryption options, as well as a hash of the sum of the password and salt.
 *
 * @note In the next version, the header of the encrypted file will be backed up with a CRC checksum.
 */
void CryptFileDevice::insertHeader( void )
{
    QByteArray header;
    header.append( 0xcd ); // cryptdevice byte
    header.append( 0x01 ); // version
    header.append((char *)&m_aesKeyLength, 4 ); // aes key length
    header.append((char *)&m_numRounds, 4 ); // iteration count to use
    QByteArray passwordHash = QCryptographicHash::hash( m_password, QCryptographicHash::Sha3_256 );
    header.append( passwordHash );
    QByteArray saltHash = QCryptographicHash::hash( m_salt, QCryptographicHash::Sha3_256 );
    header.append( saltHash );
    QByteArray padding( kHeaderLength - header.length(), 0xcd ); // padding with 0xcd
    header.append( padding );
    m_device->write( header );
}

/**
 * @brief CryptFileDevice::tryParseHeader
 *
 * The CryptFileDevice::tryParseHeader method parses the special 1024-bit header
 * (kHeaderLength variable). This will allow you to look up the special AES encryption
 * options as well as a hash of the sum of password and salt.
 *
 * @note In the next version, the header of the encrypted file will be backed up with a CRC checksum.
 *
 * @retval true if parse successful,
 * @retval false otherwise.
 */
bool CryptFileDevice::tryParseHeader( void )
{
    QByteArray header = m_device->read( kHeaderLength );
    if ( header.length() != kHeaderLength )
    {
        return false;
    }

    if ( header.at(0) != (char)0xcd )
    {
        return false;
    }

    //int version = header.at(1);

    int aesKeyLength = *(int *)header.mid(2, 4).data();
    if (aesKeyLength != m_aesKeyLength)
        return false;

    int numRounds = *(int *)header.mid(6, 4).data();
    if (numRounds != m_numRounds)
        return false;

    QByteArray passwordHash = header.mid( 10, 32 );
    QByteArray expectedPasswordHash = QCryptographicHash::hash( m_password, QCryptographicHash::Sha3_256 );
    if ( passwordHash != expectedPasswordHash )
    {
        return false;
    }

    QByteArray saltHash = header.mid( 42, 32 );
    QByteArray expectedSaltHash = QCryptographicHash::hash( m_salt, QCryptographicHash::Sha3_256 );
    if ( saltHash != expectedSaltHash )
    {
        return false;
    }

    QByteArray padding = header.mid( 74 );
    QByteArray expectedPadding( padding.length(), 0xcd );

    return ( padding == expectedPadding );
}

/**
 * @brief CryptFileDevice::close
 *
 * Reimplemented from QIODevice::close().
 * Calls CryptFileDevice::flush() and closes the file.
 *
 * First emits aboutToClose(), then closes the device and sets its OpenMode to NotOpen.
 * The error string is also reset.
 *
 * @note Errors from flush are ignored.
 */
void CryptFileDevice::close( void )
{
    if ( !this->isOpen() )
    {
        return;
    }

    if ( (openMode() & WriteOnly) || (openMode() & Append) )
    {
        flush();
    }

    this->seek(0);
    m_device->close();
    this->setOpenMode(NotOpen);

    if ( m_encrypted )
    {
        m_encrypted = false;
    }
}

/**
 * @brief set-function for the fileName
 *
 * @param fileName of the type QString &
 */
void CryptFileDevice::setFileName( const QString &fileName )
{
    if ( m_device )
    {
        m_device->close();
        if ( m_deviceOwner )
        {
            delete m_device;
        }
    }
    m_device = new QFile( fileName );
    m_deviceOwner = true;
}

/**
 * @brief get-function for the fileName
 *
 * @return fileName of the type QString
 */
QString CryptFileDevice::fileName( void ) const
{
    if ( m_device != nullptr )
    {
        return m_device->fileName();
    }

    return QString();
}

/**
 * @brief set-function for the fileDevice
 *
 * @param device of the type QFileDevice*
 */
void CryptFileDevice::setFileDevice( QFileDevice *device )
{
    if ( m_device )
    {
        m_device->close();
        if ( m_deviceOwner )
        {
            delete m_device;
        }
    }
    m_device = device;
    m_deviceOwner = false;
}

/**
 * @brief CryptFileDevice::flush
 *
 * Flushes any buffered data to the file.
 * Returns true if successful; otherwise returns false.
 *
 * @retval true if successful;
 * @retval false otherwise.
 */
bool CryptFileDevice::flush( void )
{
    return m_device->flush();
}

/**
 * @brief CryptFileDevice::isEncrypted
 *
 * Returns whether the open file is encrypted.
 *
 * @retval true if encrypted;
 * @retval false otherwise.
 */
bool CryptFileDevice::isEncrypted( void ) const
{
    return m_encrypted;
}

/**
 * @brief CryptFileDevice::readBlock
 *
 * Reads from the open file into a buffer of length len.
 *
 * @param len the length of the block
 * @param block a Reference to array of bytes
 *
 * @return readBytes Number of bytes read
 */
qint64 CryptFileDevice::readBlock( qint64 len, QByteArray &block )
{
    int length = block.length();
    qint64 readBytes = 0;
    do
    {
        qint64 fileRead = m_device->read( block.data() + block.length(), len - readBytes );
        if ( fileRead <= 0 )
        {
            break;
        }

        readBytes += fileRead;
    } while ( readBytes < len );

    if ( readBytes == 0 )
    {
        return 0;
    }

    QScopedPointer<char> plaintext( decrypt( block.data() + length, readBytes ) );

    block.append( plaintext.data(), readBytes );

    return readBytes;
}

/**
 * @brief CryptFileDevice::readData
 *
 * Reimplemented from QIODevice::readData()
 *
 * Reads up to len bytes from the device into data,
 * and returns the number of bytes read or -1 if an error occurred.
 *
 * @note
 * - When reimplementing this function it is important that this function
 * reads all the required data before returning.
 * This is required in order for QDataStream to be able to operate on the class.
 * QDataStream assumes all the requested information was read and
 * therefore does not retry reading if there was a problem.
 * - This function might be called with a len of 0,
 * which can be used to perform post-reading operations.
 *
 * @param data of the type char*
 * @param len the length of the data
 *
 * @return the number of bytes read or -1 if an error occurred.
 */
qint64 CryptFileDevice::readData( char *data, qint64 len )
{
    if ( !m_encrypted )
    {
        return m_device->read( data, len );
    }

    if ( len == 0 )
    {
        return m_device->read( data, len );
    }

    QByteArray ba;
    ba.reserve( len );
    do
    {
        qint64 maxSize = len - ba.length();

        qint64 size = readBlock(maxSize, ba);

        if ( size == 0 )
        {
            break;
        }
    } while ( ba.length() < len );

    if ( ba.isEmpty() )
    {
        return 0;
    }

    memcpy( data, ba.data(), ba.length() );

    return ba.length();
}

/**
 * @brief CryptFileDevice::writeData
 *
 * Reimplemented from QIODevice::writeData().
 *
 * Writes up to length bytes from data to the device.
 * Returns the number of bytes written, or -1 if an error occurred.
 *
 * @note When reimplementing this function it is important that this function
 * writes all the data available before returning.
 * This is required in order for QDataStream to be able to operate on the class.
 * QDataStream assumes all the information was written and therefore does not retry
 * writing if there was a problem.
 *
 * @param data of the type char*
 * @param length the length of the data
 * @return the number of bytes written, or -1 if an error occurred.
 */
qint64 CryptFileDevice::writeData( const char *data, qint64 length )
{
    if ( !m_encrypted )
    {
        return m_device->write( data, length );
    }

    QScopedPointer<char, QScopedPointerArrayDeleter<char> > cipherText( this->encrypt( data, length ) );
    if ( cipherText.isNull() )
    {
        return -1;
    }
    m_device->write( cipherText.data(), length );

    if ( m_device->error() != 0 )
    {
        qCritical(cryptFileDev) << QObject::tr( "Write Error: %1, code: %2" ).arg( m_device->errorString() ).arg( m_device->error() );
        emit errorMessage( QObject::tr( "File: %1\nWrite Error: %2" ).arg( m_device->fileName() ).arg( m_device->errorString() ) );
    }
    return length;
}

/**
 * @brief CryptFileDevice::initCtr
 *
 * Initializes specific parameters for AES encoding.
 * And ends up calling the AES_encrypt(prevIvec, ecount, aesKey) constructor.
 *
 * @param state of the type CtrState*
 * @param iv of the type unsigned char*
 */
void CryptFileDevice::initCtr( CtrState *state, const unsigned char *iv )
{
    qint64 position = pos();

    state->num = position % AES_BLOCK_SIZE;

    memset( state->ecount, 0, sizeof(state->ecount) );

    /* Initialise counter in 'ivec' */
    qint64 count = position / AES_BLOCK_SIZE;
    if ( state->num > 0 )
    {
        count++;
    }

    qint64 newCount = count;
    if ( newCount > 0 )
    {
        newCount = qToBigEndian(count);
    }

    int sizeOfIv = sizeof( state->ivec ) - sizeof( qint64 );
    memcpy( state->ivec + sizeOfIv, &newCount, sizeof( newCount ) );

    /* Copy IV into 'ivec' */
    memcpy( state->ivec, iv, sizeOfIv );

    if ( count > 0 )
    {
        count = qToBigEndian( count - 1 );
        unsigned char prevIvec[ AES_BLOCK_SIZE ];
        memcpy( prevIvec, state->ivec, sizeOfIv );

        memcpy( prevIvec + sizeOfIv, &count, sizeof( count ) );

        AES_encrypt( prevIvec, state->ecount, &m_aesKey );
    }
}

/**
 * @brief CryptFileDevice::initCipher
 * @return
 */
bool CryptFileDevice::initCipher( void )
{
    const EVP_CIPHER *cipher = EVP_enc_null();
    if ( m_aesKeyLength == kAesKeyLength128 )
    {
        cipher = EVP_aes_128_ctr();
    }
    else if ( m_aesKeyLength == kAesKeyLength192 )
    {
        cipher = EVP_aes_192_ctr();
    }
    else if ( m_aesKeyLength == kAesKeyLength256 )
    {
        cipher = EVP_aes_256_ctr();
    }
    else
    {
        Q_ASSERT_X( false, Q_FUNC_INFO, "Unknown value of AesKeyLength" );
    }

    EVP_CIPHER_CTX ctx;

    EVP_CIPHER_CTX_init( &ctx );
    EVP_EncryptInit_ex( &ctx, cipher, nullptr, nullptr, nullptr );
    int keyLength = EVP_CIPHER_CTX_key_length( &ctx );
    int ivLength = EVP_CIPHER_CTX_iv_length( &ctx );

    unsigned char key[ keyLength ];
    unsigned char iv[ ivLength ];

    int ok = EVP_BytesToKey( cipher,
                             EVP_sha256(),
                             m_salt.isEmpty() ? nullptr : reinterpret_cast<unsigned char *>(m_salt.data()),
                             reinterpret_cast<unsigned char *>(m_password.data()),
                             m_password.length(),
                             m_numRounds,
                             key,
                             iv );

    EVP_CIPHER_CTX_cleanup( &ctx );

    if ( ok == 0 )
    {
        return false;
    }

    int res = AES_set_encrypt_key( key, keyLength * 8, &m_aesKey );
    if ( res != 0 )
    {
        return false;
    }

    initCtr( &m_ctrState, iv );

    return true;
}

/**
 * @brief CryptFileDevice::encrypt
 * @param plainText
 * @param length
 * @return
 */
char *CryptFileDevice::encrypt( const char *plainText, qint64 length )
{
    unsigned char *cipherText = new (std::nothrow) unsigned char[length];
    if ( cipherText == nullptr )
    {
        qCritical(cryptFileDev) << QObject::tr( "Operator new: bad allocation memory, execution terminating" );
        emit errorMessage( QObject::tr( "Bad allocation memory, execution terminating.\n"
                                        "Advice: try to reduce the size of the buffer!" ) );
        return nullptr;
    }

    if ( m_encMethod == AesCipher )
    {
        AES_ctr128_encrypt(reinterpret_cast<const unsigned char *>(plainText),
                           cipherText,
                           length,
                           &m_aesKey,
                           m_ctrState.ivec,
                           m_ctrState.ecount,
                           &m_ctrState.num);
    }
    else if ( m_encMethod == XorCipher )
    {
        QByteArray passwordHash = QCryptographicHash::hash( m_password, QCryptographicHash::Sha3_512 );
        unsigned char *pass = reinterpret_cast<unsigned char *>( passwordHash.data() );

        for ( qint64 i = 0; i < length; i++ )
        {
            *(cipherText + i) = *(plainText + i) ^ *(pass + i%64) ^ i%251;
        }
    }
    else
    {
        Q_ASSERT_X( false, Q_FUNC_INFO, "Unknown value of EncryptionMethod" );
    }

    return reinterpret_cast<char *>( cipherText );
}

/**
 * @brief CryptFileDevice::decrypt
 * @param cipherText
 * @param len
 * @return
 */
char *CryptFileDevice::decrypt( const char *cipherText, qint64 len )
{
    unsigned char *plainText = new unsigned char[ len ];

    qint64 processLen = 0;
    do {
        int maxPlainLen = len > std::numeric_limits<int>::max() ? std::numeric_limits<int>::max() : len;

        AES_ctr128_encrypt(reinterpret_cast<const unsigned char *>(cipherText) + processLen,
                           plainText + processLen,
                           maxPlainLen,
                           &m_aesKey,
                           m_ctrState.ivec,
                           m_ctrState.ecount,
                           &m_ctrState.num);

        processLen += maxPlainLen;
        len -= maxPlainLen;
    } while ( len > 0 );

    return reinterpret_cast<char *>( plainText );
}

/**
 * @brief CryptFileDevice::atEnd
 *
 * Returns true if the current read and write position is at the end of the device
 * (i.e. there is no more data available for reading on the device);
 * otherwise returns false.
 *
 * @retval true if the current read and write position is at the end of the device;
 * @retval false otherwise.
 *
 * @warning For some devices, atEnd() can return true even though there is more data to read.
 * This special case only applies to devices that generate data in direct response to you calling read()
 * (e.g., /dev or /proc files on Unix and OS X, or console input / stdin on all platforms).
 */
bool CryptFileDevice::atEnd( void ) const
{
    return QIODevice::atEnd();
}

/**
 * @brief CryptFileDevice::bytesAvailable
 *
 * Returns the number of bytes that are available for reading.
 * This function is commonly used with sequential devices to determine the number of bytes to allocate in a buffer before reading.
 *
 * @note Subclasses that reimplement this function must call the base implementation in order to include the size of the buffer of QIODevice.
 * Example:
 * @code
 * qint64 CustomDevice::bytesAvailable() const
 * {
      return buffer.size() + QIODevice::bytesAvailable();
 * }
 * @endcode
 *
 * @return Returns the number of bytes that are available for reading.
 */
qint64 CryptFileDevice::bytesAvailable( void ) const
{
    return QIODevice::bytesAvailable();
}

/**
 * @brief CryptFileDevice::pos
 *
 * For random-access devices, this function returns the position that data is written to or read from.
 * For sequential devices or closed devices, where there is no concept of a "current position", 0 is returned.
 *
 * @note The current read/write position of the device is maintained internally by QIODevice,
 * so reimplementing this function is not necessary.
 * When subclassing QIODevice, use QIODevice::seek() to notify QIODevice about changes in the device position.
 *
 * @return returns the position that data is written to or read from.
 * For sequential devices or closed devices, where there is no concept of a "current position", 0 is returned.
 */
qint64 CryptFileDevice::pos( void ) const
{
    return QIODevice::pos();
}

/**
 * @brief CryptFileDevice::seek
 *
 * For random-access devices, this function sets the current position to pos,
 * returning true on success, or false if an error occurred. For sequential devices,
 * the default behavior is to produce a warning and return false.
 *
 * Do not forget that you need to take into account the header of the encoded file.
 * The size of which is stored in the constant kHeaderLength.
 *
 * @note Seeking beyond the end of a file:
 * If the position is beyond the end of a file, then seek() will not immediately extend the file.
 * If a write is performed at this position, then the file will be extended.
 * The content of the file between the previous end of file and
 * the newly written data is UNDEFINED and varies between platforms and file systems.
 *
 * @param pos of the type qint64
 * @retval true if success,
 * @retval false if an error occurred.
 */
bool CryptFileDevice::seek( qint64 pos )
{
    bool result = QIODevice::seek( pos );
    if ( m_encrypted )
    {
        m_device->seek( kHeaderLength + pos );
        initCtr(&m_ctrState, m_ctrState.ivec);
    }
    else
    {
        m_device->seek(pos);
    }

    return result;
}

/**
 * @brief CryptFileDevice::size
 *
 * Reimplemented from QIODevice::size().
 *
 * For open random-access devices, this function returns the size of the device.
 * For open sequential devices, bytesAvailable() is returned.

 * If the device is closed, the size returned will not reflect the actual size of the device.
 *
 * @note For regular empty files on Unix (e.g. those in /proc), this function returns 0;
 * the contents of such a file are generated on demand in response to you calling read().
 *
 * @note Do not forget that you need to take into account the header of the encoded file.
 * The size of which is stored in the constant kHeaderLength.
 *
 * @return the size of the file.
 */
qint64 CryptFileDevice::size( void ) const
{
    if ( m_device == nullptr )
    {
        return 0;
    }

    if ( !m_encrypted )
    {
        return m_device->size();
    }

    return m_device->size() - kHeaderLength;
}

/**
 * @brief CryptFileDevice::remove
 *
 * Removes the file specified by fileName(). Returns true if successful;
 * otherwise returns false.
 *
 * @note The file is closed before it is removed.
 *
 * @retval true if successful;
 * @retval false otherwise.
 */
bool CryptFileDevice::remove( void )
{
    if ( m_device == nullptr )
    {
        return false;
    }

    QString fileName = m_device->fileName();
    if ( fileName.isEmpty() )
    {
        return false;
    }

    if ( this->isOpen() )
    {
        close();
    }

    bool ok = QFile::remove( fileName );
    if ( ok )
    {
        m_device = nullptr;
    }

    return ok;
}

/**
 * @brief CryptFileDevice::exists
 *
 * This is an overloaded function.
 *
 * Returns true if the file specified by fileName() exists; otherwise returns false.
 *
 * @retval true if the file specified by fileName() exists;
 * @retval false otherwise.
 */
bool CryptFileDevice::exists( void ) const
{
    if ( m_device == nullptr )
    {
        return false;
    }

    QString fileName = m_device->fileName();
    if ( fileName.isEmpty() )
    {
        return false;
    }

    return QFile::exists( fileName );
}

/**
 * @brief CryptFileDevice::rename
 *
 * Renames the file currently specified by fileName() to newName.
 * Returns true if successful; otherwise returns false.
 *
 * @note
 * - If a file with the name newName already exists, rename() returns false
 * (i.e., QFile will not overwrite it).
 * - The file is closed before it is renamed.
 * - If the rename operation fails, Qt will attempt to copy this file's contents to newName,
 * and then remove this file, keeping only newName.
 * If that copy operation fails or this file can't be removed,
 * the destination file newName is removed to restore the old state.
 *
 * @param newName of type QString &
 * @retval true if successful;
 * @retval false otherwise.
 */
bool CryptFileDevice::rename( const QString &newName )
{
    if ( m_device == nullptr )
    {
        return false;
    }

    QString fileName = m_device->fileName();
    if ( fileName.isEmpty() )
    {
        return false;
    }

    if ( this->isOpen() )
    {
        close();
    }

    bool ok = QFile::rename( fileName, newName );
    if ( ok )
    {
        setFileName( newName );
    }

    return ok;
}

