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
 * @brief CryptFileDevice::~CryptFileDevice
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
 * @brief CryptFileDevice::setPassword
 * @param password
 */
void CryptFileDevice::setPassword( const QByteArray &password )
{
    m_password = password;
}

/**
 * @brief CryptFileDevice::setSalt
 * @param salt
 */
void CryptFileDevice::setSalt( const QByteArray &salt )
{
    m_salt = salt.mid( 0, kSaltMaxLength );
}

/**
 * @brief CryptFileDevice::setKeyLength
 * @param keyLength
 */
void CryptFileDevice::setKeyLength( AesKeyLength keyLength )
{
    m_aesKeyLength = keyLength;
}

/**
 * @brief CryptFileDevice::setNumRounds
 * @param numRounds
 */
void CryptFileDevice::setNumRounds( int numRounds )
{
    m_numRounds = numRounds;
}

/**
 * @brief CryptFileDevice::setEncryptionMethod
 * @param enc
 */
void CryptFileDevice::setEncryptionMethod(CryptFileDevice::EncryptionMethod enc)
{
    m_encMethod = enc;
}

/**
 * @brief CryptFileDevice::open
 * @param mode
 * @return
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
 * @return
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
 * @brief CryptFileDevice::setFileName
 * @param fileName
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
 * @brief CryptFileDevice::fileName
 * @return
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
 * @brief CryptFileDevice::setFileDevice
 * @param device
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
 * @return
 */
bool CryptFileDevice::flush( void )
{
    return m_device->flush();
}

/**
 * @brief CryptFileDevice::isEncrypted
 * @return
 */
bool CryptFileDevice::isEncrypted( void ) const
{
    return m_encrypted;
}

/**
 * @brief CryptFileDevice::readBlock
 * @param len
 * @param block
 * @return
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
 * @param data
 * @param len
 * @return
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
 * @param data
 * @param length
 * @return
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
 * @param state
 * @param iv
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
 * @return
 */
bool CryptFileDevice::atEnd( void ) const
{
    return QIODevice::atEnd();
}

/**
 * @brief CryptFileDevice::bytesAvailable
 * @return
 */
qint64 CryptFileDevice::bytesAvailable( void ) const
{
    return QIODevice::bytesAvailable();
}

/**
 * @brief CryptFileDevice::pos
 * @return
 */
qint64 CryptFileDevice::pos( void ) const
{
    return QIODevice::pos();
}

/**
 * @brief CryptFileDevice::seek
 * @param pos
 * @return
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
 * @return
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
 * @return
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
 * @return
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
 * @param newName
 * @return
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

