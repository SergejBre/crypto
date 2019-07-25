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
 * @file cryptfiledevice.h
 *
 * @brief This file contains the declaration of the class CryptFileDevice
 */
#ifndef CRYPTFILEDEVICE_H
#define CRYPTFILEDEVICE_H

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------
#include <QIODevice>
#include <openssl/aes.h>

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------
class QFileDevice;

/**
 * @struct CtrState
 *
 * @brief The CtrState structure
 *
 * The structure contains specific fields for the parameters of the AES encryption method.
 */
struct CtrState
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

/**
 * @class CryptFileDevice
 *
 * @brief The CryptFileDevice class provides an interface for encrypting and decrypting
 * when reading and accordingly writing to open files.
 *
 * An implementation of the CryptFileDevice class replaces the standard interface QFileDevice
 * for reading and writing to open files. The QFileDevice class is the base class for I/O devices
 * that can read and write text and binary files and resources. QFile offers the main functionality,
 * QFileDevice serves as a base class for sharing functionality with other file devices,
 * by providing all the operations that can be done on files that have been opened by QFile.
 * The CryptFileDevice class is an overloaded the base class for I/O devices,
 * inherits from the standard abstract class QIODevice.
 *
 * The following virtual methods of QIODevice class must be reimplemented.
 *
 * Reimplemented Public Functions:
 * - CryptFileDevice::open
 * - CryptFileDevice::close
 * - CryptFileDevice::size
 * - CryptFileDevice::atEnd
 * - CryptFileDevice::bytesAvailable
 * - CryptFileDevice::pos
 * - CryptFileDevice::seek
 * .
 * Reimplemented Protected Functions:
 * - CryptFileDevice::readData
 * - CryptFileDevice::writeData
 * .
 * The class has an implementation of two types of constructors.
 * One of them works with a pointer to objects of type QFileDevice,
 * the other accepts as a parameter a reference to the file name.
 *
 * The standard encryption mechanism encrypts data block by block.
 * Therefore, an additional buffer is used for blocks.
 * When reserving a buffer, availability will be checked.
 * If there is not enough space, an error message will appear.
 *
 * The class also has other important functionality.
 * The methods of the class CryptFileDevice::insertHeader and CryptFileDevice::tryParseHeader allow you
 * to provide the files being encoded with a special 1024 bit header (variable kHeaderLength).
 * Which contains AES encryption options, as well as a hash of the sum
 * of the password and salt.
 * In the next version, the header of the encrypted file will be backed up with a CRC checksum.
 *
 * @note All functions in this class are reentrant.
 */
class CryptFileDevice : public QIODevice
{
    Q_OBJECT
    Q_DISABLE_COPY( CryptFileDevice )

public:
    /// Selection of the key length between 128, 192, 256 bits.
    enum class AesKeyLength : quint32
    {
        kAesKeyLength128,
        kAesKeyLength192,
        kAesKeyLength256
    };
    /// Selection of the encryption method XOR or AES.
    enum EncryptionMethod
    {
        XorCipher,
        AesCipher
    };

    explicit CryptFileDevice( QObject *parent = 0 );
    explicit CryptFileDevice( QFileDevice *device, QObject *parent = 0 );
    explicit CryptFileDevice( QFileDevice *device,
                              const QByteArray &password,
                              const QByteArray &salt,
                              QObject *parent = 0 );
    explicit CryptFileDevice( const QString &fileName,
                              const QByteArray &password,
                              const QByteArray &salt,
                              QObject *parent = 0 );
    ~CryptFileDevice() override;

    bool open( OpenMode flags ) override;
    void close( void ) override;

    void setFileName( const QString &fileName );
    QString fileName( void ) const;

    void setFileDevice( QFileDevice *device );

    void setPassword( const QByteArray &password );
    void setSalt( const QByteArray &salt );
    void setKeyLength( AesKeyLength keyLength );
    void setNumRounds( int numRounds );
    void setEncryptionMethod( EncryptionMethod enc );

    bool isEncrypted( void ) const;
    qint64 size( void ) const override;

    bool atEnd( void ) const override;
    qint64 bytesAvailable( void ) const override;
    qint64 pos( void ) const override;
    bool seek( qint64 pos ) override;
    bool flush( void );
    bool remove( void );
    bool exists( void ) const;
    bool rename( const QString &newName );

signals:
    void errorMessage( const QVariant &msg ) const;

protected:
    qint64 readData( char *data, qint64 length ) override;
    qint64 writeData( const char *data, qint64 length ) override;

    qint64 readBlock( qint64 length, QByteArray &block );

private:
    bool initCipher( void );
    void initCtr( CtrState *state, const unsigned char *iv );
    char *encrypt( const char *plainText, qint64 length );
    char *decrypt( const char *cipherText, qint64 length );

    void insertHeader( void );
    bool tryParseHeader( void );

    QFileDevice *m_device = nullptr;
    bool m_deviceOwner = false;
    bool m_encrypted = false;

    QByteArray m_password;
    QByteArray m_salt;
    EncryptionMethod m_encMethod;
    AesKeyLength m_aesKeyLength = AesKeyLength::kAesKeyLength256;
    int m_numRounds = 5;

    CtrState m_ctrState = {};
    AES_KEY m_aesKey = {};
};

#endif // CRYPTFILEDEVICE_H
