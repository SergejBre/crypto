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
struct CtrState
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

class CryptFileDevice : public QIODevice
{
    Q_OBJECT
    Q_DISABLE_COPY( CryptFileDevice )

public:
    enum AesKeyLength
    {
        kAesKeyLength128,
        kAesKeyLength192,
        kAesKeyLength256
    };
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
    ~CryptFileDevice();

    bool open( OpenMode flags );
    void close( void );

    void setFileName( const QString &fileName );
    QString fileName( void ) const;

    void setFileDevice( QFileDevice *device );

    void setPassword( const QByteArray &password );
    void setSalt( const QByteArray &salt );
    void setKeyLength( AesKeyLength keyLength );
    void setNumRounds( int numRounds );
    void setEncryptionMethod( EncryptionMethod enc );

    bool isEncrypted( void ) const;
    qint64 size( void ) const;

    bool atEnd( void ) const;
    qint64 bytesAvailable( void ) const;
    qint64 pos( void ) const;
    bool seek( qint64 pos );
    bool flush( void );
    bool remove( void );
    bool exists( void ) const;
    bool rename( const QString &newName );

signals:
    void errorMessage( const QVariant &msg ) const;

protected:
    qint64 readData( char *data, qint64 length );
    qint64 writeData( const char *data, qint64 length );

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
    AesKeyLength m_aesKeyLength = kAesKeyLength256;
    int m_numRounds = 5;

    CtrState m_ctrState;
    AES_KEY m_aesKey;
};

#endif // CRYPTFILEDEVICE_H
