#include <QString>
#include <QtTest>
#include "../cryptfiledevice.h"

class CryptoTest : public QObject
{
    Q_OBJECT

public:
    CryptoTest();

private Q_SLOTS:
    void testCase01();
    void testCase02();
    void testCase03();
};

CryptoTest::CryptoTest()
{
}

/**
 * @brief CryptoTest::testCase01
 */
void CryptoTest::testCase01()
{
    QVERIFY2(true, "Failure");
}

/**
 * @brief CryptoTest::testCase02
 */
void CryptoTest::testCase02()
{
    QVERIFY2(true, "Failure");
}

/**
 * @brief CryptoTest::testCase03
 */
void CryptoTest::testCase03()
{
    QVERIFY2(true, "Failure");
}

QTEST_APPLESS_MAIN(CryptoTest)

#include "cryptotest.moc"
