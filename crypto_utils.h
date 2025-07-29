#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <QString>
#include <QByteArray>

bool saveMasterPasswordHash(const QString &masterPassword);
bool verifyMasterPassword(const QString &inputPassword);
QString getMasterPasswordHashFilePath(); // 👈 THIS


#endif // CRYPTO_UTILS_H
