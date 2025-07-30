#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <QString>
#include <QByteArray>

bool saveMasterPasswordHash(const QString &masterPassword, const QStringList &securityAnswers);
bool verifyMasterPassword(const QString &inputPassword);
QString getMasterPasswordHashFilePath();


#endif // CRYPTO_UTILS_H
