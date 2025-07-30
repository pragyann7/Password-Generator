#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <QString>
#include <QByteArray>

bool storeMasterPasswordAndSecurityAnswers(const QString &masterPassword, const QStringList &securityAnswers);
bool verifyMasterPassword(const QString &inputPassword);
bool verifySecurityAnswers(const QStringList &inputAnswers);
QString getMasterPasswordHashFilePath();


#endif // CRYPTO_UTILS_H
