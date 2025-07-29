#include "crypto_utils.h"
#include <QCryptographicHash>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QTextStream>

QString getMasterPasswordHashFilePath() {
    QString folderPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(folderPath);
    if (!dir.exists()) dir.mkpath(".");
    return dir.filePath("master.hash");
}

bool saveMasterPasswordHash(const QString &masterPassword) {
    QByteArray hash = QCryptographicHash::hash(masterPassword.toUtf8(), QCryptographicHash::Sha256);

    QFile file(getMasterPasswordHashFilePath());
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) return false;

    QTextStream out(&file);
    out << hash.toHex();
    file.close();
    return true;
}

bool verifyMasterPassword(const QString &inputPassword) {
    QFile file(getMasterPasswordHashFilePath());
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) return false;

    QByteArray storedHash = file.readLine().trimmed();
    file.close();

    QByteArray inputHash = QCryptographicHash::hash(inputPassword.toUtf8(), QCryptographicHash::Sha256);
    return storedHash == inputHash.toHex();
}
