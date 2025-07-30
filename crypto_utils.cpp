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

bool saveMasterPasswordHash(const QString &masterPassword, const QStringList &securityAnswers) {
    if (securityAnswers.size() != 2) return false;

    QFile file(getMasterPasswordHashFilePath());
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) return false;

    QTextStream out(&file);

    // Hash and write master password
    QByteArray passwordHash = QCryptographicHash::hash(masterPassword.toUtf8(), QCryptographicHash::Sha256);
    out << passwordHash.toHex() << '\n';

    // Hash and write each security answer
    for (const QString &answer : securityAnswers) {
        QByteArray hash = QCryptographicHash::hash(answer.toUtf8(), QCryptographicHash::Sha256);
        out << hash.toHex() << '\n';
    }

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
