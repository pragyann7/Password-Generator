#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QSlider>
#include <QLCDNumber>
#include <QClipboard>
#include <QGuiApplication>
#include <QRandomGenerator>
#include <QToolBar>
#include <QInputDialog>
#include <QMessageBox>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <QTimer>
#include <QInputDialog>
#include <QCryptographicHash>
#include <QFile>
#include <QTextStream>
#include <QStandardPaths>
#include <QDir>
#include <QRandomGenerator>
#include <QMessageBox>
#include <QByteArray>
#include <QDebug>
#include <QBuffer>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "crypto_utils.h"



// Constants
const int SALT_SIZE = 16;
const int IV_SIZE = 16;
const int KEY_SIZE = 32;  // AES-256
const int PBKDF2_ITERATIONS = 100000;

//Encryption section
QByteArray generateRandomBytes(int length) {
    QByteArray bytes;
    for (int i = 0; i < length; ++i) {
        bytes.append(static_cast<char>(QRandomGenerator::system()->generate() & 0xFF));
    }
    return bytes;
}

bool deriveKeyFromPassword(const QString &crypto, const QByteArray &salt, QByteArray &keyOut) {
    keyOut.resize(KEY_SIZE);
    int result = PKCS5_PBKDF2_HMAC(crypto.toUtf8().data(),
                                   crypto.toUtf8().size(),
                                   reinterpret_cast<const unsigned char*>(salt.constData()),
                                   salt.size(),
                                   PBKDF2_ITERATIONS,
                                   EVP_sha256(),
                                   KEY_SIZE,
                                   reinterpret_cast<unsigned char*>(keyOut.data()));
    return result == 1;
}

bool encryptPassword(const QString &plainText, const QByteArray &key, const QByteArray &iv, QByteArray &cipherOut) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len;
    int ciphertext_len;
    QByteArray ciphertext;
    ciphertext.resize(plainText.toUtf8().size() + EVP_MAX_BLOCK_LENGTH);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                                reinterpret_cast<const unsigned char*>(key.constData()),
                                reinterpret_cast<const unsigned char*>(iv.constData()))) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_EncryptUpdate(ctx,
                               reinterpret_cast<unsigned char*>(ciphertext.data()), &len,
                               reinterpret_cast<const unsigned char*>(plainText.toUtf8().constData()),
                               plainText.toUtf8().size())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx,
                                 reinterpret_cast<unsigned char*>(ciphertext.data() + len), &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext_len += len;
    cipherOut = ciphertext.left(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool saveEncryptedPasswordToFile(const QString &name, const QString &password, const QString &crypto) {
    // Generate salt and IV

    QByteArray salt = generateRandomBytes(SALT_SIZE);
    QByteArray iv = generateRandomBytes(IV_SIZE);

    QByteArray key;

    if (!deriveKeyFromPassword(crypto, salt, key)) {
        return false;
    }

    QByteArray cipherText;
    if (!encryptPassword(password, key, iv, cipherText)) {
        return false;
    }

    // Save to secure location
    QString folderPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(folderPath);
    if (!dir.exists()) dir.mkpath(".");

    QString filePath = dir.filePath("passwords.txt");
    QFile file(filePath);

    if (!file.open(QIODevice::Append | QIODevice::Text)) {
        return false;
    }

    QTextStream out(&file);
    out << name << ":"
        << salt.toBase64() << ":"
        << iv.toBase64() << ":"
        << cipherText.toBase64() << "\n";

    file.close();
    return true;
}

//Decryption section
bool decryptPassword(const QByteArray &cipherText, const QByteArray &key, const QByteArray &iv, QString &plainTextOut) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len;
    int plaintext_len;
    QByteArray plaintext;
    plaintext.resize(cipherText.size()); // ciphertext size is max size of plaintext

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                                reinterpret_cast<const unsigned char*>(key.constData()),
                                reinterpret_cast<const unsigned char*>(iv.constData()))) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_DecryptUpdate(ctx,
                               reinterpret_cast<unsigned char*>(plaintext.data()), &len,
                               reinterpret_cast<const unsigned char*>(cipherText.constData()),
                               cipherText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx,
                                 reinterpret_cast<unsigned char*>(plaintext.data() + len), &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);
    plainTextOut = QString::fromUtf8(plaintext);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}



MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->errorLabel->hide();
    ui->passwordTable->setColumnCount(2);


    QLabel *versionLabel = new QLabel("Version 1.0.0", this);
        QFont font = versionLabel->font();
    font.setPointSize(12);
    versionLabel->setFont(font);

    statusBar()->addPermanentWidget(versionLabel);


    ui->passwordTable->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    ui->passwordTable->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    ui->passwordTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->passwordTable->setSelectionMode(QAbstractItemView::NoSelection);
    ui->passwordTable->setFocusPolicy(Qt::NoFocus);
    ui->passwordTable->setEditTriggers(QAbstractItemView::NoEditTriggers);


    connect(ui->passwordTable, &QTableWidget::cellClicked,this, &MainWindow::onPasswordTableCellClicked);


    QToolBar *toolbar = new QToolBar("Navigation", this);
    addToolBar(Qt::TopToolBarArea, toolbar);

    // Create actions
    QAction *generateAction = new QAction("Generate", this);
    generateAction->setToolTip("Generate a new password");

    QAction *savedAction = new QAction("Saved", this);
    savedAction->setToolTip("View saved passwords");

    QAction *settingAction = new QAction("Setting", this);
    settingAction->setToolTip("Open application settings");

    QAction *aboutAction = new QAction("About", this);
    aboutAction->setToolTip("About this application");

    toolbar->addAction(generateAction);
    toolbar->addAction(savedAction);
    toolbar->addAction(settingAction);
    toolbar->addAction(aboutAction);



    toolbar->setMovable(false);
    toolbar->setFloatable(false);

    // Only store if file doesn't exist (first-time setup)
    QFile file(getMasterPasswordHashFilePath());
    if (!file.exists()) {
        toolbar->hide();
        ui->stackedWidget->setCurrentWidget(ui->page_setup_password);
    }
    else{
        toolbar->show();
        ui->stackedWidget->setCurrentWidget(ui->page_generate);

    }

    // Connect to page switching
    connect(generateAction, &QAction::triggered, this, [=]() {
        ui->stackedWidget->setCurrentWidget(ui->page_generate);
    });

    connect(savedAction, &QAction::triggered, this, [=]() {
        bool ok;
        QString inputPassword = QInputDialog::getText(
            this, "Authentication Required",
            "Enter Master Password:",
            QLineEdit::Password, "", &ok);

        if (!ok || inputPassword.isEmpty()) return;

        if (!verifyMasterPassword(inputPassword)) {
            QMessageBox::critical(this, "Access Denied", "Incorrect Master Password.");
            return;
        }

        if (ui->page_saved) {
            ui->stackedWidget->setCurrentWidget(ui->page_saved);
            loadSavedPasswords(cryptoKey); // uses static cryptoKey
        }
    });




    connect(settingAction, &QAction::triggered, this, [=]() {
        ui->stackedWidget->setCurrentWidget(ui->page_setting);
    });

    connect(aboutAction, &QAction::triggered, this, [=]() {
        ui->stackedWidget->setCurrentWidget(ui->page_about);
    });


    connect(ui->passwordLength, &QSlider::valueChanged, this, [=](int value) {
        ui->passwordLengthIndicator->setText(QString::number(value));
    });

    connect(ui->generateBtn, &QPushButton::clicked, this, [=](){
        QString lowercase = "abcdefghijklmnopqrstuvwxyz";
        QString uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        QString digits = "0123456789";
        QString symbols = "!@#$%^";

        QString possibleChars;
        QString password;
        QList<QChar> mandatoryChars;

        // selected set ra euta compulsary character lini randomly
        if(ui->a2zCheck->isChecked()) {
            possibleChars += lowercase;
            mandatoryChars.append(lowercase[QRandomGenerator::global()->bounded(lowercase.length())]);
        }
        if(ui->A2ZCheck->isChecked()) {
            possibleChars += uppercase;
            mandatoryChars.append(uppercase[QRandomGenerator::global()->bounded(uppercase.length())]);
        }
        if(ui->digitCheck->isChecked()) {
            possibleChars += digits;
            mandatoryChars.append(digits[QRandomGenerator::global()->bounded(digits.length())]);
        }
        if(ui->symbolCheck->isChecked()) {
            possibleChars += symbols;
            mandatoryChars.append(symbols[QRandomGenerator::global()->bounded(symbols.length())]);
        }

        int length = ui->passwordLength->value();

        if(possibleChars.isEmpty()){
            ui->errorLabel->show();
            ui->passwordOutput->clear();
            return;
        }

        // baaki character haru select garni randomly
        for (int i = 0; i < length - mandatoryChars.size(); ++i) {
            int index = QRandomGenerator::global()->bounded(possibleChars.length());
            password += possibleChars.at(index);
        }

        // compulsary character haru random position ma halni
        for (QChar ch : mandatoryChars) {
            int pos = QRandomGenerator::global()->bounded(password.length() + 1);
            password.insert(pos, ch);
        }

        ui->errorLabel->hide();
        ui->passwordOutput->setText(password);
    });

    connect(ui->copyBtn, &QPushButton::clicked, this, [=](){
        QClipboard *clipboard = QGuiApplication::clipboard();
        clipboard->setText(ui->passwordOutput->text());
    });



    //Styling ko section
    toolbar->setStyleSheet(R"(
    QToolBar {
        background-color: #2c3e50;
    }
    QToolBar QToolButton {
        padding: 5px 10px;
        border: none;
        color: white;
        font-size: 12px;
    }
    QToolBar QToolButton:hover {
        background-color: #2c3e52;
        color: white;
        border-radius: 6px;
    }
)");

    ui->generateBtn->setStyleSheet(R"(
    QPushButton {
        background-color: #3498db;
        color: white;
        border-radius: 12px;
        padding: 6px 12px;
    }
    QPushButton:hover {
        background-color: #2980b9;
    }
    QPushButton:pressed {
        background-color: #1f618d;
    }
)");

    ui->saveButton->setStyleSheet(R"(
    QPushButton {
        background-color: #28a745;
        color: white;
        border-radius: 12px;
        padding: 6px 12px;
    }
    QPushButton:hover {
        background-color: #218838;
    }
    QPushButton:pressed {
        background-color: #1e7e34;
    }
)");

    ui->cmpBtn->setStyleSheet(R"(
    QPushButton {
        background-color: #617190;
        color: white;
        border-radius: 12px;
        padding: 9px 12px;
    }
    QPushButton:hover {
        background-color: #4f5c75;
    }
    QPushButton:pressed {
        background-color: #2e3645;
    }
)");

    ui->themebtn->setStyleSheet(R"(
    QPushButton {
        background-color: #617190;
        color: white;
        border-radius: 12px;
        padding: 9px 12px;
    }
    QPushButton:hover {
        background-color: #4f5c75;
    }
    QPushButton:pressed {
        background-color: #2e3645;
    }
)");

    ui->exportpassBtn->setStyleSheet(R"(
    QPushButton {
        background-color: #617190;
        color: white;
        border-radius: 12px;
        padding: 9px 12px;
    }
    QPushButton:hover {
        background-color: #4f5c75;
    }
    QPushButton:pressed {
        background-color: #2e3645;
    }
)");

    ui->filelocationBtn->setStyleSheet(R"(
    QPushButton {
        background-color: #617190;
        color: white;
        border-radius: 12px;
        padding: 9px 12px;
    }
    QPushButton:hover {
        background-color: #4f5c75;
    }
    QPushButton:pressed {
        background-color: #2e3645;
    }
)");

    ui->forgetpassBtn->setStyleSheet(R"(
    QPushButton {
        background-color: #617190;
        color: white;
        border-radius: 12px;
        padding: 9px 12px;
    }
    QPushButton:hover {
        background-color: #4f5c75;
    }
    QPushButton:pressed {
        background-color: #2e3645;
    }
)");

    ui->passsubmitBtn->setStyleSheet(R"(
    QPushButton {
        background-color: #617190;
        color: white;
        border-radius: 12px;
        padding: 9px 12px;
    }
    QPushButton:hover {
        background-color: #4f5c75;
    }
    QPushButton:pressed {
        background-color: #2e3645;
    }
)");


}

MainWindow::~MainWindow()
{
    delete ui;
}



//Functions

void MainWindow::savePasswordToFile(const QString &name, const QString &password)
{
    QString filePath = QDir::homePath() + "/passwords.txt";

    QFile file(filePath);

    if (!file.open(QIODevice::Append | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Error"), tr("Could not open file to save password."));
        return;
    }

    QTextStream out(&file);
    // Format: Name:Password
    out << name << ":" << password << "\n";

    file.close();
}

void MainWindow::on_saveButton_clicked()
{
    QString password = ui->passwordOutput->text();
    if (password.isEmpty()) {
        QMessageBox::warning(this, tr("Invalid input"), tr("Password cannot be empty."));
        return;
    }

    bool ok = false;
    QString name;

    QInputDialog inputDialog(this);
    inputDialog.setWindowTitle(tr("Save Password"));
    inputDialog.setLabelText(tr("Enter a name for your password:"));
    inputDialog.setTextValue(QString());
    inputDialog.setInputMode(QInputDialog::TextInput);
    inputDialog.resize(400, 150);

    if (inputDialog.exec() == QDialog::Accepted) {
        name = inputDialog.textValue();
        ok = true;
    }

    if (!ok || name.isEmpty()) {
        QMessageBox::warning(this, tr("Invalid input"), tr("Please enter a valid name."));
        return;
    }

    QString enteredPassword = QInputDialog::getText(this, "Master Password", "Enter master password:", QLineEdit::Password);
    if (enteredPassword.isEmpty()) {
        QMessageBox::warning(this, "Cancelled", "Master password is required to encrypt.");
        return;
    }

    if(verifyMasterPassword(enteredPassword)){

        if (saveEncryptedPasswordToFile(name, password, cryptoKey)) {
            QMessageBox::information(this, tr("Saved"), tr("Encrypted password saved as \"%1\".").arg(name));
        } else {
            QMessageBox::critical(this, tr("Error"), tr("Failed to save encrypted password."));
        }
    }
    else{
        QMessageBox::warning(this, "Invalid input", "Incorrect Password!");
        return;
    }
}

void MainWindow::loadSavedPasswords(const QString &cryptoKey)
{
    QString folderPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(folderPath);
    QString filePath = dir.filePath("passwords.txt");

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Error"), tr("Could not open saved passwords file."));
        return;
    }

    ui->passwordTable->clear();
    ui->passwordTable->setRowCount(0);
    ui->passwordTable->setColumnCount(2);
    ui->passwordTable->setHorizontalHeaderLabels(QStringList() << tr("Name") << tr("Password"));

    QTextStream in(&file);
    while (!in.atEnd()) {
        QString line = in.readLine();
        if (line.isEmpty()) continue;

        QStringList parts = line.split(':');
        if (parts.size() != 4) continue;

        QString name = parts[0];
        QByteArray salt = QByteArray::fromBase64(parts[1].toUtf8());
        QByteArray iv = QByteArray::fromBase64(parts[2].toUtf8());
        QByteArray cipherText = QByteArray::fromBase64(parts[3].toUtf8());

        // Derive key from static cryptoKey
        QByteArray key;
        if (!deriveKeyFromPassword(cryptoKey, salt, key)) {
            QMessageBox::warning(this, tr("Error"), tr("Failed to derive key."));
            continue;
        }

        QString decryptedPassword;
        if (!decryptPassword(cipherText, key, iv, decryptedPassword)) {
            decryptedPassword = tr("<Decryption Failed>");
        }

        int row = ui->passwordTable->rowCount();
        ui->passwordTable->insertRow(row);
        ui->passwordTable->setItem(row, 0, new QTableWidgetItem(name));
        ui->passwordTable->setItem(row, 1, new QTableWidgetItem(decryptedPassword));
    }

    file.close();
}






void MainWindow::onPasswordTableCellClicked(int row, int column)
{
    if (column != 1) return;

    QString originalPassword = ui->passwordTable->item(row, column)->text();

    QClipboard *clipboard = QGuiApplication::clipboard();
    clipboard->setText(originalPassword);

    ui->passwordTable->item(row, column)->setText("Copied!");

    QTimer::singleShot(1000, this, [=]() {
        ui->passwordTable->item(row, column)->setText(originalPassword);
    });
}

void MainWindow::on_cmpBtn_clicked()
{
    bool ok;
    QString enteredPassword = QInputDialog::getText(
        this,
        tr("Authentication Required"),
        tr("Enter Master Password:"),
        QLineEdit::Password,
        "",
        &ok
        );

    if(!ok){
        return;
    }

    if (verifyMasterPassword(enteredPassword)) {
            ui->stackedWidget->setCurrentWidget(ui->page_resetPassword);

    } else {
        QMessageBox::warning(this, tr("Access Denied"), tr("Incorrect password."));
    }
}


void MainWindow::on_passsubmitBtn_clicked()
{
    QString masterPassword = ui->masterpassField->text().trimmed();
    QString answer1 = ui->answer1Field->text().trimmed();
    QString answer2 = ui->answer2Field->text().trimmed();

    // Validate input
    if (masterPassword.isEmpty() || answer1.isEmpty() || answer2.isEmpty()) {
        QMessageBox::warning(this, "Input Required", "All fields are required.");
        return;
    }

    QStringList answers = { answer1, answer2 };

    if (saveMasterPasswordHash(masterPassword, answers)) {
        QMessageBox::information(this, "Success", "Master password and security answers saved.");
        ui->stackedWidget->setCurrentWidget(ui->page_generate);  // Go to main page after setup
    } else {
        QMessageBox::critical(this, "Error", "Failed to save credentials.");
    }
}

