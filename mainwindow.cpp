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
#include <qtimer.h>


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->errorLabel->hide();
    ui->stackedWidget->setCurrentWidget(ui->page_generate);

    QLabel *versionLabel = new QLabel("Version 1.0.0", this);
        QFont font = versionLabel->font();
    font.setPointSize(12);
    versionLabel->setFont(font);

    statusBar()->addPermanentWidget(versionLabel);


    ui->passwordTable->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
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

    // Connect to page switching
    connect(generateAction, &QAction::triggered, this, [=]() {
        ui->stackedWidget->setCurrentWidget(ui->page_generate);
    });

    connect(savedAction, &QAction::triggered, this, [=]() {
        ui->stackedWidget->setCurrentWidget(ui->page_saved);
        loadSavedPasswords(); // ⬅️ call to refresh table
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
        background-color: #2c3e50;  /* toolbar background */
    }
    QToolBar QToolButton {
        padding: 5px 10px;
        border: none;
        color: white;
        font-size: 12px;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    QToolBar QToolButton:hover {
        background-color: #2c3e52;
        color: white;
        border-radius: 6px;
    }
)");

    ui->generateBtn->setStyleSheet(R"(
    QPushButton {
        background-color: #3498db;  /* green background */
        color: white;               /* white text */
        border-radius: 12px;
        padding: 6px 12px;
    }
    QPushButton:hover {
        background-color: #2980b9;  /* darker green on hover */
    }
    QPushButton:pressed {
        background-color: #1f618d;  /* even darker when pressed */
    }
)");

    ui->saveButton->setStyleSheet(R"(
    QPushButton {
        background-color: #28a745;  /* green background */
        color: white;               /* white text */
        border-radius: 12px;
        padding: 6px 12px;
    }
    QPushButton:hover {
        background-color: #218838;  /* darker green on hover */
    }
    QPushButton:pressed {
        background-color: #1e7e34;  /* even darker when pressed */
    }
)");

    ui->cmpBtn->setStyleSheet(R"(
    QPushButton {
        background-color: #617190;  /* green background */
        color: white;               /* white text */
        border-radius: 12px;
        padding: 9px 12px;
    }
    QPushButton:hover {
        background-color: #4f5c75;  /* darker green on hover */
    }
    QPushButton:pressed {
        background-color: #2e3645;  /* even darker when pressed */
    }
)");

    ui->themebtn->setStyleSheet(R"(
    QPushButton {
        background-color: #617190;  /* green background */
        color: white;               /* white text */
        border-radius: 12px;
        padding: 9px 12px;
    }
    QPushButton:hover {
        background-color: #4f5c75;  /* darker green on hover */
    }
    QPushButton:pressed {
        background-color: #2e3645;  /* even darker when pressed */
    }
)");

    ui->exportpassBtn->setStyleSheet(R"(
    QPushButton {
        background-color: #617190;  /* green background */
        color: white;               /* white text */
        border-radius: 12px;
        padding: 9px 12px;
    }
    QPushButton:hover {
        background-color: #4f5c75;  /* darker green on hover */
    }
    QPushButton:pressed {
        background-color: #2e3645;  /* even darker when pressed */
    }
)");

    ui->filelocationBtn->setStyleSheet(R"(
    QPushButton {
        background-color: #617190;  /* green background */
        color: white;               /* white text */
        border-radius: 12px;
        padding: 9px 12px;
    }
    QPushButton:hover {
        background-color: #4f5c75;  /* darker green on hover */
    }
    QPushButton:pressed {
        background-color: #2e3645;  /* even darker when pressed */
    }
)");

    ui->languageBtn->setStyleSheet(R"(
    QPushButton {
        background-color: #617190;  /* green background */
        color: white;               /* white text */
        border-radius: 12px;
        padding: 9px 12px;
    }
    QPushButton:hover {
        background-color: #4f5c75;  /* darker green on hover */
    }
    QPushButton:pressed {
        background-color: #2e3645;  /* even darker when pressed */
    }
)");


}

MainWindow::~MainWindow()
{
    delete ui;
}

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
    qDebug() << "Password text:" << password;
    if (password.isEmpty()) {
        QMessageBox::warning(this, tr("Invalid input"), tr("Password cannot be empty."));
        return;
    }

    bool ok = false;
    QString name;

    // Instead of direct call to QInputDialog::getText, create a dialog object explicitly
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

    if (ok && !name.isEmpty()) {
        savePasswordToFile(name, password);
        QMessageBox::information(this, tr("Saved"), tr("Password \"%1\" saved as \"%2\".").arg(password, name));
    } else if (ok) {
        QMessageBox::warning(this, tr("Invalid input"), tr("Please enter a valid name."));
    }
}

void MainWindow::loadSavedPasswords()
{
    QString filePath = QDir::homePath() + "/passwords.txt";
    QFile file(filePath);

    ui->passwordTable->setRowCount(0); // Clear existing data

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return; // No file, nothing to load
    }

    QTextStream in(&file);
    int row = 0;

    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty() || !line.contains(":"))
            continue;

        QStringList parts = line.split(":");
        if (parts.size() != 2)
            continue;

        QString name = parts[0].trimmed();
        QString password = parts[1].trimmed();

        ui->passwordTable->insertRow(row);
        ui->passwordTable->setItem(row, 0, new QTableWidgetItem(name));
        ui->passwordTable->setItem(row, 1, new QTableWidgetItem(password));
        row++;
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
