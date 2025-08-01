#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_saveButton_clicked();
    void onPasswordTableCellClicked(int row, int column);
    void on_cmpBtn_clicked();
    void on_passsubmitBtn_clicked();
    void on_changepassBtn_clicked();
    void on_answersubmitBtn_clicked();

    void on_forgetpassBtn_clicked();

    void on_forgotsubmitBtn_clicked();
    void setupAboutPage();

    void on_themebtn_clicked();

private:
    Ui::MainWindow *ui;
    QToolBar *toolbar;
    void savePasswordToFile(const QString &name, const QString &password);
    void loadSavedPasswords(const QString &cryptoKey);
    void clearAllInputFields();

    QString cryptoKey = "123";
    QString pendingNewMasterPassword;

};

#endif // MAINWINDOW_H
