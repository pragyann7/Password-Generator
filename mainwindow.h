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

private:
    Ui::MainWindow *ui;

    void savePasswordToFile(const QString &name, const QString &password);
    void loadSavedPasswords(const QString &cryptoKey);

    QString cryptoKey = "123";
    QString masterPassword = "qwe";

};

#endif // MAINWINDOW_H
