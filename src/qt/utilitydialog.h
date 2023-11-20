// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_UTILITYDIALOG_H
#define BITCOIN_QT_UTILITYDIALOG_H

#include <QDialog>
#include <QNetworkAccessManager>
#include <QUrl>
#include <QWidget>

QT_BEGIN_NAMESPACE
class QMainWindow;
QT_END_NAMESPACE

namespace Ui {
    class HelpMessageDialog;
}

/** "Help message" dialog box */
class HelpMessageDialog : public QDialog
{
    Q_OBJECT

public:
    explicit HelpMessageDialog(QWidget *parent, bool about);
    ~HelpMessageDialog();

    void printToConsole();
    void showOrPrint();

private:
    Ui::HelpMessageDialog *ui;
    QString text;

private Q_SLOTS:
    void on_okButton_accepted();
};

/** "Update wallet" dialog box */
class UpdateWalletDialog : public QDialog
{
    Q_OBJECT

public:
    const QUrl VERSION_URL = QUrl("http://electraprotocol.eu/getlatestversion");
    const std::string SIGNING_ADDR_HEX = "4030a4b91118ba1cef4e8ec02f78196f8ff83eef"; // PESag4Dpqxtwv9QW3UVVM95oPUEcjk9HJt

    explicit UpdateWalletDialog(QWidget *parent);
    ~UpdateWalletDialog();

    void checkForUpdate();

private:
    Ui::HelpMessageDialog *ui;
    QNetworkAccessManager *manager = nullptr;
    QNetworkReply *reply = nullptr;
    bool mandatoryUpdate = false;
    int newVersionMajor = 0;
    int newVersionMinor = 0;
    int newVersionRevision = 0;
    int newVersionBuild = 0;
    int newVersionRC = 0;

    void gotReply();
    QString getUpdateString();

private Q_SLOTS:
    void on_okButton_accepted();
};


/** "Shutdown" window */
class ShutdownWindow : public QWidget
{
    Q_OBJECT

public:
    explicit ShutdownWindow(QWidget *parent=nullptr, Qt::WindowFlags f=Qt::Widget);
    static QWidget* showShutdownWindow(QMainWindow* window);

protected:
    void closeEvent(QCloseEvent *event) override;
};

#endif // BITCOIN_QT_UTILITYDIALOG_H
