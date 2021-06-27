// Copyright (c) 2021 The XEP Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef APPLOCKER_H
#define APPLOCKER_H

#include <QCloseEvent>
#include <QDateTime>
#include <QDesktopWidget>
#include <QMessageBox>
//#include <QPasswordDigestor>
#include <QPushButton>
#include <QRegExpValidator>
#include <QScreen>
#include <QWidget>

QT_BEGIN_NAMESPACE
namespace Ui {
    class AppLocker;
}
QT_END_NAMESPACE

class AppLocker : public QWidget
{
    Q_OBJECT

public:
    AppLocker(QWidget *parent);
    bool isWalletLocked() { return walletLocked; }
    void forceShutdown() { forceClose = true; }
    ~AppLocker();

private:
    Ui::AppLocker *ui;
    unsigned char pinHash[32]; // A SHA256 hash requires 32 bytes to store
    QByteArray salt;

    bool walletLocked = false;
    bool forceClose = false;
    void setLock();
    void secureClearPinFields();

Q_SIGNALS:
    void lockingApp(bool);
    void quitAppFromWalletLocker();

public Q_SLOTS:
    void showLocker();

protected:
    void closeEvent(QCloseEvent *event) override;
};

#endif // APPLOCKER_H
