// Copyright (c) 2021 The XEP Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/applocker.h>
#include <qt/forms/ui_applocker.h>

#include <crypto/pbkdf2_hmac.h>

AppLocker::AppLocker(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::AppLocker)
{
    ui->setupUi(this);
    this->setWindowTitle(tr("Wallet locker"));
    this->setWindowModality(Qt::ApplicationModal);
    QRegExpValidator *validatorReg = new QRegExpValidator(QRegExp("[1-9]\\d{5,9}"), this);

    // Lock view (index 1)
    ui->stackedWidget->setCurrentIndex(1);
    ui->headLabel->setText(tr("Set a PIN to lock your wallet:") + "<br>");
    ui->messageLabel->setText("<br>- " + tr("Your PIN must be at least 6 digits long.") +
                              "<br>- " + tr("The PIN is only valid for this session."));
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Lock"));
    ui->buttonBox->button(QDialogButtonBox::Ok)->setDefault(true);
    ui->buttonBox->button(QDialogButtonBox::Cancel)->setAutoDefault(true);
    ui->pinLineEdit->setValidator(validatorReg);
    ui->pinLineEdit->setEchoMode(QLineEdit::Password);
    ui->confirmLineEdit->setValidator(validatorReg);
    ui->confirmLineEdit->setEchoMode(QLineEdit::Password);

    // Unlock view
    ui->lockLabel->setText(tr("Your wallet is locked.") + "<br>");
    ui->unlocklabel->setText(tr("PIN"));
    ui->unlockLineEdit->setValidator(validatorReg);
    ui->unlockLineEdit->setEchoMode(QLineEdit::Password);

    connect(ui->unlockLineEdit, &QLineEdit::textChanged, [this] {
        if (ui->unlockLineEdit->text().size() >= 6) {
            ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
        } else if (ui->stackedWidget->currentIndex() == 0) {
            ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
        }
    });
    connect(ui->pinLineEdit, &QLineEdit::returnPressed, ui->buttonBox, &QDialogButtonBox::accepted);
    connect(ui->confirmLineEdit, &QLineEdit::returnPressed, ui->buttonBox, &QDialogButtonBox::accepted);
    connect(ui->unlockLineEdit, &QLineEdit::returnPressed, ui->buttonBox, &QDialogButtonBox::accepted);
    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &AppLocker::setLock);
    connect(ui->buttonBox, &QDialogButtonBox::rejected, this, &AppLocker::close);
}

AppLocker::~AppLocker()
{
    delete ui;
}

void AppLocker::setLock()
{
    switch (ui->stackedWidget->currentIndex()) {
    case 0:
        if (pbkdf2_hmac_sha256_time_check(reinterpret_cast<const unsigned char*>(ui->unlockLineEdit->text().toUtf8().constData()), ui->unlockLineEdit->text().size(), reinterpret_cast<const unsigned char*>(salt.constData()), salt.size(), 3, pinHash)) {
            walletLocked = false;
            secureClearPinFields();
            ui->stackedWidget->setCurrentIndex(1);
            ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Lock"));
            ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
            ui->buttonBox->button(QDialogButtonBox::Cancel)->setEnabled(true);
            ui->buttonBox->button(QDialogButtonBox::Cancel)->setVisible(true);
            ui->pinLineEdit->setFocus();
            Q_EMIT lockingApp(false);
        } else {
            QMessageBox::warning(this, tr("Error"), tr("The entered PIN is incorrect."), QMessageBox::Ok);
        }
        break;
    case 1:
        if (ui->pinLineEdit->text().isEmpty() || ui->confirmLineEdit->text().isEmpty()) {
            QMessageBox::information(this, tr("Error"), tr("Please enter and confirm your PIN."), QMessageBox::Ok);
        } else if (ui->pinLineEdit->text().size() < 6 || ui->confirmLineEdit->text().size() < 6) {
            QMessageBox::information(this, tr("Error"), tr("Your PIN must be at least 6 digits long."), QMessageBox::Ok);
        } else if (ui->pinLineEdit->text() != ui->confirmLineEdit->text()) {
            QMessageBox::warning(this, tr("Error"), tr("The entered PINs don't match, please try again."), QMessageBox::Ok);
        } else {
            walletLocked = true;
            salt = QString::number(QDateTime::currentMSecsSinceEpoch()).toUtf8();
            // pinHash = QPasswordDigestor::deriveKeyPbkdf2(QCryptographicHash::Sha256, ui->pinLineEdit->text().toUtf8(), salt, 10000, quint64(32));
            pbkdf2_hmac_sha256_time(reinterpret_cast<const unsigned char*>(ui->pinLineEdit->text().toUtf8().constData()), ui->pinLineEdit->text().size(), reinterpret_cast<const unsigned char*>(salt.constData()), salt.size(), 1, pinHash);
            secureClearPinFields();
            ui->stackedWidget->setCurrentIndex(0); // move to unlock view
            ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Unlock"));
            ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
            ui->buttonBox->button(QDialogButtonBox::Cancel)->setEnabled(false);
            ui->buttonBox->button(QDialogButtonBox::Cancel)->setVisible(false);
            ui->unlockLineEdit->setFocus();
            Q_EMIT lockingApp(true);
        }
        break;
    }
}

void AppLocker::showLocker()
{
    this->move(QGuiApplication::primaryScreen()->geometry().center() - this->rect().center());
    if (ui->stackedWidget->currentIndex() == 1) {
        ui->pinLineEdit->setFocus();
    }
    this->show();
    this->setFixedSize(this->size());
}

void AppLocker::closeEvent(QCloseEvent *event)
{
    if (walletLocked) {
        int ret = -1;
        if (!forceClose) {
            ret = QMessageBox::warning(this, tr("Warning"), tr("The wallet application will exit, would you like to continue?"), QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Cancel);
            if (ret == QMessageBox::Cancel) {
                event->ignore();
            }
        }
        if (forceClose || ret == QMessageBox::Ok) {
            // Clear memory being used by app locker
            secureClearPinFields();
            Q_EMIT quitAppFromWalletLocker();
            event->accept();
        }
    } else if (ui->stackedWidget->currentIndex() == 1) {
        // Clear memory being used by app locker
        secureClearPinFields();
        event->accept();
    } else {
        event->ignore();
    }
}

void AppLocker::secureClearPinFields()
{
    // Overwrite text so that it does not remain in memory
    ui->unlockLineEdit->setText(QString(" ").repeated(ui->unlockLineEdit->text().size()));
    ui->pinLineEdit->setText(QString(" ").repeated(ui->pinLineEdit->text().size()));
    ui->confirmLineEdit->setText(QString(" ").repeated(ui->confirmLineEdit->text().size()));
    ui->unlockLineEdit->clear();
    ui->pinLineEdit->clear();
    ui->confirmLineEdit->clear();
}
