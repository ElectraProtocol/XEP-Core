// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/xep-config.h>
#endif

#include <qt/utilitydialog.h>

#include <qt/forms/ui_helpmessagedialog.h>

#include <qt/guiutil.h>

#include <clientversion.h>
#include <init.h>
#include <key_io.h>
#include <script/standard.h>
#include <uint256.h>
#include <util/message.h>
#include <util/system.h>
#include <util/strencodings.h>

#include <stdio.h>

#include <QCloseEvent>
#include <QDesktopServices>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QMainWindow>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegExp>
#include <QTextCursor>
#include <QTextTable>
#include <QUrl>
#include <QVBoxLayout>

/** "Help message" or "About" dialog box */
HelpMessageDialog::HelpMessageDialog(QWidget *parent, bool about) :
    QDialog(parent),
    ui(new Ui::HelpMessageDialog)
{
    ui->setupUi(this);

    QString version = QString{PACKAGE_NAME} + " " + tr("version") + " " + QString::fromStdString(FormatFullVersion());

    if (about)
    {
        setWindowTitle(tr("About %1").arg(PACKAGE_NAME));

        std::string licenseInfo = LicenseInfo();
        /// HTML-format the license message from the core
        QString licenseInfoHTML = QString::fromStdString(LicenseInfo());
        // Make URLs clickable
        QRegExp uri("<(.*)>", Qt::CaseSensitive, QRegExp::RegExp2);
        uri.setMinimal(true); // use non-greedy matching
        licenseInfoHTML.replace(uri, "<a href=\"\\1\">\\1</a>");
        // Replace newlines with HTML breaks
        licenseInfoHTML.replace("\n", "<br>");

        ui->aboutMessage->setTextFormat(Qt::RichText);
        ui->scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        text = version + "\n" + QString::fromStdString(FormatParagraph(licenseInfo));
        ui->aboutMessage->setText(version + "<br><br>" + licenseInfoHTML);
        ui->aboutMessage->setWordWrap(true);
        ui->helpMessage->setVisible(false);
    } else {
        setWindowTitle(tr("Command-line options"));
        QString header = "Usage:  xep-qt [command-line options]                     \n";
        QTextCursor cursor(ui->helpMessage->document());
        cursor.insertText(version);
        cursor.insertBlock();
        cursor.insertText(header);
        cursor.insertBlock();

        std::string strUsage = gArgs.GetHelpMessage();
        QString coreOptions = QString::fromStdString(strUsage);
        text = version + "\n\n" + header + "\n" + coreOptions;

        QTextTableFormat tf;
        tf.setBorderStyle(QTextFrameFormat::BorderStyle_None);
        tf.setCellPadding(2);
        QVector<QTextLength> widths;
        widths << QTextLength(QTextLength::PercentageLength, 35);
        widths << QTextLength(QTextLength::PercentageLength, 65);
        tf.setColumnWidthConstraints(widths);

        QTextCharFormat bold;
        bold.setFontWeight(QFont::Bold);

        for (const QString &line : coreOptions.split("\n")) {
            if (line.startsWith("  -"))
            {
                cursor.currentTable()->appendRows(1);
                cursor.movePosition(QTextCursor::PreviousCell);
                cursor.movePosition(QTextCursor::NextRow);
                cursor.insertText(line.trimmed());
                cursor.movePosition(QTextCursor::NextCell);
            } else if (line.startsWith("   ")) {
                cursor.insertText(line.trimmed()+' ');
            } else if (line.size() > 0) {
                //Title of a group
                if (cursor.currentTable())
                    cursor.currentTable()->appendRows(1);
                cursor.movePosition(QTextCursor::Down);
                cursor.insertText(line.trimmed(), bold);
                cursor.insertTable(1, 2, tf);
            }
        }

        ui->helpMessage->moveCursor(QTextCursor::Start);
        ui->scrollArea->setVisible(false);
        ui->aboutLogo->setVisible(false);
    }

    GUIUtil::handleCloseWindowShortcut(this);
}

HelpMessageDialog::~HelpMessageDialog()
{
    delete ui;
}

void HelpMessageDialog::printToConsole()
{
    // On other operating systems, the expected action is to print the message to the console.
    tfm::format(std::cout, "%s\n", qPrintable(text));
}

void HelpMessageDialog::showOrPrint()
{
#if defined(WIN32)
    // On Windows, show a message box, as there is no stderr/stdout in windowed applications
    exec();
#else
    // On other operating systems, print help text to console
    printToConsole();
#endif
}

void HelpMessageDialog::on_okButton_accepted()
{
    close();
}

/** "Update wallet" dialog box */
UpdateWalletDialog::UpdateWalletDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::HelpMessageDialog)
{
    ui->setupUi(this);
    manager = new QNetworkAccessManager(this);

    connect(manager, &QNetworkAccessManager::finished, [this]{ gotReply(); });
    connect(this, &QDialog::rejected, [this]{ on_okButton_accepted(); });

    setWindowTitle(tr("%1 update available").arg(PACKAGE_NAME));
    setWindowModality(Qt::ApplicationModal);

    ui->aboutMessage->setTextFormat(Qt::RichText);
    ui->scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    ui->aboutMessage->setText(getUpdateString());
    ui->aboutMessage->setWordWrap(true);
    ui->helpMessage->setVisible(false);

    GUIUtil::handleCloseWindowShortcut(this);
}

UpdateWalletDialog::~UpdateWalletDialog()
{
    delete ui;
    delete manager;
}

void UpdateWalletDialog::checkForUpdate()
{
    const QNetworkRequest request(VERSION_URL);
    reply = manager->get(request);
}

void UpdateWalletDialog::gotReply()
{
    if (!reply)
        return;

    // Data format:
    /*
    {
        "version_message":{
            "version_major":1,
            "version_minor":0,
            "version_revision":4,
            "version_build":0,
            "version_rc":0,
            "mandatory":false,
            "last_mandatory":{
                "version_major":1,
                "version_minor":0,
                "version_revision":3,
                "version_build":0,
                "version_rc":0
            }
        },
        "signature_base64":"IFEIcNVlQZ5TzzoQMI5Pa40NPNzK4jomkvRJE3OIpv9hEUorgTiNnXTQgpsgzUMPkHATErH7sWPJmt22Z8ymZ7Q="
    }
    */
    // The message signature ensures that the current version data has not been tampered with

    const QByteArray response_data = reply->readAll();
    reply->deleteLater();

    // Ensure json is in compact format for signature check
    const QByteArray compact_data = QString(response_data.simplified()).remove(QRegularExpression("(\r\n|\r|\n)|[ \t]")).toUtf8();
    const QJsonDocument jsonAnswer = QJsonDocument::fromJson(compact_data);

    if (!jsonAnswer.isObject())
        return;

    const QJsonObject &responseObject = jsonAnswer.object();

    const QString strVerMessage = "version_message";
    const QString strVerMajor = "version_major";
    const QString strVerMinor = "version_minor";
    const QString strVerRev = "version_revision";
    const QString strVerBuild = "version_build";
    const QString strVerRC = "version_rc";
    const QString strMandatory = "mandatory";
    const QString strLastMandatory = "last_mandatory";
    const QString strSignature = "signature_base64";

    const QString verMsgMatch = "\"" + strVerMessage + "\":";
    const QString sigMatch = ",\"" + strSignature + "\":\"";
    const int verMsgStart = compact_data.indexOf(verMsgMatch);
    const int sigStart = compact_data.indexOf(sigMatch);

    // Check that the json is well formatted (strVerMessage is present and comes before strSignature)
    if (responseObject.size() != 2 || !responseObject[strVerMessage].isObject() || !responseObject[strSignature].isString() || sigStart <= verMsgStart)
        return;

    const QJsonObject &versionMessage = responseObject[strVerMessage].toObject();
    const QString &versionSignature = responseObject[strSignature].toString();
    QByteArray versionMessageCompact = compact_data;
    versionMessageCompact.remove(0, verMsgStart + verMsgMatch.size()).chop(compact_data.size() - sigStart);

    // Check signature
    const std::string signingAddr = EncodeDestination(PKHash(uint160(ParseHex(SIGNING_ADDR_HEX))));
    if (MessageVerify(signingAddr, versionSignature.toStdString(), versionMessageCompact.toStdString()) != MessageVerificationResult::OK)
        return;

    // Check that the json is well formatted
    if (versionMessage.size() != 7 || !versionMessage[strVerMajor].isDouble() || !versionMessage[strVerMinor].isDouble() ||
        !versionMessage[strVerRev].isDouble() || !versionMessage[strVerBuild].isDouble() || !versionMessage[strVerRC].isDouble() ||
        !versionMessage[strMandatory].isBool() || !versionMessage[strLastMandatory].isObject())
        return;

    const QJsonObject &lastMandatory = versionMessage[strLastMandatory].toObject();

    // Check that the json is well formatted
    if (lastMandatory.size() != 5 || !lastMandatory[strVerMajor].isDouble() || !lastMandatory[strVerMinor].isDouble() ||
        !lastMandatory[strVerRev].isDouble() || !lastMandatory[strVerBuild].isDouble() || !lastMandatory[strVerRC].isDouble())
        return;

    bool outdated = true;
    mandatoryUpdate = true;

    newVersionMajor = versionMessage[strVerMajor].toInt();
    newVersionMinor = versionMessage[strVerMinor].toInt();
    newVersionRevision = versionMessage[strVerRev].toInt();
    newVersionBuild = versionMessage[strVerBuild].toInt();
    newVersionRC = versionMessage[strVerRC].toInt();

    const int lastMandatoryMajor = lastMandatory[strVerMajor].toInt();
    const int lastMandatoryMinor = lastMandatory[strVerMinor].toInt();
    const int lastMandatoryRevision = lastMandatory[strVerRev].toInt();
    const int lastMandatoryBuild = lastMandatory[strVerBuild].toInt();

    // Are we newer than the last mandatory version?
    if (lastMandatoryMajor < CLIENT_VERSION_MAJOR || (lastMandatoryMajor == CLIENT_VERSION_MAJOR && lastMandatoryMinor < CLIENT_VERSION_MINOR) ||
        (lastMandatoryMajor == CLIENT_VERSION_MAJOR && lastMandatoryMinor == CLIENT_VERSION_MINOR && lastMandatoryRevision < CLIENT_VERSION_REVISION) ||
        (lastMandatoryMajor == CLIENT_VERSION_MAJOR && lastMandatoryMinor == CLIENT_VERSION_MINOR && lastMandatoryRevision == CLIENT_VERSION_REVISION &&
         lastMandatoryBuild <= CLIENT_VERSION_BUILD)) {
        mandatoryUpdate = versionMessage[strMandatory].toBool();

        // Are we the newest version available?
        if (newVersionMajor < CLIENT_VERSION_MAJOR || (newVersionMajor == CLIENT_VERSION_MAJOR && newVersionMinor < CLIENT_VERSION_MINOR) ||
            (newVersionMajor == CLIENT_VERSION_MAJOR && newVersionMinor == CLIENT_VERSION_MINOR && newVersionRevision < CLIENT_VERSION_REVISION) ||
            (newVersionMajor == CLIENT_VERSION_MAJOR && newVersionMinor == CLIENT_VERSION_MINOR && newVersionRevision == CLIENT_VERSION_REVISION &&
             newVersionBuild <= CLIENT_VERSION_BUILD)) {
            outdated = false;
        }
    }

    // Not outdated, nothing to do
    if (!outdated)
        return;

    ui->aboutMessage->setText(getUpdateString());
    show();
}

QString UpdateWalletDialog::getUpdateString()
{

    QString oldVersion = tr("Old version") + " - " + QString{PACKAGE_NAME} + " " + tr("version") + " " + QString::fromStdString(FormatFullVersion());
    QString newVersion = tr("New version") + " - " + QString{PACKAGE_NAME} + " " + tr("version") + " v" + QString::number(newVersionMajor) + "." + QString::number(newVersionMinor) + "." + QString::number(newVersionRevision) + "." + QString::number(newVersionBuild) + (newVersionRC ? "rc" + QString::number(newVersionRC) : "");

    /// HTML-format the license message from the core
    QString updateString = tr("There is a new version of %1 available for download from %2.").arg(PACKAGE_NAME, "<" PACKAGE_URL ">") + "\n\n" + tr("Please update your wallet at your earliest convenience.") + " " + (mandatoryUpdate ? tr("This is a mandatory update.") : tr("This is an optional update."));
    // Make URLs clickable
    QRegExp uri("<(.*)>", Qt::CaseSensitive, QRegExp::RegExp2);
    uri.setMinimal(true); // use non-greedy matching
    updateString.replace(uri, "<a href=\"\\1\">\\1</a>");
    // Replace newlines with HTML breaks
    updateString.replace("\n", "<br>");

    return (oldVersion + "<br>" + newVersion + "<br><br>" + updateString);
}

void UpdateWalletDialog::on_okButton_accepted()
{
    close();

    if (mandatoryUpdate) {
        QDesktopServices::openUrl(QUrl(PACKAGE_URL));
        QApplication::quit();
    }
}


/** "Shutdown" window */
ShutdownWindow::ShutdownWindow(QWidget *parent, Qt::WindowFlags f):
    QWidget(parent, f)
{
    QVBoxLayout *layout = new QVBoxLayout();
    layout->addWidget(new QLabel(
        tr("%1 is shutting down...").arg(PACKAGE_NAME) + "<br /><br />" +
        tr("Do not shut down the computer until this window disappears.")));
    setLayout(layout);

    GUIUtil::handleCloseWindowShortcut(this);
}

QWidget* ShutdownWindow::showShutdownWindow(QMainWindow* window)
{
    assert(window != nullptr);

    // Show a simple window indicating shutdown status
    QWidget *shutdownWindow = new ShutdownWindow();
    shutdownWindow->setWindowTitle(window->windowTitle());

    // Center shutdown window at where main window was
    const QPoint global = window->mapToGlobal(window->rect().center());
    shutdownWindow->move(global.x() - shutdownWindow->width() / 2, global.y() - shutdownWindow->height() / 2);
    shutdownWindow->show();
    return shutdownWindow;
}

void ShutdownWindow::closeEvent(QCloseEvent *event)
{
    event->ignore();
}
