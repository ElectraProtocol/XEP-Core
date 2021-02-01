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
#include <util/system.h>
#include <util/strencodings.h>

#include <stdio.h>

#include <QCloseEvent>
#include <QLabel>
#include <QMainWindow>
#include <QRegExp>
#include <QTextCursor>
#include <QTextTable>
#include <QVBoxLayout>
#include <QNetworkRequest>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDesktopServices>

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
    const QUrl strVerUrl = QUrl("http://electraprotocol.eu/getlatestversion");

    const QNetworkRequest request(strVerUrl);
    reply = manager->get(request);
}

void UpdateWalletDialog::gotReply()
{
    if (reply) {
        const QByteArray response_data = reply->readAll();
        delete reply;
        const QJsonDocument jsonAnswer = QJsonDocument::fromJson(response_data);
        if (jsonAnswer.isObject()) {
            const QJsonObject &responseObject = jsonAnswer.object();

            const QString strVerMajor = "version_major";
            const QString strVerMinor = "version_minor";
            const QString strVerRev = "version_revision";
            const QString strVerBuild = "version_build";
            const QString strVerRC = "version_rc";
            const QString strMandatory = "mandatory";
            const QString strLastMandatory = "lastmandatory";

            if (responseObject.size() == 7 && responseObject[strVerMajor].isDouble() && responseObject[strVerMinor].isDouble() &&
                responseObject[strVerRev].isDouble() && responseObject[strVerBuild].isDouble() && responseObject[strVerRC].isDouble() &&
                responseObject[strMandatory].isBool() && responseObject[strLastMandatory].isObject()) {
                const QJsonObject &lastMandatory = responseObject[strLastMandatory].toObject();
                if (lastMandatory.size() == 5 && lastMandatory[strVerMajor].isDouble() && lastMandatory[strVerMinor].isDouble() &&
                    lastMandatory[strVerRev].isDouble() && lastMandatory[strVerBuild].isDouble() && lastMandatory[strVerRC].isDouble()) {
                    bool outdated = true;
                    mandatoryUpdate = true;

                    newVersionMajor = responseObject[strVerMajor].toInt();
                    newVersionMinor = responseObject[strVerMinor].toInt();
                    newVersionRevision = responseObject[strVerRev].toInt();
                    newVersionBuild = responseObject[strVerBuild].toInt();
                    newVersionRC = responseObject[strVerRC].toInt();
                    if (lastMandatory[strVerMajor].toInt() <= CLIENT_VERSION_MAJOR && lastMandatory[strVerMinor].toInt() <= CLIENT_VERSION_MINOR && lastMandatory[strVerRev].toInt() <= CLIENT_VERSION_REVISION && lastMandatory[strVerBuild].toInt() <= CLIENT_VERSION_BUILD) {
                        mandatoryUpdate = responseObject[strMandatory].toBool();
                        if (newVersionMajor <= CLIENT_VERSION_MAJOR && newVersionMinor <= CLIENT_VERSION_MINOR && newVersionRevision <= CLIENT_VERSION_REVISION && newVersionBuild <= CLIENT_VERSION_BUILD) {
                            outdated = false;
                        }
                    }

                    if (outdated) {
                        ui->aboutMessage->setText(getUpdateString());
                        exec();
                    }
                }
            }
        }
    }
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
