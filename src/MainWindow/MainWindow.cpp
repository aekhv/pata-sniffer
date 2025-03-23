/****************************************************************************
**
** This file is part of the Parallel ATA Sniffer project.
** Copyright (C) 2025 Alexander E. <aekhv@vk.com>
** License: GNU GPL v2, see file LICENSE.
**
****************************************************************************/

#include "MainWindow.h"
#include "ui_MainWindow.h"
#include "AtaRegisters.h"
#include <QStandardPaths>
#include <QFileDialog>
#include <QDateTime>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    setWindowTitle("Parallel ATA sniffer");

    ui->startButton->setEnabled(false);
    ui->stopButton->setEnabled(false);

    thread = new QThread(this);
    sniffer = new UsbSniffer;
    sniffer->moveToThread(thread);

    connect(sniffer, &UsbSniffer::message, this, &MainWindow::message);
    connect(sniffer, &UsbSniffer::lockInterface, this, &MainWindow::lockInterface);
    connect(sniffer, &UsbSniffer::unlockInterface, this, &MainWindow::unlockInterface);
    connect(sniffer, &UsbSniffer::updateStatistics, this, &MainWindow::updateStatistics);
    connect(ui->findButton, &QPushButton::pressed, this, &MainWindow::findLocation);
    connect(ui->startButton, &QPushButton::pressed, this, &MainWindow::startPressed);
    connect(ui->stopButton, &QPushButton::pressed, sniffer, &UsbSniffer::stop, Qt::DirectConnection);
    connect(ui->decoderButton, &QPushButton::pressed, this, &MainWindow::decodePressed);
    connect(ui->exportButton, &QPushButton::pressed, this, &MainWindow::exportPressed);
    connect(this, &MainWindow::start, sniffer, &UsbSniffer::start);
    connect(thread, &QThread::started, sniffer, &UsbSniffer::init);
    connect(thread, &QThread::finished, sniffer, &UsbSniffer::deleteLater);
    connect(ui->actionExit, &QAction::triggered, this, &MainWindow::close);
    connect(ui->actionAbout, &QAction::triggered, this, &MainWindow::about);

    const QStringList docs = QStandardPaths::standardLocations(QStandardPaths::DocumentsLocation);
    ui->locationEdit->setText(docs.first());

    const QFont mono = QFont("Consolas", 9);
    ui->decoderTextEdit->setFont(mono);

    const QStringList list = QStringList() << "PIO0 (600 ns)" << "PIO1 (383 ns)" << "PIO2 (240 ns)" << "PIO3 (180 ns)" << "PIO4 (120 ns)";
    ui->comboBox->addItems(list);
    ui->comboBox->setCurrentIndex(list.size() - 1);
    ui->comboBox->setEnabled(false);

    loadAtaCommandCodes();

    thread->start();
}

MainWindow::~MainWindow()
{
    sniffer->stop();

    thread->exit();
    thread->wait();

    delete ui;
}

void MainWindow::message(const QString &s)
{
    ui->reportTextEdit->appendPlainText(s);
}

void MainWindow::lockInterface()
{
    ui->comboBox->setEnabled(false);
    ui->startButton->setEnabled(false);
    ui->stopButton->setEnabled(true);
}

void MainWindow::unlockInterface()
{
    ui->comboBox->setEnabled(true);
    ui->startButton->setEnabled(true);
    ui->stopButton->setEnabled(false);
}

void MainWindow::findLocation()
{
    const QStringList docs = QStandardPaths::standardLocations(QStandardPaths::DocumentsLocation);
    const QString dir = QFileDialog::getExistingDirectory(this,
                                                          "Find location",
                                                          docs.first());
    if (!dir.isEmpty())
        ui->locationEdit->setText(dir);
}

void MainWindow::startPressed()
{
    const QDateTime dt = QDateTime::currentDateTime();
    const QString path = QString("%1/capturing-%2.sniff")
                             .arg(ui->locationEdit->text())
                             .arg(dt.toString("yyyy.MM.dd-hh.mm.ss"));

    // Clock divider sets FX3 PIB frequency as (384.0 MHz / clkDiv)
    // The minimum value is 2, the maximum is 1024
    quint16 clkDiv;
    switch (ui->comboBox->currentIndex()) {
    case 0:
        // PIO mode 0, best values are 6...40,
        clkDiv = 24;
        break;
    case 1:
        // PIO mode 1, best values are 6...30
        clkDiv = 18;
        break;
    case 2:
        // PIO mode 2, best values are 6...18
        clkDiv = 12;
        break;
    case 3:
        // PIO mode 3, best values are 6...14
        clkDiv = 10;
        break;
    default:
        // PIO mode 4, best values are 6...9
        clkDiv = 8;
    }

    emit start(path, clkDiv);
}

void MainWindow::decodePressed()
{
    const QString path = QFileDialog::getOpenFileName(this,
                                                      "Open a file to decode",
                                                      ui->locationEdit->text(),
                                                      "Sniffer files (*.sniff);;All files (*.*)");
    if (path.isEmpty())
        return;

    ui->decoderTextEdit->clear();

    QTextCharFormat tf = ui->decoderTextEdit->currentCharFormat();

    QFile file(path);
    if (!file.open(QFile::ReadOnly)) {
        tf.setForeground(QBrush(QColor(Qt::black)));
        ui->decoderTextEdit->setCurrentCharFormat(tf);
        ui->decoderTextEdit->appendPlainText(QString("File opening error: %1\n%2")
                                            .arg(path)
                                            .arg(file.errorString()));
        return;
    }

    qint64 dataStart = -1; // Data flow beginning
    bool dataRead = true; // Data flow direction
    int lastAltStatusSample = -1; // Used to hide duplicate values of ALT_STATUS
    quint16 lastAltStatusValue = 0;
    int lastStatusSample = -1; // Used to hide duplicate values of STATUS
    quint16 lastStatusValue = 0;
    const int samplesCount = file.size() / sizeof(sniffer_item_t);

    for (int i = 0; i < samplesCount; i++) {

        // RAW data item
        sniffer_item_t item;
        if (file.read((char*)&item, sizeof(item)) != sizeof(item)) {
            tf.setForeground(QBrush(QColor(Qt::black)));
            ui->decoderTextEdit->setCurrentCharFormat(tf);
            ui->decoderTextEdit->appendPlainText("File reading error!");
            break;
        }

        // DIOR and DIOW must be different
        if (item.dior == item.diow) {
            tf.setForeground(QBrush(QColor(Qt::black)));
            ui->decoderTextEdit->setCurrentCharFormat(tf);
            ui->decoderTextEdit->appendPlainText(QString("%1: INCORRECT STATE!")
                                                     .arg(i, 8, 16, QChar('0')));
            continue;
        }

        // Current data direction
        const bool read = !item.dior;

        // ATA register
        QString s;
        switch (item.address) {
        case ATA_REG_ALT_STATUS:
            if (read)
                s = QString("ALT_STATUS [ %1 ]").arg(ataStatus(item.data));
            else
                s = "DEVICE_CONTROL";
            break;
        case ATA_REG_STATUS:
            if (read)
                s = QString("STATUS     [ %1 ]").arg(ataStatus(item.data));
            else
                s = QString("COMMAND (%1)").arg(ataCommand(item.data));
            break;
        case ATA_REG_ERROR:
            if (read)
                s = QString("ERROR      [ %1 ]").arg(ataError(item.data));
            else
                s = "FEATURES";
            break;
        case ATA_REG_DATA:
            s = "DATA";
            break;
        case ATA_REG_SECTOR_COUNT:
            s = "SECTOR_COUNT";
            break;
        case ATA_REG_LBA_LOW:
            s = "LBA_LOW";
            break;
        case ATA_REG_LBA_MID:
            s = "LBA_MID";
            break;
        case ATA_REG_LBA_HIGH:
            s = "LBA_HIGH";
            break;
        case ATA_REG_LBA_DEVICE:
            s = "LBA_DEVICE";
            break;
        default: s = QString("UNKNOWN REGISTER (0x%1)").arg(item.address, 2, 16, QChar('0'));
        }

        // Hide duplicate values of ATA_REG_ALT_STATUS
        if ((item.address == (ATA_REG_ALT_STATUS)) && (item.dior == 0)) {
            if ((item.data == lastAltStatusValue)
                && (i == (lastAltStatusSample + 1))) {
                lastAltStatusSample = i;
                continue;
            } else {
                lastAltStatusValue = item.data;
                lastAltStatusSample = i;
            }
        }

        // Hide duplicate values of ATA_REG_STATUS
        if ((item.address == (ATA_REG_STATUS)) && (item.dior == 0)) {
            if ((item.data == lastStatusValue)
                && (i == (lastStatusSample + 1))) {
                lastStatusSample = i;
                continue;
            } else {
                lastStatusValue = item.data;
                lastStatusSample = i;
            }
        }

        // Data begins
        if ((item.address == (ATA_REG_DATA)) && (dataStart == -1)) {
            dataRead = read;
            dataStart = i;
        }

        // Data ended
        if ((item.address != (ATA_REG_DATA)) && (dataStart != -1)) {
            const QColor c = dataRead ? Qt::blue : Qt::red;
            tf.setForeground(QBrush(c));
            ui->decoderTextEdit->setCurrentCharFormat(tf);
            ui->decoderTextEdit->appendPlainText(QString("%1: [....] %2 PIO data %3 (%4 bytes)")
                                                     .arg(dataStart, 8, 16, QChar('0'))
                                                     .arg(dataRead ? "<<" : ">>")
                                                     .arg(dataRead ? "read" : "write")
                                                     .arg((i - dataStart) * 2));
            printHexData(&file, dataStart, i - dataStart);
            file.seek((i + 1) * sizeof(sniffer_item_t));
            dataStart = -1;
        }

        // Data ended & end of the file
        if ((dataStart != -1) && (i == (samplesCount - 1))) {
            const QColor c = dataRead ? Qt::blue : Qt::red;
            tf.setForeground(QBrush(c));
            ui->decoderTextEdit->setCurrentCharFormat(tf);
            ui->decoderTextEdit->appendPlainText(QString("%1: [....] %2 PIO data %3 (%4 bytes)")
                                                     .arg(dataStart, 8, 16, QChar('0'))
                                                     .arg(dataRead ? "<<" : ">>")
                                                     .arg(dataRead ? "read" : "write")
                                                     .arg((i - dataStart + 1) * 2));
            printHexData(&file, dataStart, i - dataStart + 1);
        }


        if (dataStart == -1) {
            QString ascii = ".";
            if (((item.data & 0x00ff) >= 0x20) && ((item.data & 0x00ff) <= 0x7e))
                ascii = QChar(item.data & 0x00ff);

            QColor color = read ? Qt::blue : Qt::red;

            if (read) {
                if ((item.address ==(ATA_REG_ALT_STATUS)) ||
                    (item.address == (ATA_REG_STATUS)))
                    color = Qt::darkGreen;
                if (item.address ==(ATA_REG_ERROR))
                    color = Qt::darkMagenta;
            }

            tf.setForeground(QBrush(color));
            ui->decoderTextEdit->setCurrentCharFormat(tf);
            ui->decoderTextEdit->appendPlainText(QString("%1: [%2|%3] %4 %5")
                                                     .arg(i, 8, 16, QChar('0'))
                                                     .arg(item.data & 0xff, 2, 16, QChar('0'))
                                                     .arg(ascii)
                                                     .arg(read ? "<<" : ">>")
                                                     .arg(s));
        }
    }

    file.close();
}

void MainWindow::exportPressed()
{
    const QString path = QFileDialog::getSaveFileName(this,
                                                      "Export to HTML",
                                                      ui->locationEdit->text(),
                                                      "HTML files (*.html);;All files (*.*)");
    if (path.isEmpty())
        return;

    QFile file(path);

    if (!file.open(QFile::WriteOnly))
        return;

    QTextDocument *doc = ui->decoderTextEdit->document();

    file.write(doc->toHtml().toUtf8());
    file.close();
}

void MainWindow::updateStatistics(quint32 bytesCommited, quint32 errorCount)
{
    ui->statisticsLabel->setText(QString("<b>Samples collected: %1, error count: %2</b>")
                                     .arg(bytesCommited / sizeof(sniffer_item_t)).arg(errorCount));
}

void MainWindow::about()
{
    QMessageBox::information(this, "About",
                             "<b>Parallel ATA sniffer 1.0</b><br><br>"
                             "Copyright (C) 2025 by Alexander E. &lt;aekhv@vk.com&gt;<br>"
                             "<a href=https://github.com/aekhv/pata-sniffer>https://github.com/aekhv/pata-sniffer</a>");
}

QString MainWindow::ataStatus(quint8 status)
{
    QStringList list = {"BSY", "DRD", "DWF", "DSC", "DRQ", "CRR", "IDX", "ERR"};
    QString s;

    quint16 n = 0x80;
    for (int i = 0; i < list.count(); ++i) {
        s.append(QString("%1 ").arg( (status & n) ? list.at(i) : "---" ));
        n /= 2;
    }

    return s.trimmed();
}

QString MainWindow::ataError(quint8 error)
{
    QStringList list = {"BBK", "UNC", "MCD", "INF", "MCR", "ABR", "T0N", "AMN"};
    QString s;

    quint16 n = 0x80;
    for (int i = 0; i < list.count(); ++i) {
        s.append(QString("%1 ").arg( (error & n) ? list.at(i) : "---" ));
        n /= 2;
    }

    return s.trimmed();
}

QString MainWindow::ataCommand(quint8 command)
{
    if (ataCodes.contains(command))
        return ataCodes.value(command);
    else
        return "UNKNOWN";
}

void MainWindow::printHexData(QFile *file, int offset, int length)
{
    sniffer_item_t item;
    file->seek(offset * sizeof(item));

    QString s;
    QString ascii;

    for (int i = 0; i < length; i += 8)
    {
        s.clear();
        s.append(QString("    %1: ").arg(i * 2, 4, 16, QChar('0')));

        ascii.clear();
        for (int j = 0; j < 8; j++) {

            if ((i + j) >= length)
                continue;

            file->read((char*)&item, sizeof(item));
            s.append(QString("%1 ").arg(item.data & 0x00ff, 2, 16, QChar('0')));
            s.append(QString("%1 ").arg(item.data >> 8, 2, 16, QChar('0')));

            QString lo = ".";
            if (((item.data & 0x00ff) >= 0x20) && ((item.data & 0x00ff) <= 0x7e))
                lo = QChar(item.data & 0x00ff);
            ascii.append(lo);

            QString hi = ".";
            if (((item.data >> 8) >= 0x20) && ((item.data >> 8) <= 0x7e))
                hi = QChar(item.data >> 8);
            ascii.append(hi);

        }

        ui->decoderTextEdit->appendPlainText(QString("%1| %2").arg(s).arg(ascii));
    }
}

void MainWindow::loadAtaCommandCodes()
{
    QFile file("AtaCommandCodes.txt");

    if (!file.open(QFile::ReadOnly | QFile::Text)) {
        ui->reportTextEdit->appendPlainText(QString("File opening error: %1").arg(file.fileName()));
        return;
    }

    while (!file.atEnd()) {
        const QString line = file.readLine();
        const QStringList list = line.split(QChar('='));
        if (list.length() < 2)
            continue;
        bool ok = false;
        const quint8 key = list.at(0).trimmed().toUShort(&ok, 16);
        if (!ok)
            continue;
        const QString value = list.at(1).trimmed();
        if (!ataCodes.contains(key))
            ataCodes.insert(key, value);
    }

    file.close();
}
