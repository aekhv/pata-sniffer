/****************************************************************************
**
** This file is part of the Parallel ATA Sniffer project.
** Copyright (C) 2025 Alexander E. <aekhv@vk.com>
** License: GNU GPL v2, see file LICENSE.
**
****************************************************************************/

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QFile>
#include <QMap>
#include "UsbSniffer/UsbSniffer.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void message(const QString &s);
    void lockInterface();
    void unlockInterface();
    void findLocation();
    void startPressed();
    void decodePressed();
    void exportPressed();
    void updateStatistics(quint32 bytesCommited, quint32 errorCount);
    void about();

signals:
    void start(const QString &path, int clkDiv);

private:
    Ui::MainWindow *ui;
    QThread *thread;
    UsbSniffer *sniffer;
    QMap<quint8, QString> ataCodes;

    QString ataStatus(quint8 status);
    QString ataError(quint8 error);
    QString ataCommand(quint8 command);
    void printHexData(QFile *file, int offset, int length);
    void loadAtaCommandCodes();
};

#pragma pack(push, 1)

typedef struct {
    quint16 data;
    quint8 address:5;
    quint8 unused1:3;
    quint8 dior:1;
    quint8 diow:1;
    quint8 unused2:6;
} sniffer_item_t;

static_assert(sizeof(sniffer_item_t) == 4, "Incorrect 'sniffer_item_t' size!");

#pragma pack(pop)

#endif // MAINWINDOW_H
