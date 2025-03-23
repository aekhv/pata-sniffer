/****************************************************************************
**
** This file is part of the Parallel ATA Sniffer project.
** Copyright (C) 2025 Alexander E. <aekhv@vk.com>
** License: GNU GPL v2, see file LICENSE.
**
****************************************************************************/

#include "MainWindow/MainWindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setWindowIcon(QIcon(":/icons/app.ico"));

    MainWindow w;
    w.show();

    return app.exec();
}
