/****************************************************************************
**
** This file is part of the Parallel ATA Sniffer project.
** Copyright (C) 2025 Alexander E. <aekhv@vk.com>
** License: GNU GPL v2, see file LICENSE.
**
****************************************************************************/

#ifndef USBSNIFFER_H
#define USBSNIFFER_H

#include <QObject>
#include <libusb.h>

#define CY_FX_USB_VID           (0x04B4)
#define CY_FX_USB_PID           (0x0101)
#define CY_FX_EP_CONSUMER       (0x81)
#define CY_FX_VENDOR_REQUEST    (0xFF)
#define DEFAULT_USB_TIMEOUT     (1000) /* 1000 ms */
#define DEFAULT_BUFFER_SIZE     (65536)

typedef struct {
    quint32 errorCount;
    quint32 bytesCommited;
} status_t;

class UsbSniffer : public QObject
{
    Q_OBJECT
public:
    explicit UsbSniffer(QObject *parent = nullptr);
    ~UsbSniffer();
    void init();

public slots:
    void start(const QString &path, int clkDiv);
    void stop() { cancel = true; }

signals:
    void message(const QString &s);
    void lockInterface();
    void unlockInterface();
    void updateStatistics(quint32 bytesCommited, quint32 errorCount);

private:
    libusb_context *ctx;
    libusb_device_handle *handle;
    volatile bool cancel;
    bool readBulkData(char *data, int length);
};

#endif // USBSNIFFER_H
