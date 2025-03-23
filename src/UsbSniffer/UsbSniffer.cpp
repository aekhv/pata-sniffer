/****************************************************************************
**
** This file is part of the Parallel ATA Sniffer project.
** Copyright (C) 2025 Alexander E. <aekhv@vk.com>
** License: GNU GPL v2, see file LICENSE.
**
****************************************************************************/

#include "UsbSniffer.h"
#include <QFile>

UsbSniffer::UsbSniffer(QObject *parent)
    : QObject(parent),
    ctx(nullptr),
    handle(nullptr)
{

}

UsbSniffer::~UsbSniffer()
{
    if (handle)
        libusb_close(handle);

    if (ctx)
        libusb_exit(ctx);
}

void UsbSniffer::init()
{
    // Init library
    int err = libusb_init(&ctx);
    if (err < 0) {
        emit message(QString("FAIL on 'libusb_init'! ( %1 )")
                         .arg(libusb_error_name(err)));
        return;
    }

    // Printing lib version
    const struct libusb_version *v;
    v = libusb_get_version();
    emit message(QString("LibUSB %1.%2.%3.%4")
                     .arg(v->major)
                     .arg(v->minor)
                     .arg(v->micro)
                     .arg(v->nano));

    // Getting device list
    ssize_t cnt;
    libusb_device **dev_list;
    cnt = libusb_get_device_list(ctx, &dev_list);
    if (cnt < 0) {
        emit message(QString("FAIL on 'libusb_get_device_list'! ( %1 )")
                         .arg(libusb_error_name(cnt)));
        return;
    }

    // Searching for device
    int n = -1;
    struct libusb_device_descriptor dev_desc;
    for (int i = 0; dev_list[i]; i++) {
        err = libusb_get_device_descriptor(dev_list[i], &dev_desc);
        if (err != LIBUSB_SUCCESS) {
            emit message(QString("FAIL on 'libusb_get_device_descriptor'! ( %1 )")
                             .arg(libusb_error_name(err)));
            continue;
        }
        if ((dev_desc.idVendor == CY_FX_USB_VID) && (dev_desc.idProduct == CY_FX_USB_PID)) {
            emit message(QString("Sniffer device found: VID_0x%1&PID_0x%2 USB %3.%4 REV %5.%6")
                             .arg(dev_desc.idVendor, 4, 16, QChar('0'))
                             .arg(dev_desc.idProduct, 4, 16, QChar('0'))
                             .arg((dev_desc.bcdUSB & 0x0f00) >> 8)
                             .arg((dev_desc.bcdUSB & 0x00f0) >> 4)
                             .arg(dev_desc.bcdDevice >> 8)
                             .arg(dev_desc.bcdDevice & 0xFF));
            n = i;
            break;
        }
    }

    // Check if device not found
    if (n == -1) {
        emit message("Sniffer device not found!");
        libusb_free_device_list(dev_list, 1);
        return;
    }

    // Opening the device
    err = libusb_open(dev_list[n], &handle);
    if (err != LIBUSB_SUCCESS) {
        emit message(QString("FAIL on 'libusb_open'! ( %1 )")
                         .arg(libusb_error_name(err)));
        libusb_free_device_list(dev_list, 1);
        return;
    }

    err = libusb_claim_interface(handle, 0);
    if (err != LIBUSB_SUCCESS) {
        emit message(QString("FAIL on 'libusb_claim_interface'! ( %1 )")
                         .arg(libusb_error_name(err)));
        libusb_free_device_list(dev_list, 1);
        return;
    }

    libusb_free_device_list(dev_list, 1);
    emit unlockInterface();
}

void UsbSniffer::start(const QString &path, int clkDiv)
{
    QFile file(path);

    if (!file.open(QFile::WriteOnly)) {
        emit message(QString("File opening error: %1\n%2")
                         .arg(path)
                         .arg(file.errorString()));
        return;
    }

    emit lockInterface();
    emit message(QString("File opened: %1")
                     .arg(path));
    emit updateStatistics(0, 0);

    int err;

    // Sniffer start (wValue > 0)
    err = libusb_control_transfer(handle,
                                  LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_INTERFACE,
                                  CY_FX_VENDOR_REQUEST, // bRequest
                                  clkDiv,               // wValue
                                  0,                    // wIndex
                                  nullptr,              // Buffer to send or receive
                                  0,                    // Buffer length
                                  DEFAULT_USB_TIMEOUT);

    if (err < 0) {
        file.close();
        emit message(QString("FAIL on 'libusb_control_transfer'0! ( %1 )")
                         .arg(libusb_error_name(err)));
        emit unlockInterface();
        return;
    }

    cancel = false;
    status_t status = {0, 0};
    quint32 bytesCommited = 0;
    QByteArray buffer(DEFAULT_BUFFER_SIZE, 0);

    while (!cancel) {

        // Sniffer status
        err = libusb_control_transfer(handle,
                                      LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_INTERFACE,
                                      CY_FX_VENDOR_REQUEST, // bRequest
                                      0,                    // wValue
                                      0,                    // wIndex
                                      (uchar*)&status,      // Buffer to send or receive
                                      sizeof(status),       // Buffer length
                                      DEFAULT_USB_TIMEOUT);

        if (err < 0) {
            file.close();
            emit message(QString("FAIL on 'libusb_control_transfer'1! ( %1, %2 )")
                             .arg(libusb_error_name(err)).arg(err));
            emit unlockInterface();
            return;
        }

        if (status.errorCount > 0) {
            file.close();
            emit updateStatistics(status.bytesCommited, status.errorCount);
            emit message("Sniffer device error detected.");
            emit unlockInterface();
            return;
        }

        // Receive raw data
        if (status.bytesCommited > bytesCommited) {
            if (!readBulkData(buffer.data(), status.bytesCommited - bytesCommited)) {
                file.close();
                emit unlockInterface();
                return;
            }
            file.write(buffer.data(), status.bytesCommited - bytesCommited);
            bytesCommited = status.bytesCommited;
            emit updateStatistics(status.bytesCommited, status.errorCount);
        }

    }

    // Sniffer stop (wValue = 0)
    err = libusb_control_transfer(handle,
                                  LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_INTERFACE,
                                  CY_FX_VENDOR_REQUEST, // bRequest
                                  0,                    // wValue
                                  0,                    // wIndex
                                  nullptr,              // Buffer to send or receive
                                  0,                    // Buffer length
                                  DEFAULT_USB_TIMEOUT);

    if (err < 0) {
        file.close();
        emit message(QString("FAIL on 'libusb_control_transfer'2! ( %1 )")
                         .arg(libusb_error_name(err)));
        emit unlockInterface();
        return;
    }

    // Sniffer status
    err = libusb_control_transfer(handle,
                                  LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_INTERFACE,
                                  CY_FX_VENDOR_REQUEST, // bRequest
                                  0,                    // wValue
                                  0,                    // wIndex
                                  (uchar*)&status,      // Buffer to send or receive
                                  sizeof(status),       // Buffer length
                                  DEFAULT_USB_TIMEOUT);

    if (err < 0) {
        file.close();
        emit message(QString("FAIL on 'libusb_control_transfer'3! ( %1, %2 )")
                         .arg(libusb_error_name(err)).arg(err));
        emit unlockInterface();
        return;
    }

    if (status.errorCount > 0) {
        file.close();
        emit updateStatistics(status.bytesCommited, status.errorCount);
        emit message("Sniffer device error detected.");
        emit unlockInterface();
        return;
    }

    // Receive last part of raw data
    if (status.bytesCommited > bytesCommited) {
        if (!readBulkData(buffer.data(), status.bytesCommited - bytesCommited)) {
            file.close();
            emit unlockInterface();
            return;
        }
        file.write(buffer.data(), status.bytesCommited - bytesCommited);
        emit updateStatistics(status.bytesCommited, status.errorCount);
    }

    file.close();
    emit message("Completed.");
    emit unlockInterface();
}

bool UsbSniffer::readBulkData(char *data, int length)
{
    int bytesRead = 0;

    while (bytesRead < length) {

        int br = 0;
        int err = libusb_bulk_transfer(handle,
                                       CY_FX_EP_CONSUMER,
                                       (uchar*)data + bytesRead,
                                       length - bytesRead,
                                       &br,
                                       DEFAULT_USB_TIMEOUT);

        if (err < 0) {
            emit message(QString("FAIL on 'libusb_bulk_transfer'! ( %1 )")
                             .arg(libusb_error_name(err)));
            return false;
        }

        bytesRead += br;

        if (bytesRead < length)
            emit message(QString("Warning: %1 of %2 bytes received!")
                             .arg(br)
                             .arg(length - bytesRead));

    }

    return true;
}
