#include "mainwindow.h"
#include "common.h"
#include "server.h"
#include <QHostAddress>

#include <QApplication>

// global for simplicity
QHash<QString, FileEntry> fileEntries;

int main(int argc, char *argv[])
{
    qRegisterMetaType<FileEntry>();

    QApplication a(argc, argv);

    Server(QHostAddress("192.168.0.102"), 8888);

    MainWindow w;
    w.show();
    return a.exec();
}
