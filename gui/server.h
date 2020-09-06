#ifndef SERVER_H
#define SERVER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include "common.h"

class Server : public QObject
{
    Q_OBJECT
private:
    QTcpServer* m_server;
    quint16     m_nNextBlockSize;

private:
    void sendToClient(QTcpSocket* pSocket, const QString& str);

public:
    Server(QHostAddress addr, quint16 nPort);

public slots:
    virtual void slotNewConnection();
            void slotReadClient();

signals:
    void fileAdded(FileEntry);
    void fileRemoved(FileEntry);
    void fileChanged(FileEntry);
};

#endif // SERVER_H
