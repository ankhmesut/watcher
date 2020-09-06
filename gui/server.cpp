#include "server.h"

#include <QMessageBox>

Server::Server(QHostAddress addr, quint16 nPort)
  : m_nNextBlockSize(0)
{
    m_server = new QTcpServer(this);
    if (!m_server->listen(addr, nPort)) {
        QMessageBox::critical(nullptr,
                              "Server Error",
                              "Unable to start the server:"
                              + m_server->errorString()
                             );
        m_server->close();
        return;
    }
    connect(m_server, SIGNAL(newConnection()), this, SLOT(slotNewConnection()));
}

/*virtual*/ void Server::slotNewConnection()
{
    QTcpSocket* pClientSocket = m_server->nextPendingConnection();
    connect(pClientSocket, SIGNAL(disconnected()),
            pClientSocket, SLOT(deleteLater())
           );
    connect(pClientSocket, SIGNAL(readyRead()),
            this,          SLOT(slotReadClient())
           );

    qDebug() << "new conn" << pClientSocket->peerName();

    sendToClient(pClientSocket, "Server Response: Connected!");
}

void Server::slotReadClient()
{
    QTcpSocket* pClientSocket = (QTcpSocket*)sender();
    QDataStream in(pClientSocket);

    for (;;) {
        if (!m_nNextBlockSize) {
            if (pClientSocket->bytesAvailable() < sizeof(quint16)) {
                break;
            }
            in >> m_nNextBlockSize;
        }

        if (pClientSocket->bytesAvailable() < m_nNextBlockSize) {
            break;
        }
        QTime   time;
        QString str;
        in >> time >> str;

        QString strMessage =
            time.toString() + " " + "Client has sended - " + str;

        QMessageBox::information(nullptr, "", strMessage);

        m_nNextBlockSize = 0;

//        sendToClient(pClientSocket,
//                     "Server Response: Received \"" + str + "\""
//                    );
    }
}

void Server::sendToClient(QTcpSocket* pSocket, const QString& str)
{
    QByteArray  arrBlock;
    QDataStream out(&arrBlock, QIODevice::WriteOnly);

    out << quint16(0) << QTime::currentTime() << str;

    out.device()->seek(0);
    out << quint16(arrBlock.size() - sizeof(quint16));

    pSocket->write(arrBlock);
}
