#ifndef COMMON_H
#define COMMON_H

#include <QObject>
#include <QString>
#include <QDateTime>

struct FileEntry
{
    QString name;
    QDateTime modified;
    quint32 size;
};

Q_DECLARE_METATYPE(FileEntry)

extern QHash<QString, FileEntry> fileEntries;

#endif // COMMON_H
