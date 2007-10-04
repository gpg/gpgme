/*
  Copyright (C) 2007 Klarälvdalens Datakonsult AB

  KDPipeIODevice is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  KDPipeIODevice is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Library General Public License for more details.

  You should have received a copy of the GNU Library General Public License
  along with KDPipeIODevice; see the file COPYING.LIB.  If not, write to the
  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

#ifndef __KDTOOLSCORE_KDPIPEIODEVICE_H__
#define __KDTOOLSCORE_KDPIPEIODEVICE_H__

#include <QIODevice>

#include <utility>

//#include "checker.h"

namespace _gpgme_ {

class KDPipeIODevice : public QIODevice {
    Q_OBJECT
    //KDAB_MAKE_CHECKABLE( KDPipeIODevice )
public:
    explicit KDPipeIODevice( QObject * parent=0 );
    explicit KDPipeIODevice( int fd, OpenMode=ReadOnly, QObject * parent=0 );
    explicit KDPipeIODevice( Qt::HANDLE handle, OpenMode=ReadOnly, QObject * parent=0 );
    ~KDPipeIODevice();

    static std::pair<KDPipeIODevice*, KDPipeIODevice*> makePairOfConnectedPipes();

    bool open( int fd, OpenMode mode=ReadOnly );
    bool open( Qt::HANDLE handle, OpenMode mode=ReadOnly );

    Qt::HANDLE handle() const;
    int descriptor() const;

    bool readWouldBlock() const;
    bool writeWouldBlock() const;

    /* reimp */ qint64 bytesAvailable() const;
    /* reimp */ qint64 bytesToWrite() const;
    /* reimp */ bool canReadLine() const;
    /* reimp */ void close();
    /* reimp */ bool isSequential() const;
    /* reimp */ bool atEnd() const;

    /* reimp */ bool waitForBytesWritten( int msecs );
    /* reimp */ bool waitForReadyRead( int msecs );

protected:
    /* reimp */ qint64 readData( char * data, qint64 maxSize );
    /* reimp */ qint64 writeData( const char * data, qint64 maxSize );

private:
    class Private;
    Private * d;
};

} /* namespace _gpgme_ */

#endif /* __KDTOOLSCORE_KDPIPEIODEVICE_H__ */

