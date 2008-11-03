/****************************************************************************
** Meta object code from reading C++ file 'kdpipeiodevice.h'
**
** Created: Mon Aug 27 15:17:18 2007
**      by: The Qt Meta Object Compiler version 59 (Qt 4.3.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "kdpipeiodevice.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'kdpipeiodevice.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 59
#error "This file was generated using the moc from 4.3.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

static const uint qt_meta_data_KDPipeIODevice[] = {

 // content:
       1,       // revision
       0,       // classname
       0,    0, // classinfo
       0,    0, // methods
       0,    0, // properties
       0,    0, // enums/sets

       0        // eod
};

static const char qt_meta_stringdata_KDPipeIODevice[] = {
    "KDPipeIODevice\0"
};

const QMetaObject KDPipeIODevice::staticMetaObject = {
    { &QIODevice::staticMetaObject, qt_meta_stringdata_KDPipeIODevice,
      qt_meta_data_KDPipeIODevice, 0 }
};

const QMetaObject *KDPipeIODevice::metaObject() const
{
    return &staticMetaObject;
}

void *KDPipeIODevice::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_KDPipeIODevice))
	return static_cast<void*>(const_cast< KDPipeIODevice*>(this));
    return QIODevice::qt_metacast(_clname);
}

int KDPipeIODevice::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QIODevice::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    return _id;
}
