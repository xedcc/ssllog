#-------------------------------------------------
#
# Project created by QtCreator 2013-11-07T02:27:24
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = untitled
TEMPLATE = app

INCLUDEPATH += /home/default2/dev/Open-Transactions/include/irrxml
SOURCES += main.cpp\
        mainwindow.cpp \
    form.cpp \
    editkeyset.cpp \
    editoraclemachine.cpp \
    ComboBoxDelegate.cpp

HEADERS  += mainwindow.h \
    form.h \
    editkeyset.h \
    editoraclemachine.h \
    ComboBoxDelegate.h

FORMS    += mainwindow.ui \
    form.ui \
    editkeyset.ui \
    editoraclemachine.ui

OTHER_FILES += \
    config.xml

unix: CONFIG += link_pkgconfig
unix: PKGCONFIG += opentxs
