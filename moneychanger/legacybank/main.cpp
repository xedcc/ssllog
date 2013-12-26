#include "mainwindow.h"
#include "form.h"
#include <QApplication>
#include <QMutex>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QMutex mutex;
    Form w(&mutex);
    w.show();

    return a.exec();
}
