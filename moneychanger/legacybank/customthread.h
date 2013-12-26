//This class declaraion MUST be in a separate header file b/c of Q_OBJECT,
//otherwise you'll get an error if you inline this declaration in a cpp file.

//This class waits on a mutex and after locking it, synchronously sends
//HTTPS requests to EC2.
//Due to some Qt bug, I couldn't make QNetworkAccessManager trigger the
//finished SLOTs, so for now all sending of requests and processing of replies
//happens from the run function

#ifndef CUSTOMTHREAD_H
#define CUSTOMTHREAD_H
#include <QThread>
#include <QtNetwork/QNetworkReply>
#include <QMutex>

class CustomThread : public QThread{
    Q_OBJECT
public:
    explicit CustomThread(QMutex* mutex) { this->mutex = mutex; }
private:
    void run();
    QMutex* mutex;
};



#endif // CUSTOMTHREAD_H
