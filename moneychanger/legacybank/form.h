#ifndef FORM_H
#define FORM_H

#include <QWidget>
#include <QStandardItemModel>
#include <QtNetwork/QNetworkReply>
#include <QProcess>
#include <vector>
#include <string>
#include <fstream>
#include <QMutex>

using namespace std;

struct keyset {
    string label;
    string status;
    string userPrivKey;
    string judgePrivKey;
    string userSSHKey;
    string judgeSSHKey;
};

namespace Ui {
class Form;
}

class Form : public QWidget
{
    Q_OBJECT

public:
    explicit Form(QMutex* mutex, QWidget *parent = 0);
    ~Form();

public slots:
    void slotGenerateKeyset();
    void slotDeleteKeyset();
    void slotViewAndEditKeyset();
    void slotEditOracleMachine();
    void slotImportExistingKeys();
    void slotSaveXML();
    void slotRunPaysty();
    void slotPaystyFinished(int);
    void slotChangeOracleMachineTitle(QModelIndex topLeft, QModelIndex bottomRight);
    void slotEnableButtons();
    void slotReselectRow(int row);
    void slotQueryOracleMachine();
    void slotReadSSHStderr();
    void slotReadSSHStdout();
    void slotSSHFinished(int);

private:
    Ui::Form *ui;
    ofstream stderr;
    ofstream stdout;
    QProcess *paystyProcess;
    QProcess *sshProcess;
    QStandardItemModel *modelKeysets;
    QStandardItemModel *modelOracleMachine;
    QNetworkAccessManager *nam;
    QString SSHStderr;
    void loadXMLIntoModel();
    void saveXML();
    void waitForTrigger();
    bool isTriggered;
    //informs slotSaveXML to ignore model's signals when loading XML for the first time on init
    bool isXMLLoaded;
    QMutex* mutex;

};

#endif // FORM_H
