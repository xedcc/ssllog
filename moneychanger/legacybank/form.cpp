#include "form.h"
#include "editkeyset.h"
#include "editoraclemachine.h"
#include "ui_form.h"
#include "irrxml/irrXML.h"
#include "CXMLReaderImpl.h"
#include <iostream>
#include <fstream>
#include <QListWidget>
#include <QListView>
#include <QTableView>
#include <QStandardItem>
#include <QProcess>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "ComboBoxDelegate.h"
#include <Qt>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <OTStringXML.h>
#include <QtXml/QDomDocument>
#include <QtXml/QDomElement>
#include <QRegularExpression>
#include <unistd.h>
#include <QDebug>
#include <QThread>
#include "customthread.h"
#include <QProcess>

using namespace irr; // irrXML is located in the namespace irr::io
using namespace io;

//This class exists to allow editing of the first column while
//leaving other columns read-only

//-------------BEGIN custom class
class customStandardItemModel : public QStandardItemModel{
public:
  customStandardItemModel(int row, int column, QObject *parent = 0);
  Qt::ItemFlags flags(const QModelIndex &index) const;
};

customStandardItemModel::customStandardItemModel(int row, int column, QObject *parent)
  :QStandardItemModel(row, column, parent){}

Qt::ItemFlags customStandardItemModel::flags(const QModelIndex &index) const{
  if (index.column() == 0){
    return QAbstractItemModel::flags(index) | Qt::ItemIsEditable;
  }
  else QAbstractItemModel::flags(index) & (~Qt::ItemIsEditable);
}
//------------------END custom class


Form::Form(QMutex* mutex, QWidget *parent) :
  QWidget(parent),
  ui(new Ui::Form)
{
  ui->setupUi(this);
  isXMLLoaded = false;

  modelKeysets = new customStandardItemModel(0,6,this);
  modelKeysets->setHorizontalHeaderItem(0, new QStandardItem(QString("Status")));
  modelKeysets->setHorizontalHeaderItem(1, new QStandardItem(QString("Label")));
  modelKeysets->setHorizontalHeaderItem(2, new QStandardItem(QString("User Privkey")));
  modelKeysets->setHorizontalHeaderItem(3, new QStandardItem(QString("User SSHKey")));
  modelKeysets->setHorizontalHeaderItem(4, new QStandardItem(QString("Judge Privkey")));
  modelKeysets->setHorizontalHeaderItem(5, new QStandardItem(QString("Judge SSHKey")));
  ui->tableViewKeysets->setModel(modelKeysets);

  ComboBoxDelegate* delegate = new ComboBoxDelegate(this);
  ui->tableViewKeysets->setItemDelegateForColumn(0, delegate);

  connect(ui->tableViewKeysets, SIGNAL(pressed(QModelIndex)), this, SLOT(slotEnableButtons()));


  modelOracleMachine = new QStandardItemModel(0,7,this);
  QList<QStandardItem*> newRow;
  newRow.clear();
  //fill with empty values. This eliminates the need to check later whether items contain values.
  newRow.append(new QStandardItem(QString("")));
  newRow.append(new QStandardItem(QString("")));
  newRow.append(new QStandardItem(QString("")));
  newRow.append(new QStandardItem(QString("")));
  newRow.append(new QStandardItem(QString("")));
  newRow.append(new QStandardItem(QString("")));
  newRow.append(new QStandardItem(QString("")));
  this->modelOracleMachine->appendRow(newRow);

  connect(ui->toolButtonGenerate, SIGNAL(clicked()), this, SLOT(slotGenerateKeyset()));
  connect(ui->toolButtonDelete, SIGNAL(clicked()), this, SLOT(slotDeleteKeyset()));
  connect(ui->toolButtonViewAndEdit, SIGNAL(clicked()), this, SLOT(slotViewAndEditKeyset()));
  connect(ui->toolButtonImportExisting, SIGNAL(clicked()), this, SLOT(slotImportExistingKeys()));
  connect(ui->toolButtonEditOracleMachine, SIGNAL(clicked()), this, SLOT(slotEditOracleMachine()));
  connect(modelKeysets, SIGNAL(dataChanged(QModelIndex,QModelIndex)),this, SLOT(slotSaveXML()));
  connect(modelKeysets, SIGNAL(rowsInserted(QModelIndex,int,int)),this, SLOT(slotSaveXML()));
  connect(modelKeysets, SIGNAL(rowsRemoved(QModelIndex,int,int)),this, SLOT(slotSaveXML()));
  connect(modelOracleMachine, SIGNAL(dataChanged(QModelIndex,QModelIndex)),this, SLOT(slotSaveXML()));
  connect(modelOracleMachine, SIGNAL(dataChanged(QModelIndex,QModelIndex)),this, SLOT(slotChangeOracleMachineTitle(QModelIndex,QModelIndex)));

  connect(ui->toolButtonRunPaysty, SIGNAL(clicked()), this, SLOT(slotRunPaysty()));
  paystyProcess = new QProcess();
  connect(paystyProcess, SIGNAL(finished(int)), this, SLOT(slotPaystyFinished(int)));
  connect(ui->toolButtonQueryOracleMachine, SIGNAL(clicked()), this, SLOT(slotQueryOracleMachine()));

  sshProcess = new QProcess();
  connect(sshProcess, SIGNAL(readyReadStandardError()), this, SLOT(slotReadSSHStderr()));
  connect(sshProcess, SIGNAL(readyReadStandardOutput()), this, SLOT(slotReadSSHStdout()));
  connect(sshProcess, SIGNAL(finished(int)), this, SLOT(slotSSHFinished(int)));

  loadXMLIntoModel();

  this->mutex = mutex;
  mutex->lock();
  CustomThread* mThread = new CustomThread(mutex);
  mThread->start();
}


Form::~Form()
{
  delete ui;
}

void Form::slotReadSSHStderr(){
  string out;
  out = QString(sshProcess->readAllStandardError()).toStdString();
//  qDebug() << "stderr";
//  qDebug() << out.c_str();
  SSHStderr.append(out.c_str());
}

void Form::slotReadSSHStdout(){
  string out;
  out = QString(sshProcess->readAllStandardOutput()).toStdString();
  qDebug() << "stdout";
  qDebug() << out.c_str();
}

void Form::slotSSHFinished(int exitcode){
  qDebug() << "from slotSSHFinished";
  qDebug() << SSHStderr;

  //An example of a db entry (newlines don't exist there, I added them here for formatting):

  //database {'escrow_fetched_tarball': 0, 'added': 1388165153, 'hash': '',
  //'last_login_time': 0, 'finished_banking': 0, 'is_logged_in_now': False,
  //'sshd_ppid': 0, 'pubkey': 'AAAAB3NzaC1yc2EAAAADAQABAAABAQDGyGDPY3PYQ3OHctbW
  //EzpMDrQa29sXouiydQEERLU8zUH8UEByglZs/B9lRTiN9UxjdC21kJu5aWtn0iXB3ehxsvUSkOx
  //Yku7R7x/N0SZZzKpmkfZCpWmzZh4wGR7VjhSBYbvlARw6vcDLqg+ot4tvg9pGbXdYGOrX07RB3M
  //xCzOa0r0bK6V1sAUoXs8JgxNDy31syTcPrIkegJp8yHM4s5s4DFQ5yteSnXW15gvIt8+/dqog7l
  //0UbRc6vbbyKK4Ms2dMCBDIID6VXkDRQtllUdaqKVoTDX+i1dkuMcm+It3+4wAhPwfreYdTwygdN
  //WS7EQinKq4pGYofKJ3yYp5RX', 'port': 2134, 'txid': '1234-5678'

  //check txid matches
  //check pubkey matches that in the contract
  //check if banking is finished
  //get trace hash

  QRegularExpression re1("'txid': '([\w\W]{9})'");
  QRegularExpressionMatch match1 = re1.match(SSHStderr);
  if (match1.hasMatch()) {
      QString txid = match1.captured(1);
  }

  QRegularExpression re2("'pubkey': '(.*)'");
  QRegularExpressionMatch match2 = re2.match(SSHStderr);
  if (match2.hasMatch()) {
      QString pubkey = match2.captured(1);
  }

  QRegularExpression re3("'finished_banking': ([0-9]*)");
  QRegularExpressionMatch match3 = re3.match(SSHStderr);
  if (match3.hasMatch()) {
    QString finishedBanking = match3.captured(1);
  }

  QRegularExpression re4("'hash': '(\w*)'");
  QRegularExpressionMatch match4 = re4.match(SSHStderr);
  if (match4.hasMatch()) {
    QString hash = match4.captured(1);
  }

}


void CustomThread::run()
{
  //wait until mutex is unlocked, which is a sign that
  //URL checking must begin
  mutex->lock();
  //we get here when the Form class has unlocked the mutex
  //after the user pressed the toolButtonQueryOracleMachine

  QString instance_volumeId;
  QString instanceId;
  QString attachTime;
  QString ownerId;
  int i;

  //should be class member var
  QString DNSName = "ec2-54-207-4-157.sa-east-1.compute.amazonaws.com";

  QString describeInstancesURL("https://ec2.sa-east-1.amazonaws.com/?"
    "AWSAccessKeyId=AKIAI3J2VY5V6W3XDV2Q&Action=DescribeInstances&"
    "Expires=2015-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&"
    "Version=2013-10-15&Signature=wGzH6YE2JNhlEsbRi8r%2Bu%2FVb4W1s2W6oMETBWBxB5%2BA%3D");

  QString describeVolumesURL("https://ec2.sa-east-1.amazonaws.com/?"
    "AWSAccessKeyId=AKIAI3J2VY5V6W3XDV2Q&Action=DescribeVolumes&"
    "Expires=2015-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2"
    "&Version=2013-10-15&Signature=n9b%2BcKDlEWgy2LPSpg7N%2FPkA%2Bkn1n8pOJtLNOydGtRg%3D");

  QString getConsoleOutputURL("https://ec2.sa-east-1.amazonaws.com/?"
    "AWSAccessKeyId=AKIAI3J2VY5V6W3XDV2Q&Action=GetConsoleOutput&Expires=2015-01-01&"
    "InstanceId=i-055e5b1a&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2013-10-15&"
    "Signature=t%2BBd%2BQkd0dsAFhDahsTITwq%2BV15tSbgz%2BRj4CfI%2FBd0%3D");

  QString listMetricsURL("https://monitoring.sa-east-1.amazonaws.com/?"
    "AWSAccessKeyId=AKIAI3J2VY5V6W3XDV2Q&Action=ListMetrics&Expires=2015-01-01&"
    "SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-08-01&"
    "Signature=hf6Z44d7GDNqRnkSxl2gGJLNPW2%2F8N9NG6aBzL4wLIk%3D");

  QString getUserURL("https://iam.amazonaws.com/?AWSAccessKeyId=AKIAI3J2VY5V6W3XDV2Q"
    "&Action=GetUser&Expires=2015-01-01&SignatureMethod=HmacSHA256&"
    "SignatureVersion=2&Version=2010-05-08&"
    "Signature=i2jb7ztPm2wpNe6DAzzrpIae55H4wQ0QpP2dtlFp0lk%3D");

  QNetworkAccessManager* nam = new QNetworkAccessManager();

  //---------REQUEST 1-------------
  QNetworkReply *reply = nam->get(QNetworkRequest(QUrl(describeInstancesURL)));
  QEventLoop loop;
  connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
  loop.exec();

  QString string_reply1(reply->readAll());
  QDomDocument doc1;
  doc1.setContent(string_reply1);
  QDomElement rootElement1 = doc1.documentElement();

  QDomNodeList dnsNameList = rootElement1.elementsByTagName("dnsName");
  bool isDNSNameFound = false;
  for ( i=0; i<dnsNameList.length(); i++){
    if (dnsNameList.at(i).firstChild().nodeValue() != DNSName) continue;
    isDNSNameFound = true;
    break;
  }
  if (!isDNSNameFound) return;
  QDomElement instance = dnsNameList.at(i).parentNode().toElement();

  if (instance.elementsByTagName("imageId").at(0).firstChild().nodeValue() != "ami-35258228") return;
  if (instance.elementsByTagName("instanceState").at(0).toElement().
      elementsByTagName("name").at(0).firstChild().nodeValue() != "running") return;
  if (instance.elementsByTagName("rootDeviceName").at(0).firstChild().nodeValue() != "/dev/sda1") return;

  QString launchTime = instance.elementsByTagName("launchTime").at(0).firstChild().nodeValue();
  instanceId = instance.elementsByTagName("instanceId").at(0).firstChild().nodeValue();
  ownerId = instance.parentNode().parentNode().toElement().
      elementsByTagName("ownerId").at(0).firstChild().nodeValue();

  QDomNodeList volumes = instance.elementsByTagName("blockDeviceMapping").
      at(0).toElement().elementsByTagName("item");
  if (volumes.length() > 1) return;
  if (volumes.at(0).toElement().elementsByTagName("deviceName").at(0).
      firstChild().nodeValue() != "/dev/sda2") return;
  if (volumes.at(0).toElement().elementsByTagName("ebs").at(0).toElement().
      elementsByTagName("status").at(0).firstChild().nodeValue() != "attached") return;
  instance_volumeId = volumes.at(0).toElement().elementsByTagName("ebs").
      at(0).toElement().elementsByTagName("volumeId").at(0).firstChild().nodeValue();
  attachTime = volumes.at(0).toElement().elementsByTagName("ebs").at(0).
      toElement().elementsByTagName("attachTime").at(0).firstChild().nodeValue();
  //example of aws time string 2013-10-12T21:17:31.000Z
  if (attachTime.left(17) != launchTime.left(17)) return ;
  if (attachTime.mid(17,19).toInt()-launchTime.mid(17,19).toInt() > 3) return ;

  //---------REQUEST 2-------------
  reply = nam->get(QNetworkRequest(QUrl(describeVolumesURL)));
  connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
  loop.exec();

  QString string_reply2(reply->readAll());
  QDomDocument doc2;
  doc2.setContent(string_reply2);
  QDomElement rootElement2 = doc2.documentElement();

  QDomNodeList volumeIDList = rootElement2.elementsByTagName("volumeId");
  bool isVolumeIDFound = false;
  for (i=0; i<volumeIDList.length(); i++){
    if (volumeIDList.at(i).firstChild().nodeValue() != instance_volumeId) continue;
    isVolumeIDFound = true;
    break;
  }
  if (!isVolumeIDFound) return ;
  QDomElement volume = volumeIDList.at(i).parentNode().toElement();
  if (volume.elementsByTagName("snapshotId").at(0).firstChild().nodeValue() != "snap-81a54469") return ;
  if (volume.elementsByTagName("status").at(0).firstChild().nodeValue() != "in-use") return ;
  if (volume.elementsByTagName("volumeType").at(0).firstChild().nodeValue() != "standard") return ;

  QString createTime = volume.elementsByTagName("createTime").at(0).firstChild().nodeValue();
  QDomElement attachedVolume = volume.elementsByTagName("attachmentSet").at(0).
      toElement().elementsByTagName("item").at(0).toElement();
  if (attachedVolume.elementsByTagName("volumeId").at(0).firstChild().nodeValue() != instance_volumeId) return ;
  if (attachedVolume.elementsByTagName("instanceId").at(0).firstChild().nodeValue() != instanceId) return ;
  if (attachedVolume.elementsByTagName("device").at(0).firstChild().nodeValue() != "/dev/sda2") return ;
  if (attachedVolume.elementsByTagName("status").at(0).firstChild().nodeValue() != "attached") return ;
  QString volumeAttachTime = attachedVolume.elementsByTagName("attachTime").at(0).firstChild().nodeValue();
  //example of aws time string 2013-10-12T21:17:31.000Z
  //milliseconds were observed to differ occasionally, so we compare up to
  //and including the second value
  if (volumeAttachTime.left(20) != attachTime.left(20)) return ;
  if (volumeAttachTime.left(20) != createTime.left(20)) return ;

  //---------REQUEST 3-------------
  reply = nam->get(QNetworkRequest(QUrl(getConsoleOutputURL)));
  connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
  loop.exec();

  QString string_reply3(reply->readAll());
  QDomDocument doc3;
  doc3.setContent(string_reply3);
  QDomElement rootElement3 = doc3.documentElement();

  if (rootElement3.elementsByTagName("ErrorResponse").length() > 0) return;
  if (rootElement3.elementsByTagName("instanceId").at(0).firstChild().nodeValue() != instanceId) return;
  QString base64Output = rootElement3.elementsByTagName("output").at(0).firstChild().nodeValue();
  QString logdata(QByteArray::fromBase64(base64Output.toLatin1()));
  QRegularExpression re("xvd[^a] | xvda[^2]");
  if (re.match(logdata).hasMatch()){
    return ;
  }

  //---------REQUEST 4-------------
  reply = nam->get(QNetworkRequest(QUrl(listMetricsURL)));
  connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
  loop.exec();

  QString string_reply4(reply->readAll());
  QDomDocument doc4;
  doc4.setContent(string_reply4);
  QDomElement rootElement4 = doc4.documentElement();

  if (rootElement4.elementsByTagName("ErrorResponse").length() > 0){
    return ;
  }

  QDomNodeList metricsList = rootElement4.elementsByTagName("Name");
  for (i=0; i < metricsList.length(); i++){
    if (metricsList.at(i).firstChild().nodeValue() == "VolumeId"){
      if (metricsList.at(i).parentNode().toElement().elementsByTagName("Value")
          .at(0).firstChild().nodeValue() != instance_volumeId)
        //return ; in development
        continue; //in testing
    }
    if (metricsList.at(i).firstChild().nodeValue() == "InstanceId") {
      if (metricsList.at(i).parentNode().toElement().elementsByTagName("Value")
          .at(0).firstChild().nodeValue() != instanceId)
        //return; in development
        continue; //in testing
    }
  }

  //---------REQUEST 5-------------
  reply = nam->get(QNetworkRequest(QUrl(getUserURL)));
  connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
  loop.exec();

  QString string_reply5(reply->readAll());
  QDomDocument doc5;
  doc5.setContent(string_reply5);
  QDomElement rootElement5 = doc5.documentElement();

  if (rootElement5.elementsByTagName("ErrorResponse").length() > 0){
    return ;
  }
  if (rootElement5.elementsByTagName("UserId").length() > 1) return ;
  QString arn = rootElement5.elementsByTagName("Arn").at(0).firstChild().nodeValue();
  if (! arn.endsWith(ownerId+":root")) return ;

  QString AccessKeyId = getUserURL.split("/?AWSAccessKeyId=").at(1).split("&").at(0);
  if (AccessKeyId != listMetricsURL.split("/?AWSAccessKeyId=").at(1).split("&").at(0)) return ;
  if (AccessKeyId != describeInstancesURL.split("/?AWSAccessKeyId=").at(1).split("&").at(0)) return ;
  if (AccessKeyId != describeVolumesURL.split("/?AWSAccessKeyId=").at(1).split("&").at(0)) return ;
  if (AccessKeyId != getConsoleOutputURL.split("/?AWSAccessKeyId=").at(1).split("&").at(0)) return ;

  mutex->unlock();
}


//query all the URLs to make sure that the oracle machine is legit
//after that perform an ssh query

void Form:: slotQueryOracleMachine(){
  mutex->unlock();
  //the url-querying thread has now locked the mutex
  if (!mutex->tryLock(30*1000)){
    //the url querying thread hasn't returned in 30 seconds
    return;
  }
  //else

  //these variables must be sourced from the contract's text

  //key taken from oracle/key2
  QString privateKey = "-----BEGIN RSA PRIVATE KEY-----\n"
      "MIIEpAIBAAKCAQEAqq2OxCSIwHdyMv+Ac1ZpsJuz0kyNprQEzlFtzkjI+UVSM22W\n"
      "tKgyKA2JiqSNFZD64YrLRhoc/+CuId9GN2gjpQUWp3xosqS5Zpy8if68jPyjrG49\n"
      "CfnY9iEmSGVlwmSjIKU/RZNKh5sJSuc1ztqvzCRctJK4/UYfPwNSfAfJhmSuPTl6\n"
      "5Q+HTn8WKwkju6+383JAxCwItEVAb7H0PN48C2+0ak+C1/8LK4JNaI8TFVSH7mcI\n"
      "aWUSiHZKkvJF7CFWp1gvUGWLLcIE3Xh1vb5Cn9u7UYlaj9Nmb0QU01MWHuKV2lQU\n"
      "GkiWchF8X9KXEffHC9GNRQs667QOxycEJVrhEQIDAQABAoIBADRPWTA4WklS0oda\n"
      "042F8IKWVfigSdHL3qU1Q8gzepUbb+QfNE9ONYEdFQiPAkaX1qyFk2N64WRzAiuT\n"
      "eLvGiRYshxLyCEyoO8J9SzOoBTXYwHk6mC6UirB03HzXxuZbXbvFqayzReZl1+VD\n"
      "E7TARZz1kAwv486MTUtMw10MLfGoLbGkjxTkjotEvE3D65YoSFUeVLQymSMIj7uN\n"
      "SWgxe8Mr9U/Bixy003JtIDh8rwJCTp+NbhFt10nl0Q+PeP8R//l8Nfy5du4QkFCc\n"
      "/b2tbJMC2w9l1xnbQ2n1vOeWKyVoTczEkdRzV0yZwKiLROzS8IVA3XZCIpvMI9o8\n"
      "oVh1sqECgYEA1Dglo1sGTobkPdrs0+NzcbUJHDCh6G9fq5j/4HbjCwBJFFsMe5Qd\n"
      "i24cn4SFusR/HFHak/kahE4u29kEFGL/VAS7pki1nnjnjY0Jt8ls7vzB9jm6vLwV\n"
      "c+iPXyZ6SmJhyqo85qJIfLzWozWmfz712dGjWVRuaqj9RwytYf6nVc0CgYEAzeOA\n"
      "4W+8C0gV6wQ5DD4/6cw7FYE4ii+314UjjFl7llWCiZSq6ojIPG3ipoDkkZssIJ7e\n"
      "GvteMxPMyTmhaMq7gAdscQ6gqQkUgLsK0K5ofogqIkHUS2UicJYJU6XSxVFzUcNy\n"
      "HqVVN02Skfde7XvH+Emir1MWSigRJekdy/4U9FUCgYA4sMMFL1Sw94HTMD9hnvoA\n"
      "3w6O9ELcF5xj95wq9zdRggMDqArenEOEMqb8yeb7bHBUPV15d+roewYzfnaDh6qT\n"
      "ZCxIkFXL/ppEiu+Uo/8wnF6oCuXicw/8BZz/GwVCB6P+ApoANkvM3pkrwjI2/bep\n"
      "N0I+o7pXTctTBoTuj5td5QKBgQC3F+9gC4Z1nehn9HxrB9y8pLOSXzURpnfeAHdp\n"
      "c5Y1TdvlT8FjCrrPCoV5vrwFRLJMXBt2cT4HPD9sX4TL9SYjJ/bm37Q+PmXuSOfI\n"
      "RqGEjMCzcElDty+WYcbvjVLPyKw99QpCeJM8uA51IkBX/zEI+yrisYfr8I+3YATw\n"
      "iQbHdQKBgQCKOkntX+l1dNyh8ZA9MWJdTBZC7aJksLZsRuS4EVppqMUXEwcnnHHo\n"
      "9Npki5+fiC48ggkbavDM552DfP6A5WSUBN8XHg5QghFA0Ao+aHZLU03AOtCALTAA\n"
      "Ywrw1Woqe29mkx5Xg5KaeBZ9QVh9R8fH6rQyAbFWYizu8V+8hdrvtA==\n"
      "-----END RSA PRIVATE KEY-----\n";
  ofstream privkeyFile;
  privkeyFile.open("/tmp/priv.key");
  privkeyFile << privateKey.toStdString();
  privkeyFile.close();
  QProcess::execute("chmod 0600 /tmp/priv.key");

  //wrte the privkey to a file;
  QString DNSName = "ec2-54-207-4-157.sa-east-1.compute.amazonaws.com";

  //connect to SSH/plink
  QString program = "/usr/bin/ssh";
  QStringList arguments;
  //string concat = "ubuntu@" + DNSName.toStdString();
  string concat = "localhost";
  QString qconcat(concat.c_str());
  arguments << "-i" << "/tmp/priv.key" << "-oIdentitiesOnly=yes" << qconcat;

  sshProcess->start(program, arguments);



  //parse the SSH data:
  //make sure we were querying the correct SSH Pubkey
}


void Form::slotEnableButtons(){
  ui->toolButtonDelete->setEnabled(true);
  ui->toolButtonViewAndEdit->setEnabled(true);
}

void Form::slotChangeOracleMachineTitle(QModelIndex topLeft, QModelIndex bottomRight){
  //we're only looking out for the change in DNSname (index in model 0,0)- that's the actual title
  if (topLeft.column() == 0 && topLeft.row() == 0){
    ui->lineEditOracleMachine->setText(modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,0))->text());
  }
}


void Form::loadXMLIntoModel(){
  IrrXMLReader *xml = createIrrXMLReader("/tmp/config.xml");
  QList<QStandardItem*> newRow;

  while(xml && xml->read()){
    //only interested in item nodes
    if (xml->getNodeType() == EXN_ELEMENT && !strcmp ("keyset", xml->getNodeName())){
      newRow.clear();
      newRow.append(new QStandardItem(QString::fromStdString(xml->getAttributeValue("status"))));
      newRow.append(new QStandardItem(QString::fromStdString(xml->getAttributeValue("label"))));
      newRow.append(new QStandardItem(QString::fromStdString(xml->getAttributeValue("userPrivKey"))));
      newRow.append(new QStandardItem(QString::fromStdString(xml->getAttributeValue("userSSHKey"))));
      newRow.append(new QStandardItem(QString::fromStdString(xml->getAttributeValue("judgePrivKey"))));
      newRow.append(new QStandardItem(QString::fromStdString(xml->getAttributeValue("judgeSSHKey"))));
      this->modelKeysets->appendRow(newRow);
      ui->tableViewKeysets->openPersistentEditor(modelKeysets->index(modelKeysets->rowCount()-1,0));
    }
    else
      if (xml->getNodeType() == EXN_ELEMENT && !strcmp ("oracleMachine", xml->getNodeName())){
        modelOracleMachine->setItem(0,0, new QStandardItem(QString::fromStdString(xml->getAttributeValue("dnsName"))));
        ui->lineEditOracleMachine->setText(QString::fromStdString(xml->getAttributeValue("dnsName")));
        modelOracleMachine->setItem(0,1, new QStandardItem(QString::fromStdString(xml->getAttributeValue("getUserUrl"))));
        modelOracleMachine->setItem(0,2, new QStandardItem(QString::fromStdString(xml->getAttributeValue("listMetricsUrl"))));
        modelOracleMachine->setItem(0,3, new QStandardItem(QString::fromStdString(xml->getAttributeValue("describeInstancesUrl"))));
        modelOracleMachine->setItem(0,4, new QStandardItem(QString::fromStdString(xml->getAttributeValue("describeVolumesUrl"))));
        modelOracleMachine->setItem(0,5, new QStandardItem(QString::fromStdString(xml->getAttributeValue("getConsoleOutputUrl"))));
        modelOracleMachine->setItem(0,6, new QStandardItem(QString::fromStdString(xml->getAttributeValue("publicEBSSnapshotID"))));
      }
  }
  delete xml;
  isXMLLoaded = true;
}

//receives model's signal on row insert & remove
void Form::slotSaveXML(){
  if (!isXMLLoaded) return;
  ofstream cfg;
  cfg.open ("/tmp/config.xml");
  cfg << "<oracleOperatorConfig>\n\n";

  //first goes the oracle machine's attributes
  cfg << "<oracleMachine dnsName=\""
      << modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,0))->text().toStdString()
      << "\"\n";
  cfg << "getUserUrl=\""
      << modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,1))->text().toStdString()
      << "\"\n";
  cfg << "listMetricsUrl=\""
      << modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,2))->text().toStdString()
      << "\"\n";
  cfg << "describeInstancesUrl=\""
      << modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,3))->text().toStdString()
      << "\"\n";
  cfg << "describeVolumesUrl=\""
      << modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,4))->text().toStdString()
      << "\"\n";
  cfg << "getConsoleOutputUrl=\""
      << modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,5))->text().toStdString()
      << "\"\n";
  cfg << "publicEBSSnapshotID=\""
      << modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,6))->text().toStdString()
      << "\"/>\n\n";


  //iterate over each keyset in model
  int rowCount = modelKeysets->rowCount();
  for (int i=0; i < rowCount; i++) {
    //force each tableView row to show the comboBox widget
    ui->tableViewKeysets->openPersistentEditor(modelKeysets->index(i,0));
    cfg << "<keyset status=\"" << modelKeysets->itemFromIndex(modelKeysets->index(i,0))->text().toStdString() << "\"\n";
    cfg << "label=\"" << modelKeysets->itemFromIndex(modelKeysets->index(i,1))->text().toStdString() << "\"\n";
    cfg << "userPrivKey=\"" << modelKeysets->itemFromIndex(modelKeysets->index(i,2))->text().toStdString() << "\"\n";
    cfg << "userSSHKey=\"" << modelKeysets->itemFromIndex(modelKeysets->index(i,3))->text().toStdString() << "\"\n";
    cfg << "judgePrivKey=\"" << modelKeysets->itemFromIndex(modelKeysets->index(i,4))->text().toStdString() << "\"\n";
    cfg << "judgeSSHKey=\"" << modelKeysets->itemFromIndex(modelKeysets->index(i,5))->text().toStdString() << "\"/>\n\n";
  }
  cfg << "\n</oracleOperatorConfig>";
  cfg.close();
}

void Form::slotPaystyFinished(int exitcode){
  if (exitcode == 3){
    //SSL audit finished successfully
    //Inform oracle operator that he may fetch the SSL trace from oracle machine and hand it over to judge

    //Change the status of the dispute to "awaiting oracle operator actions"
  }
}


void Form::slotRunPaysty(){
  QString program = "/usr/bin/python";
  QStringList arguments;
  arguments << "/home/default2/Desktop/sslxchange/buyer-oracle.py" << "OTmode";

  //these arguments MUST be sourced from the contract
  //We source them from the oracle's model for the convenience of testing
  arguments << modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,0))->text();
  arguments << modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,1))->text();
  arguments << modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,2))->text();
  arguments << modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,3))->text();
  arguments << modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,4))->text();
  arguments << modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,5))->text();
  arguments << modelOracleMachine->itemFromIndex(modelOracleMachine->index(0,6))->text();
  arguments << "AVeryLongStringOfASCIIArmoredPEMPrivateKeyWhichMUSTBeSourcedFromTheContract";

  paystyProcess->start(program, arguments);
}


void Form::slotViewAndEditKeyset(){
  //find out which keyset is selected an remove it from vector
  QModelIndexList id = ui->tableViewKeysets->selectionModel()->selectedIndexes();
  if (id.length() == 0) return;
  int row = id.at(0).row();
  editKeyset *ek = new editKeyset(modelKeysets, row, this);
  //the signal to workaround QTableWidget's bug which removes selection
  //from items that have been updates
  connect(ek, SIGNAL(FinishedEditingRow(int)), SLOT(slotReselectRow(int)));
  ek->setModal(true);
  ek->show();

}

void Form::slotReselectRow(int row){
  ui->tableViewKeysets->selectRow(row);
}

void Form::slotEditOracleMachine(){
  editOracleMachine *eom = new editOracleMachine(modelOracleMachine);
  eom->show();
}

void Form::slotImportExistingKeys(){
  editKeyset *ek = new editKeyset(modelKeysets);
  ek->show();
}


void Form::slotDeleteKeyset(){
  //find out which keyset is selected an remove it from vector
  QModelIndexList id = ui->tableViewKeysets->selectionModel()->selectedIndexes();
  if (id.length() == 0) return;
  int row = id.at(0).row();
  modelKeysets->removeRow(row);
  //after deletion, the table view ends up in a state where nothing is selected, hence
  //we disable the button until some other item is selected
  ui->toolButtonDelete->setEnabled(false);
  ui->toolButtonViewAndEdit->setEnabled(false);
}


//generate 2 pub/priv keys - one for user and one for judge
void Form::slotGenerateKeyset(){
  const int kBits = 2048;
  const int kExp = 3;
  int keylen, keylen_pub;
  char *pem_key, *pem_key_pub;
  RSA *rsa;
  BIO *bio, *biob64, *b64;
  FILE* stream;
  vector <string> keys;

  //generate 2 key pairs
  for (int i=0; i<2; i++){

    rsa = RSA_generate_key(kBits, kExp, 0, 0);

    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
    keylen = BIO_pending(bio);
    pem_key = (char *)calloc(keylen+1, 1); /* Null-terminate */
    BIO_read(bio, pem_key, keylen);

    keys.push_back(string(pem_key));

    //extract exponent and modulus for ssh-rsa format
    u_int32_t exponent_size = BN_num_bytes(rsa->e);
    u_int32_t modulus_size = BN_num_bytes(rsa->n);
    uchar *exponent = (uchar *)malloc(exponent_size);
    uchar *modulus  = (uchar *)malloc(modulus_size);
    BN_bn2bin(rsa->e, exponent);
    BN_bn2bin(rsa->n, modulus);

    //ssh-rsa format is base64'd bytearray:
    // /x00/x00/x00/x07ssh-rsa/x00/x00/x00/x01 + exponent + /x00/x00/x01/x01 + /x00 + modulus

    // or a more general formula:
    // htonl(u_int_32(7)) + ssh-rsa + htonl(u_int32(exponent_size)) +
    // exponent + htonl(u_int32(modulus_size)) + /x00 + modulus

    char ssh_rsa_str[7] = {'s','s','h','-','r','s','a'};
    u_int32_t ssh_rsa_str_sz = 7;
    //we need all the 32-bit ints in big-endian format
    u_int32_t be_ssh_rsa_str_sz = htonl(ssh_rsa_str_sz);
    u_int32_t be_exponent_size = htonl(exponent_size);
    u_int32_t be_modulus_size = htonl(modulus_size);
    u_int8_t zero = 0;

    int data_to_encode_sz = 4 + ssh_rsa_str_sz + 4 + exponent_size + 4 + 1 + modulus_size;
    char *data_to_encode = (char *)malloc(data_to_encode_sz);
    memcpy(data_to_encode, &be_ssh_rsa_str_sz, 4);
    memcpy(data_to_encode+4, ssh_rsa_str, 7);
    memcpy(data_to_encode+11, &be_exponent_size, 4);
    memcpy(data_to_encode+15, exponent, exponent_size);
    memcpy(data_to_encode+15+exponent_size, &be_modulus_size, 4);
    memcpy(data_to_encode+15+exponent_size+4, &zero, 1);
    memcpy(data_to_encode+15+exponent_size+4+1, modulus, modulus_size);
    free(exponent);
    free(modulus);


    //adapted from https://gist.github.com/barrysteyn/4409525#file-base64encode-c

    int encodedSize = 4*ceil((double)data_to_encode_sz/3);
    char *ssh_key = (char *)malloc(encodedSize+1);
    stream = fmemopen((void *)ssh_key, encodedSize+1, "w");
    b64 = BIO_new(BIO_f_base64());
    biob64 = BIO_new_fp(stream, BIO_NOCLOSE);
    biob64 = BIO_push(b64, biob64);
    BIO_set_flags(biob64, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
    BIO_write(biob64, data_to_encode, data_to_encode_sz);
    BIO_flush(biob64);
    BIO_free_all(biob64);
    fclose(stream);

    keys.push_back(string(ssh_key));
  }

  QList<QStandardItem*> newRow;
  newRow.append(new QStandardItem(QString("Available")));
  //generate a random 6-char label
  const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
  const int randomStringLength = 6;
  QString randomString;
  for(int i=0; i<randomStringLength; ++i)
  {
    int index = qrand() % possibleCharacters.length();
    QChar nextChar = possibleCharacters.at(index);
    randomString.append(nextChar);
  }
  newRow.append(new QStandardItem(randomString));
  newRow.append(new QStandardItem(QString::fromStdString(keys[0])));
  newRow.append(new QStandardItem(QString::fromStdString(keys[1])));
  newRow.append(new QStandardItem(QString::fromStdString(keys[2])));
  newRow.append(new QStandardItem(QString::fromStdString(keys[3])));

  this->modelKeysets->appendRow(newRow);
  ui->tableViewKeysets->openPersistentEditor(modelKeysets->index(modelKeysets->rowCount()-1,0));

  //We still need the pubkey code below, so that we could compare the output of
  //ssh-keygen -f /tmp/pubkey -i -m PKCS8 with buffer (ssh-rsa formatted pubkey)
  //this will be used in unit test
  //     BIO *bio_pub = BIO_new(BIO_s_mem());
  //     PEM_write_bio_RSA_PUBKEY(bio_pub, rsa);

  //     keylen_pub = BIO_pending(bio_pub);
  //     pem_key_pub = (char *)calloc(keylen_pub+1, 1); /* Null-terminate */
  //     BIO_read(bio_pub, pem_key_pub, keylen_pub);

  //     printf("%s", pem_key);
  //     printf("%s", pem_key_pub);

  //     ofstream privkey;
  //     privkey.open ("/tmp/privkey");
  //     privkey << pem_key;
  //     privkey.close();

  //     ofstream pubkey;
  //     pubkey.open ("/tmp/pubkey");
  //     pubkey << pem_key_pub;
  //     pubkey.close();


  //     BIO_free_all(bio);
  //     BIO_free_all(bio_pub);
  //     RSA_free(rsa);
  //     free(pem_key);
  //     free(pem_key_pub);

}

