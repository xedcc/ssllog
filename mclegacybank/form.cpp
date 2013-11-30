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



Form::Form(QWidget *parent) :
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

    stderr.open ("/tmp/stderr");
    stdout.open ("/tmp/stdout");

    loadXMLIntoModel();
}

Form::~Form()
{
    delete ui;
}

void Form::slotReadSSHStderr(){
    string out;
    out = QString(sshProcess->readAllStandardError()).toStdString();
    stderr << out;
    stderr.flush();
}

void Form::slotReadSSHStdout(){
    string out;
    out = QString(sshProcess->readAllStandardOutput()).toStdString();
    stdout << out;
    stdout.flush();
}

void Form::slotURLRequestFinished(QNetworkReply* reply){
    QString string_reply(reply->readAll());
    OTStringXML stringXML(string_reply.toStdString());
    IrrXMLReader *xml = createIrrXMLReader(&stringXML);

    while(xml && xml->read()){
        //only interested in item nodes
        if (xml->getNodeType() == EXN_ELEMENT && !strcmp ("Arn", xml->getNodeName())){
            int a = 0;
        }
    }
    ofstream urlreply;
    urlreply.open("/tmp/urlreply");
    urlreply << string_reply.toStdString();
    urlreply.close();
}

void Form::slotQueryOracleMachine(){
    //query all the URLs to make sure that the oracle Machine is legit
    QNetworkAccessManager *nam = new QNetworkAccessManager(this);
    connect(nam,SIGNAL(finished(QNetworkReply*)),this,SLOT(slotURLRequestFinished(QNetworkReply*)));
    QString describeInstancesURL("https://ec2.sa-east-1.amazonaws.com/?AWSAccessKeyId=AKIAI3J2VY5V6W3XDV2Q&"
                                 "Action=DescribeInstances&Expires=2015-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2"
                                 "&Version=2013-10-15&Signature=wGzH6YE2JNhlEsbRi8r%2Bu%2FVb4W1s2W6oMETBWBxB5%2BA%3D");

    QString getUserURL("https://iam.amazonaws.com/?AWSAccessKeyId=AKIAI3J2VY5V6W3XDV2Q"
                                     "&Action=GetUser&Expires=2015-01-01&SignatureMethod=HmacSHA256&"
                                     "SignatureVersion=2&Version=2010-05-08&"
                                     "Signature=i2jb7ztPm2wpNe6DAzzrpIae55H4wQ0QpP2dtlFp0lk%3D");

    nam->get(QNetworkRequest(QUrl(describeInstancesURL)));

    return;


    //these variables must be sourced from the contract's text

    QString privateKey = "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA1wYBamyURAQNKi3eHEcUxJyxB6RmozYbj8sBgDKMASUW85ri\n"
            "+BcQKJ4OdUapBlYAG7ioKOpIV6XhpffLUr65++/lmZMpzj/shefIAl7K8qX4wS9Q\n"
            "0Vpmv894gs3uA43HGbuHfpVrhabCqEj2zW8okq7iOKpL1U7HY+i9zEccpzwG3/EK\n"
            "3kFvVOYsnA4uD4PClMPYU7w2lOij6Z1hxfaxDKeR7Xh96zlW72zL0h46eDRSBP8Y\n"
            "05ZYNpB3cPRkgeJzH3WpcLVCSLuQH/0S9bA2KJvC7zXZsTRiJTkbAxr89O9cJ1F/\n"
            "L6RcjVPe3Pj0UnP7g+CmWal5GsG7f5BQNzyBeQIDAQABAoIBAFAKwEQpnxeimnP1\n"
            "FxVXsHdwDMZXgI2I+sGQRELAjjVu5RhRs+O+UhmMnL0zTIA7S1cGajKw47Uc3t61\n"
            "W062CO2r48BDc/B/A0DlgyK+vrWM6wie4GrOSClmxemLVuqjwFXn5QxN+vSJmzSh\n"
            "1J2sn2HbEAMgAZKp/LdIUD7WyefGVdPXSM2urrp4eT0ScpzHxpQohXcwdGnACkod\n"
            "hq65TiB8C6m0Qq5fSYla5jsiJGsDoDJ6V+5gUQnnJr7LQp/3rjAMoXlUeQQT12mW\n"
            "NcHmeBaJcFeWsN8u/cGncpgmcRF/r4Rn/37rFLeZXb8oRLptQANTvS10Je+y2Bre\n"
            "rEitsgECgYEA8nIyiV5buT0a9SmzCJ0gnHRZUAjJkGzfryb4IvYlk3kFsHqp4BgY\n"
            "zWnOHCfVlteG/IjPnUL7YQxKh6w/SHx3uzwZxo6njQ92HUuNGEGL2aJqQ0+wFtzg\n"
            "XhIBg9L09zR+trZNXaHuMVBUMZU9UwsWxsR0CA1rFlTBHpQwvWKWEUkCgYEA4wtY\n"
            "YEm20mnRz0AzRjHZGlUlIdZIHMtEeZXx7HS7sydQ/rpfrMgmtVYPA2HVIZRrkZyl\n"
            "ko8iNlAXALScPvOjPBv+j9ZywcSog0TI+KVSo1LtTWlNV9FZdnKck+BYS23pOieb\n"
            "yNTqIvu1CGaFURR4gW2pTr6RNQX2dRFqKO/UHrECgYEAnMeUPpiyH9uP7zIEAHH7\n"
            "gLEMgGDuV2LQU2eT1qfuLKt6LmFkMPHkOBFPo41u5ZiCRhQCjeOew2c7WvjcA3fZ\n"
            "xU5cLLZbSzDQZKlSmHjqgtYweU6yxFYZETv7ls94cdOUjXreFMp+SY10pIupmGX3\n"
            "WJn5nqtusIYmTCvwSMfT22ECgYEAgbBKU/3nQzuUz/iREUiKBYObST+4Q1JMk9L1\n"
            "tKZdTRFpL4fP/Mb7bVtyCfGJJ7w60ZsT7Kp71WBcM1f3Y/IRTNWEzC6nsE0gIJNa\n"
            "5MSydn549F3xAvefTYxcKg/c/4ER1tknIEmWUFNM7jZ5cn3p86xrKIKsOQhl5isD\n"
            "Y8zScpECgYBfy6GqfrGiY4xvakQ8xTj1XGty9koOTtYgNgXFdnBsElIWzUTdJBdF\n"
            "kpKzTOEYrY2LbKkB70FlbIkN7gjAPMD2V9UckGjmE3E6qtOtd4ljWSSW+9GaIRwQ\n"
            "aWRsjUtDYEZlzEmnT6yUT9skDOvdP3T3e7d6AsB0xRKHzGGdDSCeqg==\n"
            "-----END RSA PRIVATE KEY-----";
    ofstream privkeyFile;
    privkeyFile.open("/tmp/priv.key");
    privkeyFile << privateKey.toStdString();
    privkeyFile.close();

    //wrte the privkey to a file;
    QString DNSName = "ec2-54-207-26-20.sa-east-1.compute.amazonaws.com";
    QString getUserURL = "";

    //connect to SSH/plink

    QString program = "/usr/bin/ssh";
    QStringList arguments;
    string concat = "ubuntu@" + DNSName.toStdString();
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
