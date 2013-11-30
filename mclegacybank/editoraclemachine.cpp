#include "editoraclemachine.h"
#include "ui_editoraclemachine.h"

editOracleMachine::editOracleMachine(QStandardItemModel *model, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::editOracleMachine)
{
    ui->setupUi(this);
    this->model = model;
    connect(ui->toolButtonDontSave, SIGNAL(clicked()), this, SLOT(close()));
    connect(ui->toolButtonSave, SIGNAL(clicked()), this, SLOT(slotSaveChangesAndClose()));

    if (model->rowCount() != 0){
        ui->lineEditDNSName->setText(model->itemFromIndex(model->index(0,0))->text());
        ui->textEditGetUser->setPlainText(model->itemFromIndex(model->index(0,1))->text());
        ui->textEditListMetrics->setPlainText(model->itemFromIndex(model->index(0,2))->text());
        ui->textEditDescribeInstances->setPlainText(model->itemFromIndex(model->index(0,3))->text());
        ui->textEditDescribeVolumes->setPlainText(model->itemFromIndex(model->index(0,4))->text());
        ui->textEditGetConsoleOutput->setPlainText(model->itemFromIndex(model->index(0,5))->text());
        ui->lineEditSnapshotID->setText(model->itemFromIndex(model->index(0,6))->text());
    }
    //signals must be connected AFTER the fields are populated, so that the save changes button
    //remains inactive until some field is changed
    connect(ui->textEditGetUser, SIGNAL(textChanged()), this, SLOT(slotCheckAllFormFields()));
    connect(ui->textEditDescribeVolumes, SIGNAL(textChanged()), this, SLOT(slotCheckAllFormFields()));
    connect(ui->textEditDescribeInstances, SIGNAL(textChanged()), this, SLOT(slotCheckAllFormFields()));
    connect(ui->textEditGetConsoleOutput, SIGNAL(textChanged()), this, SLOT(slotCheckAllFormFields()));
    connect(ui->textEditListMetrics, SIGNAL(textChanged()), this, SLOT(slotCheckAllFormFields()));
    connect(ui->lineEditDNSName, SIGNAL(textChanged(QString)), this, SLOT(slotCheckAllFormFields()));
    connect(ui->lineEditSnapshotID, SIGNAL(textChanged(QString)), this, SLOT(slotCheckAllFormFields()));

}

void editOracleMachine::slotSaveChangesAndClose(){
    model->setItem(0,0, new QStandardItem(ui->lineEditDNSName->text()));
    model->setItem(0,1, new QStandardItem(ui->textEditGetUser->toPlainText()));
    model->setItem(0,2, new QStandardItem(ui->textEditListMetrics->toPlainText()));
    model->setItem(0,3, new QStandardItem(ui->textEditDescribeInstances->toPlainText()));
    model->setItem(0,4, new QStandardItem(ui->textEditDescribeVolumes->toPlainText()));
    model->setItem(0,5, new QStandardItem(ui->textEditGetConsoleOutput->toPlainText()));
    model->setItem(0,6, new QStandardItem(ui->lineEditDNSName->text()));
    this->close();
}

void editOracleMachine::slotCheckAllFormFields(){
    bool ok = !ui->lineEditDNSName->text().isEmpty()
            && !ui->lineEditSnapshotID->text().isEmpty()
            && !ui->textEditDescribeVolumes->toPlainText().isEmpty()
            && !ui->textEditGetUser->toPlainText().isEmpty()
            && !ui->textEditListMetrics->toPlainText().isEmpty()
            && !ui->textEditGetConsoleOutput->toPlainText().isEmpty()
            && !ui->textEditDescribeInstances->toPlainText().isEmpty();
    ui->toolButtonSave->setEnabled(ok);
}

editOracleMachine::~editOracleMachine()
{
    delete ui;
}
