#include "editkeyset.h"
#include "ui_editkeyset.h"

editKeyset::editKeyset(QStandardItemModel *model, int row, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::editKeyset)
{
    ui->setupUi(this);
    this->row = row;
    this->model = model;

    if (row != -1) {
        connect(ui->toolButtonSave, SIGNAL(clicked()), this, SLOT(slotSaveChangesAndClose()));
    }
    else {
        connect(ui->toolButtonSave, SIGNAL(clicked()), this, SLOT(slotSaveImportedAndClose()));
    }
    connect(ui->toolButtonDontSave, SIGNAL(clicked()), this, SLOT(close()));

    if (row != -1){
        ui->lineEditLabel->setText(model->itemFromIndex(model->index(row,1))->text());
        ui->textEditUserPrivKey->setPlainText(model->itemFromIndex(model->index(row,2))->text());
        ui->textEditUserSSHKey->setPlainText(model->itemFromIndex(model->index(row,3))->text());
        ui->textEditJudgePrivKey->setPlainText(model->itemFromIndex(model->index(row,4))->text());
        ui->textEditJudgeSSHKey->setPlainText(model->itemFromIndex(model->index(row,5))->text());
    }

    //these signal must be connected after the form is populated in order to keep
    //"save changes" button faded until a field is actually changed
    connect(ui->textEditJudgePrivKey, SIGNAL(textChanged()), this, SLOT(slotCheckAllFormFields()));
    connect(ui->textEditJudgeSSHKey, SIGNAL(textChanged()), this, SLOT(slotCheckAllFormFields()));
    connect(ui->textEditUserPrivKey, SIGNAL(textChanged()), this, SLOT(slotCheckAllFormFields()));
    connect(ui->textEditUserSSHKey, SIGNAL(textChanged()), this, SLOT(slotCheckAllFormFields()));
    connect(ui->lineEditLabel, SIGNAL(textChanged(QString)), this, SLOT(slotCheckAllFormFields()));
}

void editKeyset::slotCheckAllFormFields(){
    bool ok = !ui->lineEditLabel->text().isEmpty()
            && !ui->textEditJudgePrivKey->toPlainText().isEmpty()
            && !ui->textEditJudgeSSHKey->toPlainText().isEmpty()
            && !ui->textEditUserPrivKey->toPlainText().isEmpty()
            && !ui->textEditUserSSHKey->toPlainText().isEmpty();
    ui->toolButtonSave->setEnabled(ok);
}

void editKeyset::slotSaveChangesAndClose(){
    model->setItem(row,1, new QStandardItem(ui->lineEditLabel->text()));
    model->setItem(row,2, new QStandardItem(ui->textEditUserPrivKey->toPlainText()));
    model->setItem(row,3, new QStandardItem(ui->textEditUserSSHKey->toPlainText()));
    model->setItem(row,4, new QStandardItem(ui->textEditJudgePrivKey->toPlainText()));
    model->setItem(row,5, new QStandardItem(ui->textEditJudgeSSHKey->toPlainText()));
    emit FinishedEditingRow(row);
    //TODO select the row before closing since tableView doesn't preserve selection on modified rows
    this->close();
}

void editKeyset::slotSaveImportedAndClose(){
    QList<QStandardItem*> newRow;
    newRow.append(new QStandardItem(QString("Available")));
    newRow.append(new QStandardItem(ui->lineEditLabel->text()));
    newRow.append(new QStandardItem(ui->textEditUserPrivKey->toPlainText()));
    newRow.append(new QStandardItem(ui->textEditUserSSHKey->toPlainText()));
    newRow.append(new QStandardItem(ui->textEditJudgePrivKey->toPlainText()));
    newRow.append(new QStandardItem(ui->textEditJudgeSSHKey->toPlainText()));
    this->model->appendRow(newRow);
    this->close();
}


editKeyset::~editKeyset()
{
    delete ui;
}
