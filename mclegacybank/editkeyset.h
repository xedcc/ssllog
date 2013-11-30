#ifndef EDITKEYSET_H
#define EDITKEYSET_H

#include <QWidget>
#include <QDialog>
#include <QStandardItemModel>

namespace Ui {
class editKeyset;
}

class editKeyset : public QDialog
{
    Q_OBJECT

public:
    explicit editKeyset(QStandardItemModel *model, int row = -1, QWidget *parent = 0);
    ~editKeyset();

public slots:
    void slotSaveChangesAndClose();
    void slotSaveImportedAndClose();
    void slotCheckAllFormFields();

signals:
    //this signal is needed due to QTableView's wierdness
    //we need to inform it to re-select the row after we've made some changes to it
    void FinishedEditingRow(int row);

private:
    int row;
    QStandardItemModel *model;
    Ui::editKeyset *ui;
};

#endif // EDITKEYSET_H
