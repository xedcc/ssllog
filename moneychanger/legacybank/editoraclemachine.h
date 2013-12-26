#ifndef EDITORACLEMACHINE_H
#define EDITORACLEMACHINE_H

#include <QWidget>
#include <QStandardItemModel>

namespace Ui {
class editOracleMachine;
}

class editOracleMachine : public QWidget
{
    Q_OBJECT

public:
    explicit editOracleMachine(QStandardItemModel *model, QWidget *parent = 0);
    ~editOracleMachine();

public slots:
    void slotSaveChangesAndClose();
    void slotCheckAllFormFields();

private:
    Ui::editOracleMachine *ui;
    QStandardItemModel *model;

};

#endif // EDITORACLEMACHINE_H
