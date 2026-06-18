#pragma once

#include "ScannerRunner.h"

#include <QMainWindow>
#include <QProcess>
#include <QStringList>

class QButtonGroup;
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QRadioButton;
class QSpinBox;
class QTextEdit;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

protected:
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dropEvent(QDropEvent* event) override;
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onBrowseTarget();
    void onBrowseBinary();
    void onRun();
    void onCancel();
    void onSaveOutput();
    void onCopyCmdline();
    void onScannerStarted();
    void onScannerFinished(int code, QProcess::ExitStatus status);
    void onScannerOut(const QString& text);
    void onScannerErr(const QString& text);
    void onScannerFailedToStart(const QString& reason);

private:
    void buildUi();
    void loadSettings();
    void saveSettings();
    QStringList buildArgs() const;
    QString findDefaultBinary() const;
    QString humanCmdline() const;

    // ---- form widgets ----
    QRadioButton* modeFile_ = nullptr;
    QRadioButton* modeDir_  = nullptr;
    QLineEdit*    targetPath_ = nullptr;
    QCheckBox*    recursive_  = nullptr;

    QSpinBox*  maxBytes_ = nullptr;
    QSpinBox*  maxInsn_  = nullptr;
    QSpinBox*  minScore_ = nullptr;
    QSpinBox*  limit_    = nullptr;
    QLineEdit* filter_   = nullptr;
    QLineEdit* badBytes_ = nullptr;

    QButtonGroup* cfgGroup_   = nullptr;
    QRadioButton* cfgAny_     = nullptr;
    QRadioButton* cfgOnly_    = nullptr;
    QRadioButton* cfgExclude_ = nullptr;

    QCheckBox* noSymbols_ = nullptr;
    QCheckBox* pdb_       = nullptr;

    QComboBox* format_     = nullptr;
    QLineEdit* binaryPath_ = nullptr;

    QPushButton* runButton_    = nullptr;
    QPushButton* cancelButton_ = nullptr;
    QPushButton* saveButton_   = nullptr;
    QPushButton* copyCmdButton_ = nullptr;

    QLabel*    statusLabel_ = nullptr;
    QTextEdit* output_      = nullptr;

    // ---- state ----
    ScannerRunner* runner_ = nullptr;
};
