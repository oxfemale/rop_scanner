#include "MainWindow.h"

#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QClipboard>
#include <QCloseEvent>
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMimeData>
#include <QPushButton>
#include <QRadioButton>
#include <QSettings>
#include <QSpinBox>
#include <QStatusBar>
#include <QTextEdit>
#include <QTextStream>
#include <QUrl>
#include <QVBoxLayout>

namespace {
QString shellQuote(const QString& s) {
    // Quote argv element for cosmetic display only.
    if (s.isEmpty()) return "\"\"";
    if (s.contains(' ') || s.contains(';') || s.contains('"')) {
        QString esc = s;
        esc.replace("\"", "\\\"");
        return "\"" + esc + "\"";
    }
    return s;
}
} // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("rop_scanner");
    setAcceptDrops(true);

    runner_ = new ScannerRunner(this);
    connect(runner_, &ScannerRunner::started,        this, &MainWindow::onScannerStarted);
    connect(runner_, &ScannerRunner::finished,       this, &MainWindow::onScannerFinished);
    connect(runner_, &ScannerRunner::stdoutChunk,    this, &MainWindow::onScannerOut);
    connect(runner_, &ScannerRunner::stderrChunk,    this, &MainWindow::onScannerErr);
    connect(runner_, &ScannerRunner::failedToStart,  this, &MainWindow::onScannerFailedToStart);

    buildUi();
    loadSettings();

    if (binaryPath_->text().isEmpty()) {
        binaryPath_->setText(findDefaultBinary());
    }
    resize(960, 760);
}

void MainWindow::buildUi() {
    auto* central = new QWidget;
    setCentralWidget(central);
    auto* mainLayout = new QVBoxLayout(central);

    // ---- Mode + target ----
    {
        auto* modeRow = new QHBoxLayout;
        modeFile_ = new QRadioButton(tr("Single PE file"));
        modeDir_  = new QRadioButton(tr("Directory (batch)"));
        modeFile_->setChecked(true);
        modeRow->addWidget(modeFile_);
        modeRow->addWidget(modeDir_);
        modeRow->addStretch();
        mainLayout->addLayout(modeRow);
    }
    {
        auto* row = new QHBoxLayout;
        row->addWidget(new QLabel(tr("Target:")));
        targetPath_ = new QLineEdit;
        targetPath_->setPlaceholderText(tr("/path/to/ntdll.dll  —  or drop a file/directory here"));
        row->addWidget(targetPath_, 1);
        auto* browse = new QPushButton(tr("Browse…"));
        connect(browse, &QPushButton::clicked, this, &MainWindow::onBrowseTarget);
        row->addWidget(browse);
        mainLayout->addLayout(row);

        recursive_ = new QCheckBox(tr("Recurse into subdirectories  (--recursive)"));
        mainLayout->addWidget(recursive_);
    }

    // ---- Scanning options ----
    {
        auto* g = new QGroupBox(tr("Scanning"));
        auto* form = new QFormLayout(g);

        maxBytes_ = new QSpinBox; maxBytes_->setRange(1, 64);     maxBytes_->setValue(10);
        maxInsn_  = new QSpinBox; maxInsn_->setRange(1, 16);      maxInsn_->setValue(5);
        minScore_ = new QSpinBox; minScore_->setRange(0, 100);    minScore_->setValue(0);
        limit_    = new QSpinBox; limit_->setRange(0, 1000000);   limit_->setValue(0);

        filter_   = new QLineEdit;
        filter_->setPlaceholderText(tr("pop rcx ; pop rdx     or     write-mem     or     syscall"));
        badBytes_ = new QLineEdit;
        badBytes_->setPlaceholderText(tr("00,0a,0d"));

        form->addRow(tr("Max bytes back  (--max-bytes):"), maxBytes_);
        form->addRow(tr("Max instructions  (--max-insn):"), maxInsn_);
        form->addRow(tr("Min score  (--min-score):"), minScore_);
        form->addRow(tr("Filter  (--filter):"), filter_);
        form->addRow(tr("Bad bytes  (--badbytes):"), badBytes_);
        form->addRow(tr("Limit, 0 = all  (--limit):"), limit_);

        mainLayout->addWidget(g);
    }

    // ---- CFG / Symbols ----
    {
        auto* g = new QGroupBox(tr("CFG / Symbols"));
        auto* v = new QVBoxLayout(g);

        auto* cfgRow = new QHBoxLayout;
        cfgRow->addWidget(new QLabel(tr("CFG:")));
        cfgAny_     = new QRadioButton(tr("Any"));
        cfgOnly_    = new QRadioButton(tr("Only CFG-valid targets  (--only-cfg)"));
        cfgExclude_ = new QRadioButton(tr("Exclude CFG-valid  (--exclude-cfg)"));
        cfgAny_->setChecked(true);
        cfgGroup_ = new QButtonGroup(this);
        cfgGroup_->addButton(cfgAny_);
        cfgGroup_->addButton(cfgOnly_);
        cfgGroup_->addButton(cfgExclude_);
        cfgRow->addWidget(cfgAny_);
        cfgRow->addWidget(cfgOnly_);
        cfgRow->addWidget(cfgExclude_);
        cfgRow->addStretch();
        v->addLayout(cfgRow);

        noSymbols_ = new QCheckBox(tr("Skip EAT/.pdata symbol resolution  (--no-symbols, faster)"));
        v->addWidget(noSymbols_);
        pdb_ = new QCheckBox(tr("Resolve via PDB / dbghelp  (--pdb, Windows only)"));
        v->addWidget(pdb_);

        mainLayout->addWidget(g);
    }

    // ---- Output format + binary path + action buttons ----
    {
        auto* row = new QHBoxLayout;
        row->addWidget(new QLabel(tr("Output format:")));
        format_ = new QComboBox;
        format_->addItems({"text", "json", "ropper", "pwntools"});
        row->addWidget(format_);
        row->addStretch();

        copyCmdButton_ = new QPushButton(tr("Copy cmdline"));
        connect(copyCmdButton_, &QPushButton::clicked, this, &MainWindow::onCopyCmdline);
        row->addWidget(copyCmdButton_);

        saveButton_ = new QPushButton(tr("Save output…"));
        connect(saveButton_, &QPushButton::clicked, this, &MainWindow::onSaveOutput);
        row->addWidget(saveButton_);

        mainLayout->addLayout(row);
    }
    {
        auto* row = new QHBoxLayout;
        row->addWidget(new QLabel(tr("rop_scanner binary:")));
        binaryPath_ = new QLineEdit;
        binaryPath_->setPlaceholderText(tr("auto-detect"));
        row->addWidget(binaryPath_, 1);
        auto* b = new QPushButton(tr("Browse…"));
        connect(b, &QPushButton::clicked, this, &MainWindow::onBrowseBinary);
        row->addWidget(b);
        mainLayout->addLayout(row);
    }

    // ---- Run / Cancel ----
    {
        auto* row = new QHBoxLayout;
        runButton_ = new QPushButton(tr("▶  Run scan"));
        runButton_->setMinimumHeight(40);
        QFont rb = runButton_->font(); rb.setBold(true); runButton_->setFont(rb);
        cancelButton_ = new QPushButton(tr("Cancel"));
        cancelButton_->setEnabled(false);
        cancelButton_->setMinimumHeight(40);
        connect(runButton_,    &QPushButton::clicked, this, &MainWindow::onRun);
        connect(cancelButton_, &QPushButton::clicked, this, &MainWindow::onCancel);
        row->addWidget(runButton_, 1);
        row->addWidget(cancelButton_);
        mainLayout->addLayout(row);
    }

    // ---- Status + output ----
    {
        statusLabel_ = new QLabel(tr("Idle"));
        statusLabel_->setStyleSheet("QLabel { color: gray; padding: 2px 0; }");
        mainLayout->addWidget(statusLabel_);

        output_ = new QTextEdit;
        output_->setReadOnly(true);
        QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        mono.setPointSize(11);
        output_->setFont(mono);
        output_->setStyleSheet("QTextEdit { background-color: #1e1e1e; color: #d4d4d4; }");
        mainLayout->addWidget(output_, 1);
    }

    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::onBrowseTarget() {
    QString p;
    if (modeFile_->isChecked()) {
        p = QFileDialog::getOpenFileName(
            this, tr("Choose PE file"),
            targetPath_->text(),
            tr("PE files (*.dll *.exe *.sys *.cpl *.ocx *.drv *.efi);;All files (*)"));
    } else {
        p = QFileDialog::getExistingDirectory(
            this, tr("Choose directory"), targetPath_->text());
    }
    if (!p.isEmpty()) targetPath_->setText(p);
}

void MainWindow::onBrowseBinary() {
    QString p = QFileDialog::getOpenFileName(
        this, tr("Locate rop_scanner binary"),
        binaryPath_->text(),
        tr("Executables (*)"));
    if (!p.isEmpty()) binaryPath_->setText(p);
}

QStringList MainWindow::buildArgs() const {
    QStringList a;

    if (modeFile_->isChecked()) {
        a << targetPath_->text();
    } else {
        a << "--dir" << targetPath_->text();
        if (recursive_->isChecked()) a << "--recursive";
    }

    a << "--max-bytes" << QString::number(maxBytes_->value());
    a << "--max-insn"  << QString::number(maxInsn_->value());

    if (minScore_->value() > 0) a << "--min-score" << QString::number(minScore_->value());
    if (limit_->value()    > 0) a << "--limit"     << QString::number(limit_->value());
    if (!filter_->text().isEmpty())   a << "--filter"   << filter_->text();
    if (!badBytes_->text().isEmpty()) a << "--badbytes" << badBytes_->text();

    if (cfgOnly_->isChecked())    a << "--only-cfg";
    if (cfgExclude_->isChecked()) a << "--exclude-cfg";
    if (noSymbols_->isChecked())  a << "--no-symbols";
    if (pdb_->isChecked())        a << "--pdb";

    a << "--format" << format_->currentText();
    return a;
}

QString MainWindow::humanCmdline() const {
    QStringList parts;
    parts << shellQuote(binaryPath_->text());
    for (const QString& a : buildArgs()) parts << shellQuote(a);
    return parts.join(' ');
}

QString MainWindow::findDefaultBinary() const {
    const QString name =
#ifdef Q_OS_WIN
        "rop_scanner.exe";
#else
        "rop_scanner";
#endif

    QString appDir = QCoreApplication::applicationDirPath();
    QStringList candidates = {
        appDir + "/" + name,
        appDir + "/../bin/" + name,
        appDir + "/../../bin/" + name,
        appDir + "/../../build/bin/" + name,
        appDir + "/../../../build/bin/" + name,
        appDir + "/../../build/bin/Release/" + name,
        appDir + "/../Resources/" + name,                 // mac bundle layout
        QDir::currentPath() + "/" + name,
    };
    for (const QString& c : candidates) {
        QString clean = QDir::cleanPath(c);
        if (QFileInfo(clean).isExecutable()) return clean;
    }
    return {};
}

void MainWindow::onRun() {
    if (runner_->isRunning()) return;

    QString bin = binaryPath_->text();
    if (bin.isEmpty() || !QFileInfo(bin).isExecutable()) {
        QMessageBox::warning(this, tr("rop_scanner binary"),
            tr("Set the path to the rop_scanner executable first.\n\n"
               "Tried to auto-detect relative to the GUI binary but found nothing usable."));
        return;
    }
    if (targetPath_->text().isEmpty()) {
        QMessageBox::warning(this, tr("Target"),
            tr("Pick a PE file or directory to scan."));
        return;
    }

    output_->clear();
    statusLabel_->setText(tr("Running…"));
    statusLabel_->setStyleSheet("QLabel { color: #d29922; padding: 2px 0; }");
    runButton_->setEnabled(false);
    cancelButton_->setEnabled(true);
    saveSettings();

    QStringList args = buildArgs();
    output_->append(QString("[gui] %1\n").arg(humanCmdline()));

    runner_->run(bin, args);
}

void MainWindow::onCancel() {
    if (!runner_->isRunning()) return;
    statusLabel_->setText(tr("Cancelling…"));
    runner_->cancel();
}

void MainWindow::onScannerStarted() {
    statusBar()->showMessage(tr("Scan started"));
}

void MainWindow::onScannerOut(const QString& text) {
    output_->moveCursor(QTextCursor::End);
    output_->insertPlainText(text);
    output_->moveCursor(QTextCursor::End);
}

void MainWindow::onScannerErr(const QString& text) {
    output_->moveCursor(QTextCursor::End);
    QTextCharFormat fmt;
    fmt.setForeground(QColor("#d29922"));
    output_->setCurrentCharFormat(fmt);
    output_->insertPlainText(text);
    output_->setCurrentCharFormat(QTextCharFormat{});
    output_->moveCursor(QTextCursor::End);
}

void MainWindow::onScannerFinished(int code, QProcess::ExitStatus status) {
    runButton_->setEnabled(true);
    cancelButton_->setEnabled(false);
    QString state = status == QProcess::NormalExit ? tr("normal") : tr("crashed/killed");
    QString msg = tr("Finished — exit %1 (%2)").arg(code).arg(state);
    statusLabel_->setText(msg);
    statusLabel_->setStyleSheet(
        code == 0 ? "QLabel { color: #3fb950; padding: 2px 0; }"
                  : "QLabel { color: #f85149; padding: 2px 0; }");
    statusBar()->showMessage(msg, 5000);
}

void MainWindow::onScannerFailedToStart(const QString& reason) {
    runButton_->setEnabled(true);
    cancelButton_->setEnabled(false);
    statusLabel_->setText(tr("Failed to start: %1").arg(reason));
    statusLabel_->setStyleSheet("QLabel { color: #f85149; padding: 2px 0; }");
    QMessageBox::critical(this, tr("Failed to launch"),
        tr("Could not start the rop_scanner binary:\n%1").arg(reason));
}

void MainWindow::onSaveOutput() {
    QString defaultName = QString("rop_scanner_output.%1")
        .arg(format_->currentText() == "json" ? "json"
           : format_->currentText() == "pwntools" ? "py"
           : "txt");
    QString p = QFileDialog::getSaveFileName(this, tr("Save output"),
                                             QDir::homePath() + "/" + defaultName,
                                             tr("All files (*)"));
    if (p.isEmpty()) return;
    QFile f(p);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QMessageBox::warning(this, tr("Save"), tr("Cannot write to %1").arg(p));
        return;
    }
    QTextStream(&f) << output_->toPlainText();
    statusBar()->showMessage(tr("Saved to %1").arg(p), 4000);
}

void MainWindow::onCopyCmdline() {
    QApplication::clipboard()->setText(humanCmdline());
    statusBar()->showMessage(tr("Cmdline copied to clipboard"), 2500);
}

void MainWindow::dragEnterEvent(QDragEnterEvent* event) {
    if (event->mimeData()->hasUrls()) event->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent* event) {
    const auto urls = event->mimeData()->urls();
    if (urls.isEmpty()) return;
    const QString local = urls.first().toLocalFile();
    if (local.isEmpty()) return;
    QFileInfo info(local);
    if (info.isDir()) modeDir_->setChecked(true);
    else              modeFile_->setChecked(true);
    targetPath_->setText(local);
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (runner_->isRunning()) runner_->cancel();
    saveSettings();
    QMainWindow::closeEvent(event);
}

void MainWindow::loadSettings() {
    QSettings s;
    targetPath_->setText(s.value("target").toString());
    binaryPath_->setText(s.value("binary").toString());
    if (s.value("mode").toString() == "dir") modeDir_->setChecked(true);

    recursive_->setChecked(s.value("recursive", false).toBool());
    maxBytes_->setValue(s.value("maxBytes", 10).toInt());
    maxInsn_->setValue(s.value("maxInsn", 5).toInt());
    minScore_->setValue(s.value("minScore", 0).toInt());
    limit_->setValue(s.value("limit", 0).toInt());
    filter_->setText(s.value("filter").toString());
    badBytes_->setText(s.value("badbytes").toString());
    noSymbols_->setChecked(s.value("noSymbols", false).toBool());
    pdb_->setChecked(s.value("pdb", false).toBool());

    QString cfg = s.value("cfg", "any").toString();
    if      (cfg == "only")    cfgOnly_->setChecked(true);
    else if (cfg == "exclude") cfgExclude_->setChecked(true);
    else                       cfgAny_->setChecked(true);

    int fi = format_->findText(s.value("format", "text").toString());
    if (fi >= 0) format_->setCurrentIndex(fi);
}

void MainWindow::saveSettings() {
    QSettings s;
    s.setValue("target",    targetPath_->text());
    s.setValue("binary",    binaryPath_->text());
    s.setValue("mode",      modeDir_->isChecked() ? "dir" : "file");
    s.setValue("recursive", recursive_->isChecked());
    s.setValue("maxBytes",  maxBytes_->value());
    s.setValue("maxInsn",   maxInsn_->value());
    s.setValue("minScore",  minScore_->value());
    s.setValue("limit",     limit_->value());
    s.setValue("filter",    filter_->text());
    s.setValue("badbytes",  badBytes_->text());
    s.setValue("noSymbols", noSymbols_->isChecked());
    s.setValue("pdb",       pdb_->isChecked());

    QString cfg = "any";
    if      (cfgOnly_->isChecked())    cfg = "only";
    else if (cfgExclude_->isChecked()) cfg = "exclude";
    s.setValue("cfg",    cfg);
    s.setValue("format", format_->currentText());
}
