#include "ScannerRunner.h"

ScannerRunner::ScannerRunner(QObject* parent) : QObject(parent) {
    connect(&process_, &QProcess::readyReadStandardOutput,
            this, &ScannerRunner::onReadyOut);
    connect(&process_, &QProcess::readyReadStandardError,
            this, &ScannerRunner::onReadyErr);
    connect(&process_,
            QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &ScannerRunner::onFinished);
    connect(&process_, &QProcess::errorOccurred,
            this, &ScannerRunner::onErrorOccurred);
}

void ScannerRunner::run(const QString& binary, const QStringList& args) {
    if (process_.state() != QProcess::NotRunning) return;
    process_.setProcessChannelMode(QProcess::SeparateChannels);
    process_.start(binary, args);
    if (process_.waitForStarted(5000)) {
        emit started();
    }
}

void ScannerRunner::cancel() {
    if (process_.state() == QProcess::NotRunning) return;
    process_.kill();
    process_.waitForFinished(2000);
}

bool ScannerRunner::isRunning() const {
    return process_.state() != QProcess::NotRunning;
}

void ScannerRunner::onReadyOut() {
    emit stdoutChunk(QString::fromLocal8Bit(process_.readAllStandardOutput()));
}

void ScannerRunner::onReadyErr() {
    emit stderrChunk(QString::fromLocal8Bit(process_.readAllStandardError()));
}

void ScannerRunner::onFinished(int code, QProcess::ExitStatus status) {
    emit finished(code, status);
}

void ScannerRunner::onErrorOccurred(QProcess::ProcessError err) {
    if (err == QProcess::FailedToStart) {
        emit failedToStart(process_.errorString());
    }
}
