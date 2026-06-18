#pragma once

#include <QObject>
#include <QProcess>
#include <QString>
#include <QStringList>

// Thin wrapper around QProcess for spawning the rop_scanner CLI.
// Emits incremental stdout/stderr so the GUI can stream output as it arrives.
class ScannerRunner : public QObject {
    Q_OBJECT
public:
    explicit ScannerRunner(QObject* parent = nullptr);

    void run(const QString& binary, const QStringList& args);
    void cancel();
    bool isRunning() const;

signals:
    void started();
    void stdoutChunk(const QString& text);
    void stderrChunk(const QString& text);
    void finished(int exitCode, QProcess::ExitStatus status);
    void failedToStart(const QString& reason);

private slots:
    void onReadyOut();
    void onReadyErr();
    void onFinished(int code, QProcess::ExitStatus status);
    void onErrorOccurred(QProcess::ProcessError err);

private:
    QProcess process_;
};
