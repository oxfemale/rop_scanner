#include "MainWindow.h"

#include <QApplication>

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    app.setApplicationName("rop_scanner GUI");
    app.setOrganizationName("rop_scanner");
    app.setOrganizationDomain("github.com/oxfemale/rop_scanner");

    MainWindow w;
    w.show();
    return app.exec();
}
