// Copyright (c) 2019-2020 The PIXV developers
// Copyright (c) 2021 The DECENOMY Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SNACKBAR_H
#define SNACKBAR_H

#include <QDialog>
#include <QResizeEvent>

class MULTISYSGUI;

namespace Ui {
class SnackBar;
}

class SnackBar : public QDialog
{
    Q_OBJECT

public:
    explicit SnackBar(MULTISYSGUI* _window = nullptr, QWidget *parent = nullptr);
    ~SnackBar();

    virtual void showEvent(QShowEvent *event) override;
    void setText(const QString& text);

private Q_SLOTS:
    void hideAnim();
    void windowResizeEvent(QResizeEvent* event);
private:
    Ui::SnackBar *ui;
    MULTISYSGUI* window = nullptr;
    int timeout;
    // timeout based on message length, always between 2 (default) and 10 seconds.
    static const int MIN_TIMEOUT = 2000;          // < 40 chars
    static const int MAX_TIMEOUT = 10000;         // > 200 chars
    static int GetTimeout(const QString& message);
    void setTimeoutForText(const QString& text);
};

#endif // SNACKBAR_H
