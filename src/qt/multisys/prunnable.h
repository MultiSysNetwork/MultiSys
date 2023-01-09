// Copyright (c) 2019 The PIXV developers
// Copyright (c) 2021 The DECENOMY Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MULTISYS_CORE_NEW_GUI_PRUNNABLE_H
#define MULTISYS_CORE_NEW_GUI_PRUNNABLE_H

class Runnable {
public:
    virtual void run(int type) = 0;
    virtual void onError(QString error, int type) = 0;
};

#endif //MULTISYS_CORE_NEW_GUI_PRUNNABLE_H
