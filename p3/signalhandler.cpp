#include <atomic>

#include "signalhandler.h"

SignalHandler<SIGHUP> _sighup_handler;
SignalHandler<SIGUSR1> _sigusr1_handler;
SignalHandler<SIGUSR2> _sigusr2_handler;

