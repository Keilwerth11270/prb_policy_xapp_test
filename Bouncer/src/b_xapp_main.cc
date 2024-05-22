/*
# ==================================================================================
# Copyright (c) 2020 HCL Technologies Limited.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==================================================================================
*/

#include "xapp.hpp"
#include "a1_mgmt.hpp"
#include <mdclog/mdclog.h>

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;
using namespace utility;

/*
 * Variable: sig_raised
 * Description: A global variable of type sig_atomic_t used as a flag to indicate if a signal has been raised.
 *              It is set to 1 when a signal is received by the signalHandler function.
 */
sig_atomic_t sig_raised = 0;

/*
 * Function: signalHandler
 * Description: A signal handler function that is called when a signal is received.
 *              It logs the received signal information and sets the sig_raised flag to 1.
 * Parameters:
 *   - signum: The signal number received.
 * Returns: None
 */
void signalHandler(int signum) {
    mdclog_write(MDCLOG_INFO, "Interrupt signal %d (%s) received.", signum, strsignal(signum));
    sig_raised = 1;
}

/*
 * Function: main
 * Description: The main function of the bouncer-xapp application.
 *              It initializes the application, sets up signal handling, creates instances of necessary classes,
 *              starts the xApp receiver, and performs the startup and shutdown procedures.
 * Parameters:
 *   - argc: The number of command-line arguments.
 *   - argv: An array of command-line argument strings.
 * Returns: 0 on successful execution.
 */
int main(int argc, char *argv[]) {
    // Step 1: Set up signal handling
    sigset_t set;
    int sig;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigprocmask(SIG_BLOCK, &set, NULL);

    // Step 2: Initialize mdclog by reading CONFIG_MAP_NAME environment variable
    mdclog_format_initialize(1);
    mdclog_write(MDCLOG_INFO, "Starting bouncer-xapp");

    // Step 3: Get configuration settings
    XappSettings config;
    config.loadDefaultSettings();
    config.loadEnvVarSettings();
    config.loadXappDescriptorSettings();
    config.loadCmdlineSettings(argc, argv);

    // Step 4: Get the listening port and xApp name information
    std::string port = config[XappSettings::SettingName::BOUNCER_PORT];

    // Step 5: Initialize RMR (RIC Message Router)
    std::shared_ptr<XappRmr> rmr = std::make_shared<XappRmr>(port);
    rmr->xapp_rmr_init(true);

    // Step 6: Create Subscription Handler if xApp deals with subscriptions
    SubscriptionHandler sub_handler;

    // Step 7: Create Bouncer xApp instance
    std::unique_ptr<Xapp> b_xapp;
    b_xapp = std::make_unique<Xapp>(std::ref(config), std::ref(*rmr));
    mdclog_write(MDCLOG_INFO, "Created Bouncer Xapp Instance");

    // Step 8: Register async signal handler to stop on startup errors received by REST calls
    signal(SIGTERM, signalHandler);

    // Step 9: Start listener threads and register message handlers
    int num_threads = std::stoi(config[XappSettings::SettingName::THREADS]);
    if (num_threads > 1) {
        mdclog_write(MDCLOG_WARN, "Using default number of threads = 1. Multithreading on xapp receiver is not supported yet.");
    }
    mdclog_write(MDCLOG_INFO, "Starting Listener Threads. Number of Workers = %d", num_threads);

    // Step 10: Create A1 Handler instance
    std::unique_ptr<A1Handler> a1handler;
    try {
        a1handler = std::make_unique<A1Handler>(config);
    } catch (std::exception &e) {
        mdclog_write(MDCLOG_ERR, "Unable to startup xapp %s. Reason = %s", config[XappSettings::SettingName::XAPP_ID].c_str(), e.what());
        exit(EXIT_FAILURE);
    }

    // Step 11: Create XappMsgHandler instance
    std::unique_ptr<XappMsgHandler> mp_handler = std::make_unique<XappMsgHandler>(config[XappSettings::SettingName::XAPP_ID], sub_handler, std::ref(*a1handler), std::ref(*rmr));

    // Step 12: Start xApp receiver
    b_xapp->start_xapp_receiver(std::ref(*mp_handler), num_threads);
    sleep(2); // Wait to allow Kubernetes DNS to notice this xApp before proceeding to startup routines

    // Step 13: Startup E2 subscription
    try {
		// b_xapp->startup(sub_handler);
        b_xapp->startup();
    } catch (std::exception &e) {
        mdclog_write(MDCLOG_ERR, "Unable to startup xapp %s. Reason = %s", config[XappSettings::SettingName::XAPP_ID].c_str(), e.what());
        b_xapp->shutdown();
        exit(EXIT_FAILURE);
    }

    // Step 14: Wait for signals
    if (!sig_raised) {
        signal(SIGTERM, NULL); // Unregister async signal handler
        do {
            int ret_val = sigwait(&set, &sig); // Synchronously wait for a signal to proceed
            if (ret_val == -1) {
                mdclog_write(MDCLOG_ERR, "sigwait failed");
            } else {
                switch (sig) {
                    case SIGINT:
                        mdclog_write(MDCLOG_INFO, "SIGINT was received");
                        break;
                    case SIGTERM:
                        mdclog_write(MDCLOG_INFO, "SIGTERM was received");
                        break;
                    default:
                        mdclog_write(MDCLOG_WARN, "sigwait returned with sig: %d\n", sig);
                }
            }
        } while (sig != SIGINT && sig != SIGTERM);
    }

    // Step 15: Shutdown xApp
    b_xapp->shutdown(); // Start both the subscription and registration delete procedures and join threads
    mdclog_write(MDCLOG_INFO, "xapp %s has finished", config[XappSettings::SettingName::XAPP_ID].c_str());

    return 0;
}