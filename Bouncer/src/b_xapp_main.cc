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

sig_atomic_t sig_raised = 0;

void signalHandler( int signum ) {
	mdclog_write(MDCLOG_INFO, "Interrupt signal %d (%s) received.", signum, strsignal(signum));
	sig_raised = 1;
}

int main(int argc, char *argv[]) {
	// signal handler to stop xapp gracefully
	sigset_t set;
	int sig;
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	sigprocmask(SIG_BLOCK, &set, NULL);

	mdclog_format_initialize(1);	// init mdclog by reading CONFIG_MAP_NAME env var

	mdclog_write(MDCLOG_INFO, "Starting bouncer-xapp");

	//get configuration
	XappSettings config;
	//change the priority depending upon application requirement
	config.loadDefaultSettings();
	config.loadEnvVarSettings();
	config.loadXappDescriptorSettings();
	config.loadCmdlineSettings(argc, argv);

	//getting the listening port and xapp name info
	std::string  port = config[XappSettings::SettingName::BOUNCER_PORT];

	//initialize rmr
	std::shared_ptr<XappRmr> rmr = std::make_shared<XappRmr>(port);
	rmr->xapp_rmr_init(true);


	//Create Subscription Handler if Xapp deals with Subscription.
	SubscriptionHandler sub_handler;

	//create Bouncer Xapp Instance.
	std::unique_ptr<Xapp> b_xapp;
	b_xapp = std::make_unique<Xapp>(std::ref(config),std::ref(*rmr));

	mdclog_write(MDCLOG_INFO, "Created Bouncer Xapp Instance");

	// Register async signal handler to stop on startup errors received by REST calls
	signal(SIGTERM, signalHandler);

	//start listener threads and register message handlers.
	int num_threads = std::stoi(config[XappSettings::SettingName::THREADS]);
	if (num_threads > 1) {
		mdclog_write(MDCLOG_WARN, "Using default number of threads = 1. Multithreading on xapp receiver is not supported yet.");
	}
	mdclog_write(MDCLOG_INFO, "Starting Listener Threads. Number of Workers = %d", num_threads);

	std::unique_ptr<A1Handler> a1handler;
	try {
		a1handler = std::make_unique<A1Handler>(config);

	} catch (std::exception &e) {
		mdclog_write(MDCLOG_ERR, "Unable to startup xapp %s. Reason = %s",
					config[XappSettings::SettingName::XAPP_ID].c_str(),  e.what());

		exit(EXIT_FAILURE);
	}

	std::unique_ptr<XappMsgHandler> mp_handler = std::make_unique<XappMsgHandler>(config[XappSettings::SettingName::XAPP_ID], sub_handler, std::ref(*a1handler), std::ref(*rmr));

	b_xapp->start_xapp_receiver(std::ref(*mp_handler), num_threads);

	sleep(2);	// we need to wait to allow kubernetes dns to notice this xApp before proceed to startup routines

	//Startup E2 subscription
	try {
		b_xapp->startup(sub_handler);

	} catch(std::exception &e) {
		mdclog_write(MDCLOG_ERR, "Unable to startup xapp %s. Reason = %s",
					config[XappSettings::SettingName::XAPP_ID].c_str(),  e.what());

		b_xapp->shutdown();

		exit(EXIT_FAILURE);
	}

	if (!sig_raised) {
		signal(SIGTERM, NULL);	// unregister async signal handler

		do {
			int ret_val = sigwait(&set, &sig);	// sync: we wait for a signal to proceed
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
		} while(sig != SIGINT && sig != SIGTERM);
	}

	b_xapp->shutdown(); // will start both the subscription and registration delete procedures and join threads

	mdclog_write(MDCLOG_INFO, "xapp %s has finished", config[XappSettings::SettingName::XAPP_ID].c_str());

	return 0;
}



