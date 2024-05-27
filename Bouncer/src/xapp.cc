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
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>
#include <cpprest/uri.h>
#include <cpprest/json.h>

#include "xapp-asn/e2sm/e2sm_subscription.hpp"
#include "xapp-mgmt/msgs_proc.hpp"
#include "xapp-asn/e2sm/e2sm_indication.hpp"

using namespace utility;
using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace concurrency::streams;
using jsonn = nlohmann::json;

#define BUFFER_SIZE 1024

/*
 * Constructor: Xapp
 * Description: Initializes the Xapp object with the provided configuration and RMR references.
 * Parameters:
 *   - config: Reference to the XappSettings object containing the xApp configuration.
 *   - rmr: Reference to the XappRmr object for RIC Message Router (RMR) communication.
 */
Xapp::Xapp(XappSettings &config, XappRmr &rmr) {
    rmr_ref = &rmr;
    config_ref = &config;
    xapp_mutex = NULL;
    subhandler_ref = NULL;
    return;
}

/*
 * Destructor: ~Xapp
 * Description: Cleans up the resources used by the Xapp object.
 */
Xapp::~Xapp(void) {
    if (xapp_mutex != NULL) {
        xapp_mutex->~mutex();
        delete xapp_mutex;
    }
}

/*
 * Function: stop
 * Description: Stops the xApp. Note - To be run only from unit test scripts.
 *              It acquires a mutex lock, sets the RMR to stop listening, destructs the XappRmr object,
 *              and detaches the receiver threads.
 * Parameters: None
 * Returns: None
 */
void Xapp::stop(void) {
    // Step 1: Acquire a mutex lock to ensure thread safety
    std::lock_guard<std::mutex> guard(*xapp_mutex);

    // Step 2: Set the RMR to stop listening
    rmr_ref->set_listen(false);

    // Step 3: Destruct the XappRmr object
    rmr_ref->~XappRmr();

    // Step 4: Detach the receiver threads
    //         Note: The function should be called only in unit tests
    int threadcnt = xapp_rcv_thread.size();
    for (int i = 0; i < threadcnt; i++) {
        xapp_rcv_thread[i].detach();
    }

    // Step 5: Sleep for a short duration (10 seconds)
    sleep(10);
}

// -------------------------------------------------------------------------------------------   vvv READ THIS vvv   -------------------------------------------------------------------------------------------

/*
The xApp Startup Process:

1. The xApp begins its startup process in the startup() function.

2. It starts by calling the start_xapp_receiver() function, which sets up the xApp to listen for
    incoming messages from the RAN (Radio Access Network) using the RMR (RIC Message Router) protocol.

3. The xApp then fetches the list of connected gNodeBs (base stations) by calling the
    fetch_connected_nodeb_list() function, which retrieves the information from the E2 Manager service.

4. To register itself with the RIC (RAN Intelligent Controller) platform, the xApp sends a
    registration request to the RIC's Application Manager (AppMgr) using the startup_registration_request()
    function.

			4.1 When the AppMgr receives a registration request from an xApp through the startup_registration_request()
				function, the following steps occur:

			4.2 The AppMgr processes the registration request and extracts the relevant information about the xApp,
			    such as its name, version, config-file path, instance name, HTTP endpoint, and RMR endpoint.

			4.3 The AppMgr communicates with the Routing Manager (RtMgr) to register the xApp's endpoints.
			    It provides the RtMgr with the xApp's HTTP and RMR endpoints, allowing the RtMgr to establish
			    the necessary routes for communication between the xApp and other components of the RIC platform.

			4.4 The AppMgr may also interact with the Shared Data Layer (SDL) to store and retrieve xApp-related
			    information. It can store the xApp's registration details and configuration in the SDL, making it
			    accessible to other RIC components.

			4.5 If the registration is successful, the AppMgr sends a response back to the xApp indicating that
			    it has been successfully registered with the RIC platform.

			4.6 The AppMgr may also notify other RIC components, such as the E2 Manager (E2Mgr), about the newly
			    registered xApp. This allows the E2Mgr to establish the necessary connections and interactions
			    between the xApp and the E2 nodes.

5. The xApp starts an HTTP listener by calling the startup_http_listener() function, which sets up
    an endpoint to receive REST notifications from the RIC platform.

6. To establish a connection with the E2 nodes, the xApp sends subscription requests to the E2 nodes
    using the startup_subscribe_requests() function. This function builds and sends the subscription
    requests based on the connected gNodeBs and the xApp's configuration.

7. Finally, the xApp initiates a separate thread by calling the send_hardcoded_policy() function,
    which periodically sends a hardcoded policy to the RAN nodes to enforce certain behavior or parameters.
*/

// -------------------------------------------------------------------------------------------   ^^^ READ THIS ^^^   -------------------------------------------------------------------------------------------

/*
 * Function: startup
 * Description: Performs the startup sequence of the xApp.
 *              It starts the xApp receiver, fetches the connected nodeB list, sends the registration request,
 *              starts the HTTP listener, sends subscription requests, and starts a separate thread for sending
 *              a hardcoded policy.
 * Parameters:
 *   - sub_ref: Reference to the SubscriptionHandler object for handling subscriptions.
 * Returns: None
 */
void Xapp::startup(SubscriptionHandler &sub_ref) {
//void Xapp::startup(SubscriptionHandler &sub_ref) {
    // Step 1: Store the reference to the SubscriptionHandler object
    subhandler_ref = &sub_ref;

    // Step 2: Start the xApp receiver --- BEING DONE IN b_xapp_main.cc THERE IS NO NEED TO RUN THIS FUNCTION FROM HERE
	//How it is being run in that file:
	//b_xapp->start_xapp_receiver(std::ref(*mp_handler), num_threads);
    // start_xapp_receiver();

    // Step 3: Fetch the connected nodeB list
    fetch_connected_nodeb_list();

	//retrieves the list of gNodeB IDs - DEPRECATED FUNCTION
	//set_rnib_gnblist();

    // Step 4: Send the registration request (throws std::exception)
    startup_registration_request();

    // Step 5: Start the HTTP listener (throws std::exception)
    startup_http_listener();

    // Step 6: Send subscription requests (throws std::exception)
    startup_subscribe_requests();

	//read A1 policies - DEPRECATED FUNCTION SINCE WE ARE NO LONGER RETRIEVING POLICIES FROM THE A1 INTERFACE
	//startup_get_policies();

    // Step 7: Start a separate thread for sending a hardcoded policy
    // std::thread policy_thread(&Xapp::send_hardcoded_policy, this);
    // policy_thread.detach();

    return;
}


/*
 * Function: create_false_a1_payload
 * Description: This function creates a false A1 policy payload for testing purposes.
 *              It creates an a1_policy_helper object and populates it with hardcoded values
 *              representing a policy for controlling the maximum PRB (Physical Resource Block)
 *              allocation for specific UEs.
 * Parameters: None
 * Returns: a1_policy_helper object containing the false A1 policy payload
 */
a1_policy_helper Xapp::create_false_a1_payload() {
    // Step 1: Create an instance of the a1_policy_helper object
    //         This object will store the false A1 policy payload
    a1_policy_helper helper;
    
    // Step 2: Set the properties of the a1_policy_helper object
    //         These properties define the characteristics of the A1 policy
    
    // Step 2.1: Set the operation type to "CREATE"
    //           This indicates that the policy is being created
    helper.operation = "CREATE";
    
    // Step 2.2: Set the policy type ID to "20008"
    //           This is a custom policy type ID used for the false A1 policy
    helper.policy_type_id = "20008";
    
    // Step 2.3: Set the policy instance ID to "instance_1"
    //           This is a unique identifier for the policy instance
    helper.policy_instance_id = "instance_1";
    
    // Step 2.4: Set the handler ID to "handler_1"
    //           This is an identifier for the handler associated with the policy
    helper.handler_id = "handler_1";
    
    // Step 2.5: Set the status to "OK"
    //           This indicates that the policy creation is successful
    helper.status = "OK";
    
    // Step 3: Set the hardcoded JSON payload string
    //         This is a JSON string representing the policy payload
    //         In this case, it defines the maximum PRB allocation for two UEs
    helper.payload = "{\"ue_rc\": [{\"ue_index\": 1, \"max_prb\": 33}, {\"ue_index\": 2, \"max_prb\": 17}]}";
    
    // Step 4: Create the first ue_rc_helper object
    //         This object represents the policy for the first UE
    std::shared_ptr<ue_rc_helper> ue1 = std::make_shared<ue_rc_helper>();
    
    // Step 4.1: Set the UE index to 1
    //           This is a unique identifier for the UE
    ue1->ue_index = 1;
    
    // Step 4.2: Set the maximum PRB allocation to 33
    //           This specifies the maximum number of PRBs that can be allocated to the UE
    ue1->max_prb = 33;
    
    // Step 5: Add the first ue_rc_helper object to the helper's ue_list
    //         The ue_list is a vector that stores the policy for each UE
    helper.ue_list.emplace_back(ue1);
    
    // Step 6: Create the second ue_rc_helper object
    //         This object represents the policy for the second UE
    std::shared_ptr<ue_rc_helper> ue2 = std::make_shared<ue_rc_helper>();
    
    // Step 6.1: Set the UE index to 2
    //           This is a unique identifier for the UE
    ue2->ue_index = 2;
    
    // Step 6.2: Set the maximum PRB allocation to 17
    //           This specifies the maximum number of PRBs that can be allocated to the UE
    ue2->max_prb = 17;
    
    // Step 7: Add the second ue_rc_helper object to the helper's ue_list
    //         The ue_list now contains the policy for both UEs
    helper.ue_list.emplace_back(ue2);
    
    // Step 8: Return the a1_policy_helper object
    //         The object now contains the false A1 policy payload
    return helper;
}



/*
 * Function: send_false_policy
 * Description: This function is responsible for sending a false policy to the RAN.
 *              It creates a control request message based on the provided a1_policy_helper object
 *              and sends it to the RAN node using the RMR (RIC Message Router) protocol.
 * Parameters:
 *   - helper: Reference to an a1_policy_helper object containing the policy information.
 * Returns: None
 */
void Xapp::send_false_policy(a1_policy_helper& helper) {
    // Step 1: Allocate memory for the slice-level PRB (Physical Resource Block) quota helper
    //         The quota helper is used to specify the maximum and minimum PRB values for each slice
    std::unique_ptr<e2sm_rc_slice_level_prb_quota_helper> quota_helper_ptr = std::make_unique<e2sm_rc_slice_level_prb_quota_helper>();

    // Step 2: Log the policy payload for each UE (User Equipment)
    //         This is done for debugging and monitoring purposes
    std::stringstream ss;
    for (std::shared_ptr<ue_rc_helper> ue : helper.ue_list) {
        ss << "{ue_index:" << ue->ue_index << ", max_prb:" << ue->max_prb << "},";
    }

    // Step 3: Create an E2SM (E2 Service Model) control helper object
    //         This helper object is used to specify the type of control action to be performed
    e2sm_rc_control_helper control_helper;
    control_helper.present = CONTROL_ACTION_PR_SLICE_LEVEL_PRB_QUOTA;
    control_helper.choice.prb_quota_helper = quota_helper_ptr.get();

    // Step 4: Create an E2SM control object
    //         This object is used to encode the control message
    e2sm_control control;

    // Step 5: Iterate over each UE in the helper's UE list
    for (std::shared_ptr<ue_rc_helper> ue : helper.ue_list) {
        // Step 5.1: Log the policy enforcement information for each UE
        mdclog_write(MDCLOG_INFO, "Applying policy enforcement for %s {ue_index: %d, max_prb: %d",
                     "???? meid ????", ue->ue_index, ue->max_prb);

        // Step 5.2: Set the maximum and minimum PRB values for the current UE
        quota_helper_ptr->max_prb = ue->max_prb;
        quota_helper_ptr->min_prb = 1; // Dummy value as policy does not define any value here; // FIXME: Check if we do not need to send to srsRAN

        // Step 5.3: Create a buffer for the control header
        uint8_t ctrl_header_buf[8192] = {0, };
        ssize_t ctrl_header_buf_size = 8192;

        // Step 5.4: Encode the control header using the E2SM control object
        bool ret_head = control.encode_rc_control_header(ctrl_header_buf, &ctrl_header_buf_size, CONTROL_ACTION_PR_SLICE_LEVEL_PRB_QUOTA);
        if (!ret_head) {
            mdclog_write(MDCLOG_ERR, "Unable to encode RC control header in %s. Reason: %s", __func__, control.get_error().c_str());
            return;
        }

        // Step 5.5: Create a buffer for the control message
        uint8_t ctrl_msg_buf[8192] = {0, };
        ssize_t ctrl_msg_buf_size = 8192;

        // Step 5.6: Encode the control message using the E2SM control object and the control helper
        bool ret_msg = control.encode_rc_control_message(ctrl_msg_buf, &ctrl_msg_buf_size, &control_helper);
        if (!ret_msg) {
            mdclog_write(MDCLOG_ERR, "Unable to encode RC control message in %s. Reason: %s", __func__, control.get_error().c_str());
            return;
        }

        // Step 5.7: Create an E2AP (E2 Application Protocol) control helper object
        ric_control_helper ric_control_helper;
        ric_control_helper.requestor_id = 123; // Dummy value for the requestor ID
        ric_control_helper.instance_id = 1; // Dummy value for the instance ID
        ric_control_helper.func_id = 148; // Function ID for the RC (Radio Control) service model

        // Step 5.8: Set the control call process ID
        //           In this case, it is set to NULL with size 0 as it is generated as a response for a RIC indication insert
        ric_control_helper.call_process_id_size = 0;
        ric_control_helper.call_process_id = NULL;

        // Step 5.9: Set the control ACK (Acknowledgment) request
        //           In this case, no ACK is required for the control request
        ric_control_helper.control_ack = RICcontrolAckRequest_noAck;

        // Step 5.10: Set the control header in the E2AP control helper
        ric_control_helper.control_header = ctrl_header_buf;
        ric_control_helper.control_header_size = ctrl_header_buf_size;

        // Step 5.11: Set the control message in the E2AP control helper
        ric_control_helper.control_msg = ctrl_msg_buf;
        ric_control_helper.control_msg_size = ctrl_msg_buf_size;

        // Step 5.12: Create a buffer for the E2AP message
        uint8_t e2ap_buf[8192] = {0, };
        ssize_t e2ap_buf_size = 8192;

        // Step 5.13: Create an E2AP control request object
        ric_control_request control_req;

        // Step 5.14: Encode the E2AP control request using the E2AP control helper
        bool encoded = control_req.encode_e2ap_control_request(e2ap_buf, &e2ap_buf_size, ric_control_helper);
        if (encoded) {
            // Step 5.15: Create an RMR header for the control request
            xapp_rmr_header header;
            header.state = RMR_OK;
            header.payload_length = e2ap_buf_size;
            header.message_type = RIC_CONTROL_REQ;

            // Step 5.16: Set the MEID (Managed Element ID) in the RMR header
            //            This should come from the RAN or command input arguments
            strncpy((char *)header.meid, "gnb_001_001_0000019b", RMR_MAX_MEID);

            // Step 5.17: Allocate memory for the RMR message payload
            unsigned char *message = (unsigned char *)calloc(e2ap_buf_size, sizeof(unsigned char));
            memcpy(message, e2ap_buf, e2ap_buf_size);

            // Step 5.18: Log the control request information
            mdclog_write(MDCLOG_INFO, "Sending control request to %s", header.meid);

            // Step 5.19: Send the control request using the RMR protocol
            bool sent = rmr_ref->xapp_rmr_send(&header, (void *)message);
            free(message);
            if (!sent) {
                mdclog_write(MDCLOG_ERR, "Unable to send control request to %s", header.meid);
                return;
            }
        } else {
            // Step 5.20: Log the error if unable to encode the E2AP control request
            mdclog_write(MDCLOG_ERR, "E2AP Control Request encoding error. Reason = %s", control_req.get_error().c_str());
            return;
        }
    }

    // Step 6: Set the status of the policy helper to "OK"
    //         This indicates that the policy has been successfully enforced
    helper.status = "OK";
}


void Xapp::send_hardcoded_policy() {
	
    // Create an instance of a1_policy_helper
	a1_policy_helper helper = create_false_a1_payload();

	while(true){
		
		// Call the function to send the policy
		send_false_policy(helper);

		// Do this every 30 seconds
		std::this_thread::sleep_for(std::chrono::seconds(30));
	}
    
}

/*
 * Function: start_xapp_receiver
 * Description: This function starts the xApp receiver threads for handling incoming messages.
 *              It sets up the RMR (RIC Message Router) to listen for messages and creates a specified
 *              number of receiver threads. Each thread runs the `xapp_rmr_receive` function to process
 *              incoming messages using the provided message handler.
 * Parameters:
 *   - mp_handler: Reference to an XappMsgHandler object for handling received messages.
 *   - threads: The number of receiver threads to create (default is 1 if not specified).
 * Returns: None
 */
void Xapp::start_xapp_receiver(XappMsgHandler& mp_handler, int threads) {
    // Step 1: Check if the specified number of threads is less than 1
    //         If so, set the number of threads to 1 as a minimum
    if (threads < 1) {
        threads = 1;
    }

    // Step 2: Set the RMR to listen for incoming messages
    rmr_ref->set_listen(true);

    // Step 3: Check if the xapp_mutex is NULL
    //         If so, create a new mutex for thread synchronization
    if (xapp_mutex == NULL) {
        xapp_mutex = new std::mutex();
    }

    // Step 4: Create the specified number of receiver threads
    for (int i = 0; i < threads; i++) {
        // Step 4.1: Log information about the current receiver thread
        mdclog_write(MDCLOG_INFO, "Receiver Thread %d, file=%s, line=%d", i, __FILE__, __LINE__);

        // Step 4.2: Acquire a lock on the xapp_mutex to ensure thread-safe access
        {
            std::lock_guard<std::mutex> guard(*xapp_mutex);

            // Step 4.3: Create a new thread for receiving messages
            //           The thread runs the `xapp_rmr_receive` function with the provided message handler
            std::thread th_recv([&]() {
                rmr_ref->xapp_rmr_receive(std::move(mp_handler), rmr_ref);
            });

            // Step 4.4: Move the newly created thread into the xapp_rcv_thread vector
            xapp_rcv_thread.push_back(std::move(th_recv));
        }
    }

    // Step 5: Sleep for 2 seconds to allow the receiver threads to start
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Step 6: Return from the function
    return;
}

/*
 * Function: shutdown
 * Description: This function performs the shutdown sequence of the xApp.
 *              It sends subscription delete requests, sends a deregistration request,
 *              shuts down the HTTP listener, and joins the receiver threads.
 * Parameters: None
 * Returns: None
 */
void Xapp::shutdown() {
    // Step 1: Log a message indicating the shutdown of the xApp
    mdclog_write(MDCLOG_INFO, "Shutting down xapp %s", config_ref->operator[](XappSettings::SettingName::XAPP_ID).c_str());

    // Step 2: Send subscription delete requests
    shutdown_delete_subscriptions();

    // Step 3: Send deregistration request
    shutdown_deregistration_request();

    // Step 4: Sleep for a short duration (2 seconds)
    sleep(2);

    // Step 5: Set the RMR (RIC Message Router) to stop listening
    rmr_ref->set_listen(false);

    // Step 6: Shut down the HTTP listener
    shutdown_http_listener();

    // Step 7: Join the receiver threads
    int threadcnt = xapp_rcv_thread.size();
    for (int i = 0; i < threadcnt; i++) {
        if (xapp_rcv_thread[i].joinable())
            xapp_rcv_thread[i].join();
    }

    // Step 8: Clear the receiver thread vector
    xapp_rcv_thread.clear();

    // Step 9: Return from the function
    return;
}

/*
 * Function: subscribe_delete_request
 * Description: This function sends a subscription delete request to the subscription manager
 *              for the specified subscription ID. It makes an HTTP DELETE request to the subscription
 *              manager endpoint and handles the response.
 * Parameters:
 *   - sub_id: The ID of the subscription to be deleted.
 * Returns: None
 */
inline void Xapp::subscribe_delete_request(string sub_id) {
    // Step 1: Create an asynchronous task to send the subscription delete request
    auto delJson = pplx::create_task([sub_id, this]() {
        // Step 1.1: Construct the URI for the subscription manager endpoint
        utility::string_t port = U("8088");
        utility::string_t address = U("http://service-ricplt-submgr-http.ricplt.svc.cluster.local:");
        address.append(port);
        address.append(U("/ric/v1/subscriptions/"));
        address.append(utility::string_t(sub_id));
        uri_builder uri(address);
        auto addr = uri.to_uri().to_string();

        // Step 1.2: Create an HTTP client with the constructed URI
        http_client client(addr);

        // Step 1.3: Log a message indicating the making of the delete request
        ucout << utility::string_t(U("making requests at: ")) << addr << std::endl;

        // Step 1.4: Send an HTTP DELETE request to the subscription manager endpoint
        return client.request(methods::DEL);
    })
    // Step 2: Process the HTTP response
    .then([sub_id, this](http_response response) {
        // Step 2.1: Check the HTTP status code of the response
        if (response.status_code() != 204) {
            // Step 2.1.1: If the status code is not 204 (No Content), throw a runtime exception with the status code
            throw std::runtime_error("Returned " + std::to_string(response.status_code()));
        }

        // Step 2.2: Log a message indicating the successful deletion of the subscription
        mdclog_write(MDCLOG_INFO, "Subscription %s has been deleted", sub_id.c_str());
    });

    // Step 3: Handle any exceptions that occurred during the asynchronous task
    try {
        // Step 3.1: Wait for the asynchronous task to complete
        delJson.wait();
    } catch (const std::exception& e) {
        // Step 3.2: If an exception occurred, log an error message
        mdclog_write(MDCLOG_ERR, "Subscription delete exception: %s", e.what());
    }
}

/*
 * Function: shutdown_delete_subscriptions
 * Description: This function prepares and sends subscription delete requests for all the subscriptions
 *              stored in the subscription_map. It iterates over each subscription, sends a delete request,
 *              and waits for a certain duration between each request.
 * Parameters: None
 * Returns: None
 */
void Xapp::shutdown_delete_subscriptions() {
    // Step 1: Retrieve the xApp ID from the configuration settings
    std::string xapp_id = config_ref->operator[](XappSettings::SettingName::XAPP_ID);

    // Step 2: Log a message indicating the preparation of subscription delete requests
    mdclog_write(MDCLOG_INFO, "Preparing to send subscription Delete in file=%s, line=%d", __FILE__, __LINE__);

    // Step 3: Get the size of the subscription_map
    size_t len = subscription_map.size();
    mdclog_write(MDCLOG_INFO, "E2 NodeB List size : %lu", len);

    // Step 4: Initialize a counter for tracking the progress of delete requests
    size_t i = 1;

    // Step 5: Iterate over each subscription in the subscription_map
    for (auto subs : subscription_map) {
        // Step 5.1: Wait for a certain duration before sending the delete request
        sleep(5);

        // Step 5.2: Log a message indicating the sending of the delete request for the current subscription
        mdclog_write(MDCLOG_INFO, "sending subscription delete request %lu out of %lu to meid %s", i, len, subs.first.c_str());

        // Step 5.3: Send the subscription delete request for the current subscription
        subscribe_delete_request(subs.second);
    }
}

/*
 * Function: subscribe_request
 * Description: This function sends a subscription request to the specified MEID (Managed Element ID)
 *              using the provided JSON subscription object. It makes an HTTP POST request to the subscription
 *              manager endpoint and handles the response.
 * Parameters:
 *   - meid: The MEID to which the subscription request is being sent.
 *   - subObject: The JSON object representing the subscription details.
 * Returns: None
 */
inline void Xapp::subscribe_request(string meid, jsonn subObject) {
    // Step 1: Log a message indicating the sending of the subscription request to the specified MEID
    mdclog_write(MDCLOG_INFO, "sending subscription to meid = %s", meid.c_str());

    // Step 2: Create an asynchronous task to send the subscription request
    auto postJson = pplx::create_task([meid, subObject, this]() {
        // Step 2.1: Convert the JSON subscription object to a string
        utility::stringstream_t s;
        s << subObject.dump().c_str();
        web::json::value ret = json::value::parse(s);

        // Step 2.2: Construct the URI for the subscription manager endpoint
        utility::string_t address = U("http://service-ricplt-submgr-http.ricplt.svc.cluster.local:8088");
        address.append(U("/ric/v1/subscriptions"));
        uri_builder uri(address);
        auto addr = uri.to_uri().to_string();

        // Step 2.3: Create an HTTP client with the constructed URI
        http_client client(addr);

        // Step 2.4: Log a message indicating the making of the subscription request
        ucout << utility::string_t(U("making requests at: ")) << addr << "\n";

        // Step 2.5: Send an HTTP POST request to the subscription manager endpoint with the JSON payload
        return client.request(methods::POST, U("/"), ret.serialize(), U("application/json"));
    })
    // Step 3: Process the HTTP response
    .then([meid, this](http_response response) {
        // Step 3.1: Check the HTTP status code of the response
        if (response.status_code() != 201) {
            // Step 3.1.1: If the status code is not 201 (Created), throw a runtime exception with the status code
            throw std::runtime_error("Returned " + std::to_string(response.status_code()));
        }

        // Step 3.2: Extract the response body as a JSON object
        return response.extract_json();
    })
    // Step 4: Process the JSON response
    .then([meid, this](json::value jsonObject) {
        // Step 4.1: Print the received REST subscription response
        std::cout << "\nReceived REST subscription response: " << jsonObject.serialize().c_str() << "\n\n";

        // Step 4.2: Extract the subscription ID from the JSON response
        std::string tmp;
        tmp = jsonObject[U("SubscriptionId")].as_string();

        // Step 4.3: Store the subscription ID in the subscription_map using the MEID as the key
        subscription_map.emplace(std::make_pair(meid, tmp));
    });

    // Step 5: Handle any exceptions that occurred during the asynchronous task
    try {
        // Step 5.1: Wait for the asynchronous task to complete
        postJson.wait();
    } catch (const std::exception &e) {
        // Step 5.2: If an exception occurred, log an error message and rethrow the exception
        mdclog_write(MDCLOG_ERR, "xapp subscription exception: %s\n", e.what());
        throw;
    }
}

/*
 * Function: build_rc_subscription_request
 * Description: This function builds a subscription request for the RC (Radio Control) service.
 *              It constructs the necessary JSON object containing the subscription details, including the
 *              event trigger and action definition, based on the provided MEID (Managed Element ID).
 * Parameters:
 *   - meid: The MEID for which the subscription request is being built.
 * Returns: The constructed JSON object representing the RC subscription request.
 */
jsonn Xapp::build_rc_subscription_request(string meid) {
    // Step 1: Log a message indicating the building of the RC subscription request for the given MEID
    mdclog_write(MDCLOG_INFO, "Building RC subscription request for %s", meid.c_str());

    // Step 2: Retrieve the necessary configuration settings
    std::string http_addr = config_ref->operator[](XappSettings::SettingName::HTTP_SRC_ID);
    std::string port = config_ref->operator[](XappSettings::SettingName::HTTP_PORT);
    int http_port = stoi(port);
    port = config_ref->operator[](XappSettings::SettingName::BOUNCER_PORT);
    int rmr_port = stoi(port);

    // Step 3: Create the JSON object representing the RC subscription request
    jsonn jsonObject = {
        {"SubscriptionId", ""},
        {"ClientEndpoint", {
            {"Host", http_addr},
            {"HTTPPort", http_port},
            {"RMRPort", rmr_port}
        }},
        {"Meid", meid},
        {"RANFunctionID", 1},
        {"SubscriptionDetails", {
            {
                {"XappEventInstanceId", 12345},
                {"EventTriggers", {2}},
                {"ActionToBeSetupList", {
                    {
                        {"ActionID", 1},
                        {"ActionType", "insert"},
                        {"ActionDefinition", {3}},
                        {"SubsequentAction", {
                            {"SubsequentActionType", "continue"},
                            {"TimeToWait", "w10ms"}
                        }}
                    }
                }}
            }
        }}
    };

    // Step 4: Print the JSON object (for debugging purposes)
    std::cout << jsonObject.dump(4) << "\n";

    // Step 5: Return the constructed JSON object
    return jsonObject;
}

/*
 * Function: build_kpm_subscription_request
 * Description: This function builds a subscription request for the KPM (Key Performance Measurements) service.
 *              It constructs the necessary JSON object containing the subscription details, including the
 *              event trigger definition and action definition, based on the provided MEID (Managed Element ID).
 * Parameters:
 *   - meid: The MEID for which the subscription request is being built.
 * Returns: The constructed JSON object representing the KPM subscription request.
 */
jsonn Xapp::build_kpm_subscription_request(string meid) {
    // Step 1: Log a message indicating the building of the KPM subscription request for the given MEID
    mdclog_write(MDCLOG_INFO, "Building KPM subscription request for %s", meid.c_str());

    // Step 2: Retrieve the necessary configuration settings
    std::string http_addr = config_ref->operator[](XappSettings::SettingName::HTTP_SRC_ID);
    std::string port = config_ref->operator[](XappSettings::SettingName::HTTP_PORT);
    int http_port = stoi(port);
    port = config_ref->operator[](XappSettings::SettingName::BOUNCER_PORT);
    int rmr_port = stoi(port);

    // Step 3: Create an instance of the e2sm_kpm_subscription_helper
    e2sm_kpm_subscription_helper helper;

    // Step 4: Set the trigger and action definitions in the helper object
    helper.trigger.reportingPeriod = 5;  // TODO: Should be each 500ms, could be changed via ENV (seems that srsRAN hardcoded it to 1)
    helper.action.granulPeriod = 3;  // TODO: Could be changed via ENV (seems that srsRAN hardcoded it to 1)
    helper.action.format = E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format4;

    // Step 5: Create an instance of the e2sm_subscription
    e2sm_subscription kpm_sub;

    // Step 6: Create a buffer to store the encoded event trigger definition
    unsigned char buf[4096];
    ssize_t buflen = 4096;

    // Step 7: Encode the KPM event trigger definition
    if (!kpm_sub.encodeKPMTriggerDefinition(buf, &buflen, helper)) {
        // Step 7.1: If encoding fails, log an error message with the reason
        mdclog_write(MDCLOG_ERR, "Unable to enconde E2SM_KPM_EventTriggerDefinition to create subscription request. Reason: %s",
                     kpm_sub.get_error().c_str());
    }

    // Step 8: Convert the encoded event trigger definition to an array of integers (as required by the JSON schema)
    std::vector<int> kpm_trigger(buf, buf + buflen);

    // Step 9: Reset the buffer length
    buflen = 4096;

    // Step 10: Encode the KPM action definition
    if (!kpm_sub.encodeKPMActionDefinition(buf, &buflen, helper)) {
        // Step 10.1: If encoding fails, log an error message with the reason
        mdclog_write(MDCLOG_ERR, "Unable to enconde E2SM_KPM_ActionDefinition to create subscription request. Reason: %s",
                     kpm_sub.get_error().c_str());
    }

    // Step 11: Convert the encoded action definition to an array of integers (as required by the JSON schema)
    std::vector<int> kpm_action(buf, buf + buflen);

    // Step 12: Create the JSON object representing the KPM subscription request
    jsonn jsonObject = {
        {"SubscriptionId", ""},
        {"ClientEndpoint", {
            {"Host", http_addr},
            {"HTTPPort", http_port},
            {"RMRPort", rmr_port}
        }},
        {"Meid", meid},
        {"RANFunctionID", 147},
        {"SubscriptionDetails", {
            {
                {"XappEventInstanceId", 12345},
                {"EventTriggers", kpm_trigger},
                {"ActionToBeSetupList", {
                    {
                        {"ActionID", 1},
                        {"ActionType", "report"},
                        {"ActionDefinition", kpm_action},
                        {"SubsequentAction", {
                            {"SubsequentActionType", "continue"},
                            {"TimeToWait", "zero"}
                        }}
                    }
                }}
            }
        }}
    };

    // Step 13: Print the JSON object (for debugging purposes)
    std::cout << jsonObject.dump(4) << "\n";

    // Step 14: Return the constructed JSON object
    return jsonObject;
}

/*
 * Function: startup_subscribe_requests
 * Description: This function prepares and sends subscription requests to E2 nodes.
 *              It retrieves the list of connected E2 nodes and sends subscription requests
 *              based on the configured nodeB ID and PLMN ID. It builds the subscription
 *              requests using the `build_rc_subscription_request` and `build_kpm_subscription_request`
 *              functions and sends them using the `subscribe_request` function.
 * Parameters: None
 * Returns: None
 */
void Xapp::startup_subscribe_requests() {
    // Step 1: Log a message indicating the preparation of subscription requests
    mdclog_write(MDCLOG_INFO, "Preparing to send subscriptions in file=%s, line=%d", __FILE__, __LINE__);

    // Step 2: Get the size of the E2 node map
    size_t len = e2node_map.size();
    mdclog_write(MDCLOG_INFO, "E2 Node List size : %lu", len);

    // Step 3: Check if there are any connected E2 nodes
    if (len == 0) {
        // Step 3.1: If no E2 nodes are connected, throw a runtime exception
        throw std::runtime_error("Subscriptions cannot be sent as there is no E2 Node connected to the RIC");
    }

    // Step 4: Retrieve the configured nodeB ID
    string nodebid = config_ref->operator[](XappSettings::SettingName::NODEB_ID);
    unsigned long nodebid_num = 0;
    string plmnid;

    // Step 5: Check if the nodeB ID is not empty
    if (!nodebid.empty()) {
        // Step 5.1: Build the PLMN ID
        plmnid = config_ref->buildPlmnId();
        transform(plmnid.begin(), plmnid.end(), plmnid.begin(), ::tolower);

        // Step 5.2: Convert the nodeB ID to a number
        try {
            nodebid_num = std::stoul(nodebid, nullptr, 2);
        } catch (std::exception& e) {
            // Step 5.2.1: If the conversion fails, throw a runtime exception with an error message
            std::stringstream ss;
            ss << "unable to convert " << nodebid << " to number: " << e.what();
            throw std::runtime_error(ss.str());
        }
    }

    // Step 6: Iterate over the E2 nodes in the map
    for (auto e2node : e2node_map) {
        // Step 6.1: Check if the nodeB ID is not empty
        if (!nodebid.empty()) {
            // Step 6.1.1: Retrieve the PLMN ID of the E2 node
            auto e2plmn = e2node.second[U("plmnId")].as_string();
            transform(e2plmn.begin(), e2plmn.end(), e2plmn.begin(), ::tolower);

            // Step 6.1.2: Compare the PLMN ID of the E2 node with the configured PLMN ID
            if (plmnid.compare(e2plmn) != 0) {
                continue;  // If the PLMN IDs don't match, move to the next E2 node
            }

            // Step 6.1.3: Retrieve the NB ID of the E2 node
            auto e2nbId = e2node.second[U("nbId")].as_string();

            // Step 6.1.4: Convert the NB ID to a number
            try {
                auto nbId = std::stoul(e2nbId, nullptr, 2);
                if (nodebid_num != nbId) {
                    continue;  // If the NB IDs don't match, move to the next E2 node
                }
            } catch (std::exception& e) {
                // Step 6.1.4.1: If the conversion fails, throw a runtime exception with an error message
                std::stringstream ss;
                ss << "unable to convert " << e2nbId << " to number: " << e.what();
                throw std::runtime_error(ss.str());
            }
        }

        // Step 6.2: Building and sending subscription requests
        sleep(5);  // Wait for registration to complete and add a pause between each subscription

        // Step 6.3: Build the RC (Radio Control) subscription request
        jsonn jsonObject = build_rc_subscription_request(e2node.first);

        // Step 6.4: Build the KPM (Key Performance Measurements) subscription request
        jsonObject = build_kpm_subscription_request(e2node.first);

        // Step 6.5: Send the subscription request
        subscribe_request(e2node.first, jsonObject);

        // Step 6.6: Check if the nodeB ID is not empty
        if (!nodebid.empty()) {
            // If the nodeB ID is not empty and the subscription is sent,
            // break the loop to avoid sleeping over the remaining E2 nodes
            break;
        }
    }

    // Step 7: Check if any subscriptions were successfully sent
    if (subscription_map.size() == 0) {
        // Step 7.1: If no subscriptions were sent, throw a runtime exception
        throw std::runtime_error("Unable to subscribe to E2 Node");
    }
}


/*
 * Function: fetch_connected_nodeb_list
 * Description: This function fetches the list of connected E2 NodeBs from the E2 Manager service.
 *              It sends an HTTP GET request to the E2 Manager service endpoint and retrieves the list
 *              of NodeBs along with their connection status. The connected NodeBs are stored in the
 *              `e2node_map` member variable of the Xapp class.
 * Parameters: None
 * Returns: None
 */
void Xapp::fetch_connected_nodeb_list() {
    // Step 1: Log a message indicating the start of fetching the connected E2 NodeB list
    mdclog_write(MDCLOG_INFO, "Fetching connected E2 NodeB list");

    // Step 2: Create an asynchronous task to send the HTTP request and process the response
    pplx::create_task([this]() {
        // Step 2.1: Construct the URI for the E2 Manager service endpoint
        utility::string_t address = U("http://service-ricplt-e2mgr-http.ricplt.svc.cluster.local:3800");
        address.append(U("/v1/nodeb/states"));
        uri_builder uri(address);
        auto addr = uri.to_uri().to_string();

        // Step 2.2: Create an HTTP client with the constructed URI
        http_client client(addr);

        // Step 2.3: Log a message indicating the sending of the request
        mdclog_write(MDCLOG_INFO, "sending request for E2 NodeB list at: %s", addr.c_str());

        // Step 2.4: Send an HTTP GET request to the E2 Manager service endpoint
        return client.request(methods::GET, U("/"), U("accept: application/json"));
    })
    // Step 3: Process the HTTP response
    .then([this](http_response response) {
        // Step 3.1: Check the HTTP status code of the response
        if (response.status_code() != 200) {
            // Step 3.1.1: If the status code is not 200 (OK), log an error message
            mdclog_write(MDCLOG_ERR, "request for E2 NodeB list returned http status code %s - %s",
                         std::to_string(response.status_code()).c_str(), response.reason_phrase().c_str());

            // Step 3.1.2: Throw a runtime exception with the status code
            throw std::runtime_error("Returned http status code " + std::to_string(response.status_code()));
        }

        // Step 3.2: Extract the response body as a JSON object
        return response.extract_json();
    })
    // Step 4: Process the JSON response
    .then([this](web::json::value resp) {
        // Step 4.1: Log a message indicating successful fetching of the E2 NodeB list
        mdclog_write(MDCLOG_INFO, "E2 NodeB list has been fetched successfuly");

        try {
            // Step 4.2: Convert the JSON response to an array
            auto nodeb_list = resp.as_array();

            // Step 4.3: Iterate over each NodeB in the array
            for (auto nodeb : nodeb_list) {
                // Step 4.3.1: Extract the inventory name and connection status of the NodeB
                auto inv_name = nodeb[U("inventoryName")].as_string();
                auto status = nodeb[U("connectionStatus")].as_string();

                // Step 4.3.2: Log the inventory name and connection status of the NodeB
                mdclog_write(MDCLOG_DEBUG, "E2 NodeB %s is %s", inv_name.c_str(), status.c_str());

                // Step 4.3.3: If the NodeB is connected, add it to the `e2node_map`
                if (status.compare("CONNECTED") == 0) {
                    this->e2node_map.emplace(inv_name, nodeb[U("globalNbId")]);
                }
            }
        } catch (json::json_exception const &e) {
            // Step 4.4: If there's an exception while processing the JSON, log an error message
            mdclog_write(MDCLOG_ERR, "unable to process JSON payload from http response. Reason = %s", e.what());
        }
    })
    // Step 5: Handle any exceptions that occurred during the asynchronous task
    .then([](pplx::task<void> previousTask) {
        try {
            // Step 5.1: Wait for the previous task to complete
            previousTask.wait();
        } catch (exception& e) {
            // Step 5.2: If an exception occurred, log an error message
            mdclog_write(MDCLOG_ERR, "Fetch E2 NodeB list exception: %s", e.what());
        }
    });
}


/*
 * Function: startup_registration_request
 * Description: This function sends a registration request to the RIC platform's Application Manager (AppMgr)
 *              to register the xApp. It prepares the registration request payload with the xApp's details
 *              such as name, version, configuration path, instance name, HTTP endpoint, RMR endpoint, and
 *              configuration string. It then sends an HTTP POST request to the AppMgr's registration endpoint.
 * Parameters: None
 * Returns: None
 */
void Xapp::startup_registration_request() {
    // Step 1: Log a message indicating the preparation of the registration request
    mdclog_write(MDCLOG_INFO, "Preparing registration request");

    // Step 2: Retrieve the necessary configuration settings from the config_ref
    string xapp_name = config_ref->operator[](XappSettings::SettingName::XAPP_NAME);
    string xapp_id = config_ref->operator[](XappSettings::SettingName::XAPP_ID);
    string config_path = config_ref->operator[](XappSettings::SettingName::CONFIG_FILE);
    string config_str = config_ref->operator[](XappSettings::SettingName::CONFIG_STR);
    string version = config_ref->operator[](XappSettings::SettingName::VERSION);
    string rmr_addr = config_ref->operator[](XappSettings::SettingName::RMR_SRC_ID);
    string http_addr = config_ref->operator[](XappSettings::SettingName::HTTP_SRC_ID);
    string rmr_port = config_ref->operator[](XappSettings::SettingName::BOUNCER_PORT);
    string http_port = config_ref->operator[](XappSettings::SettingName::HTTP_PORT);

    // Step 3: Append the RMR port to the RMR address
    rmr_addr.append(":" + rmr_port);

    // Step 4: If both HTTP address and port are available, append the port to the HTTP address
    if (!http_addr.empty() && !http_port.empty()) {
        http_addr.append(":" + http_port);
    }

    // Step 5: Create an asynchronous task to send the registration request
    pplx::create_task([xapp_name, version, config_path, xapp_id, http_addr, rmr_addr, config_str]() {
        // Step 5.1: Create a JSON object with the xApp's registration details
        jsonn jObj;
        jObj = {
            {"appName", xapp_name},
            {"appVersion", version},
            {"configPath", config_path},
            {"appInstanceName", xapp_id},
            {"httpEndpoint", http_addr},
            {"rmrEndpoint", rmr_addr},
            {"config", config_str}
        };

        // Step 5.2: If the log level is higher than MDCLOG_INFO, print the registration body
        if (mdclog_level_get() > MDCLOG_INFO) {
            cerr << "registration body is\n" << jObj.dump(4) << "\n";
        }

        // Step 5.3: Convert the JSON object to a string and parse it as a web::json::value
        utility::stringstream_t s;
        s << jObj.dump().c_str();
        web::json::value ret = json::value::parse(s);

        // Step 5.4: Construct the URI for the AppMgr's registration endpoint
        utility::string_t port = U("8080");
        utility::string_t address = U("http://service-ricplt-appmgr-http.ricplt.svc.cluster.local:");
        address.append(port);
        address.append(U("/ric/v1/register"));
        uri_builder uri(address);
        auto addr = uri.to_uri().to_string();

        // Step 5.5: Create an HTTP client with the constructed URI
        http_client client(addr);

        // Step 5.6: Log a message indicating the sending of the registration request
        mdclog_write(MDCLOG_INFO, "sending registration request at: %s", addr.c_str());

        // Step 5.7: Send an HTTP POST request to the AppMgr's registration endpoint with the JSON payload
        return client.request(methods::POST, U("/"), ret.serialize(), U("application/json"));
    })
    // Step 6: Process the HTTP response
    .then([xapp_id](http_response response) {
        // Step 6.1: Check the HTTP status code of the response
        if (response.status_code() == 201) {
            // Step 6.1.1: If the status code is 201 (Created), log a success message
            mdclog_write(MDCLOG_INFO, "xapp %s has been registered", xapp_id.c_str());
        } else {
            // Step 6.1.2: If the status code is not 201, log an error message with the status code and reason
            mdclog_write(MDCLOG_ERR, "registration returned http status code %s - %s",
                         std::to_string(response.status_code()).c_str(), response.reason_phrase().c_str());
        }
    })
    // Step 7: Handle any exceptions that occurred during the asynchronous task
    .then([](pplx::task<void> previousTask) {
        try {
            // Step 7.1: Wait for the previous task to complete
            previousTask.wait();
        } catch (exception& e) {
            // Step 7.2: If an exception occurred, log an error message and rethrow the exception
            mdclog_write(MDCLOG_ERR, "xapp registration exception: %s", e.what());
            throw;
        }
    }).get(); // Step 8: Use get() to allow rethrowing exceptions from the task
}

/*
 * Function: shutdown_deregistration_request
 * Description: This function prepares and sends a deregistration request to the RIC platform's Application Manager (AppMgr)
 *              to deregister the xApp. It creates a JSON payload containing the xApp's name and instance name and sends
 *              an HTTP POST request to the AppMgr's deregistration endpoint.
 * Parameters: None
 * Returns: None
 */
void Xapp::shutdown_deregistration_request() {
    // Step 1: Log a message indicating the preparation of the deregistration request
    mdclog_write(MDCLOG_INFO, "Preparing deregistration request");

    // Step 2: Retrieve the xApp name and ID from the configuration settings
    string xapp_name = config_ref->operator[](XappSettings::SettingName::XAPP_NAME);
    string xapp_id = config_ref->operator[](XappSettings::SettingName::XAPP_ID);

    // Step 3: Create an asynchronous task to send the deregistration request
    pplx::create_task([xapp_name, xapp_id]() {
        // Step 3.1: Create a JSON object with the xApp's deregistration details
        jsonn jObj;
        jObj = {
            {"appName", xapp_name},
            {"appInstanceName", xapp_id}
        };

        // Step 3.2: If the log level is higher than MDCLOG_INFO, print the deregistration body
        if (mdclog_level_get() > MDCLOG_INFO) {
            cerr << "deregistration body is\n" << jObj.dump(4) << "\n";
        }

        // Step 3.3: Convert the JSON object to a string and parse it as a web::json::value
        utility::stringstream_t s;
        s << jObj.dump().c_str();
        web::json::value ret = json::value::parse(s);

        // Step 3.4: Construct the URI for the AppMgr's deregistration endpoint
        utility::string_t port = U("8080");
        utility::string_t address = U("http://service-ricplt-appmgr-http.ricplt.svc.cluster.local:");
        address.append(port);
        address.append(U("/ric/v1/deregister"));
        uri_builder uri(address);
        auto addr = uri.to_uri().to_string();

        // Step 3.5: Create an HTTP client with the constructed URI
        http_client client(addr);

        // Step 3.6: Log a message indicating the sending of the deregistration request
        mdclog_write(MDCLOG_INFO, "sending deregistration request at: %s", addr.c_str());

        // Step 3.7: Send an HTTP POST request to the AppMgr's deregistration endpoint with the JSON payload
        return client.request(methods::POST, U("/"), ret.serialize(), U("application/json"));
    })
    // Step 4: Process the HTTP response
    .then([xapp_id](http_response response) {
        // Step 4.1: Check the HTTP status code of the response
        if (response.status_code() == 204) {
            // Step 4.1.1: If the status code is 204 (No Content), log a success message
            mdclog_write(MDCLOG_INFO, "xapp %s has been deregistered", xapp_id.c_str());
        } else {
            // Step 4.1.2: If the status code is not 204, log an error message with the status code and reason
            mdclog_write(MDCLOG_ERR, "deregistration returned http status code %s - %s",
                         std::to_string(response.status_code()).c_str(), response.reason_phrase().c_str());
        }
    })
    // Step 5: Handle any exceptions that occurred during the asynchronous task
    .then([](pplx::task<void> previousTask) {
        try {
            // Step 5.1: Wait for the previous task to complete
            previousTask.wait();
        } catch (exception& e) {
            // Step 5.2: If an exception occurred, log an error message
            mdclog_write(MDCLOG_ERR, "deregistration exception: %s", e.what());
        }
    });
}

/*
 * Function: handle_error
 * Description: This function handles errors that occur during asynchronous tasks.
 *              It waits for the task to complete and logs any exceptions that occurred.
 * Parameters:
 *   - t: Reference to the asynchronous task.
 *   - msg: Error message to be logged.
 * Returns: None
 */
void Xapp::handle_error(pplx::task<void>& t, const utility::string_t msg) {
    try {
        // Step 1: Wait for the task to complete
        t.get();
    } catch (std::exception& e) {
        // Step 2: If an exception occurred, log the error message along with the exception details
        mdclog_write(MDCLOG_ERR, "%s : Reason = %s", msg.c_str(), e.what());
    }
}

/*
 * Function: handle_request
 * Description: This function handles incoming HTTP requests.
 *              It extracts the JSON payload from the request, processes the subscription instances,
 *              and sends an appropriate response based on the success or failure of the subscription.
 * Parameters:
 *   - request: The incoming HTTP request.
 * Returns: None
 */
void Xapp::handle_request(http_request request) {
    // Step 1: If the log level is higher than MDCLOG_INFO, print the details of the incoming request
    if (mdclog_level_get() > MDCLOG_INFO) {
        cerr << "\n===== Handling HTTP request =====\n" << request.to_string() << "\n=================================\n\n";
    }

    // Step 2: Create a JSON object to store the response
    auto answer = json::value::object();

    // Step 3: Extract the JSON payload from the request
    request.extract_json().then([&answer, request, this](pplx::task<json::value> task) {
        try {
            // Step 3.1: Get the extracted JSON payload
            answer = task.get();

            // Step 3.2: Log the received REST notification
            mdclog_write(MDCLOG_INFO, "Received REST notification %s", answer.serialize().c_str());

            // Step 3.3: Extract the subscription instances from the JSON payload
            auto subscriptions = answer[U("SubscriptionInstances")].as_array();

            // Step 3.4: Iterate over each subscription instance
            for (auto sub : subscriptions) {
                // Step 3.4.1: Get the E2 event instance ID
                int event = sub[U("E2EventInstanceId")].as_integer();

                // Step 3.4.2: If the event ID is 0, it indicates an error in the subscription
                if (event == 0) {
                    // Step 3.4.2.1: Extract the error source and cause from the JSON payload
                    auto source = sub[U("ErrorSource")].as_string();
                    auto cause = sub[U("ErrorCause")].as_string();

                    // Step 3.4.2.2: Log an error message with the error source and cause
                    mdclog_write(MDCLOG_ERR, "unable to complete subscription. ErrorSource: %s, ErrorCause: %s",
                                 source.c_str(), cause.c_str());

                    // Step 3.4.2.3: Send a signal to shutdown the application
                    kill(getpid(), SIGTERM);
                    break;
                }
            }

            // Step 3.5: Send an OK response to the request
            request.reply(status_codes::OK).then([this](pplx::task<void> t) {
                // Step 3.5.1: Handle any errors that occur during the response
                handle_error(t, "http reply exception");
            });
        } catch (json::json_exception const &e) {
            // Step 3.6: If an exception occurs while processing the JSON payload, log an error message
            mdclog_write(MDCLOG_ERR, "unable to process JSON payload from http request. Reason = %s", e.what());

            // Step 3.7: Send an Internal Server Error response to the request
            request.reply(status_codes::InternalError).then([this](pplx::task<void> t) {
                // Step 3.7.1: Handle any errors that occur during the response
                handle_error(t, "http reply exception");
            });
        }
    }).wait();
}

/*
 * Function: startup_http_listener
 * Description: This function starts up an HTTP listener for handling REST notifications.
 *              It constructs the URI for the listener based on the configured HTTP port and
 *              the predefined endpoint path. It creates an instance of the http_listener class
 *              and sets up support for handling POST and PUT requests.
 * Parameters: None
 * Returns: None
 */
void Xapp::startup_http_listener() {
    // Step 1: Log a message indicating the startup of the HTTP listener
    mdclog_write(MDCLOG_INFO, "Starting up HTTP Listener");

    // Step 2: Retrieve the HTTP port from the configuration settings
    utility::string_t port = U(config_ref->operator[](XappSettings::SettingName::HTTP_PORT));

    // Step 3: Construct the URI for the HTTP listener
    utility::string_t address = U("http://0.0.0.0:");
    address.append(port);
    address.append(U("/ric/v1/subscriptions/response"));
    uri_builder uri(address);
    auto addr = uri.to_uri().to_string();

    // Step 4: Validate the constructed URI
    if (!uri::validate(addr)) {
        // Step 4.1: If the URI is invalid, throw a runtime exception with an error message
        throw std::runtime_error("unable starting up the http listener due to invalid URI: " + addr);
    }

    // Step 5: Create an instance of the http_listener class with the constructed URI
    listener = make_unique<http_listener>(addr);

    // Step 6: Log a message indicating the address where the listener is listening for REST notifications
    mdclog_write(MDCLOG_INFO, "Listening for REST Notification at: %s", addr.c_str());

    // Step 7: Set up support for handling POST requests
    listener->support(methods::POST, [this](http_request request) {
        handle_request(request);
    });

    // Step 8: Set up support for handling PUT requests
    listener->support(methods::PUT, [this](http_request request) {
        handle_request(request);
    });

    try {
        // Step 9: Open the listener and wait for it to start (non-blocking operation)
        listener->open().wait();
    } catch (exception const &e) {
        // Step 10: If an exception occurs during startup, log an error message and rethrow the exception
        mdclog_write(MDCLOG_ERR, "startup http listener exception: %s", e.what());
        throw;
    }
}

/*
 * Function: shutdown_http_listener
 * Description: This function shuts down the HTTP listener.
 * Parameters: None
 * Returns: None
 */
void Xapp::shutdown_http_listener() {
    // Step 1: Log a message indicating the shutdown of the HTTP listener
    mdclog_write(MDCLOG_INFO, "Shutting down HTTP Listener");

    try {
        // Step 2: Close the listener and wait for it to shut down
        listener->close().wait();
    } catch (exception const &e) {
        // Step 3: If an exception occurs during shutdown, log an error message
        mdclog_write(MDCLOG_ERR, "shutdown http listener exception: %s", e.what());
    }
}




// -------------------------------------------------------------------------------------------   Used to be in the Startup   -------------------------------------------------------------------------------------------





/*
 * Function: startup_get_policies
 * Description: Starts up the process of retrieving A1 policies.
 *              It sends a policy query message to the RMR with the specified policy type ID.
 * Parameters: None
 * Returns: None
 */
void Xapp::startup_get_policies(void) {
    // Step 1: Log a message indicating the startup of A1 policies
    mdclog_write(MDCLOG_INFO, "Starting up A1 policies");

    // Step 2: Set the policy ID to BOUNCER_POLICY_ID
    int policy_id = BOUNCER_POLICY_ID;

    // Step 3: Create the policy query string with the policy ID
    std::string policy_query = "{\"policy_type_id\":" + std::to_string(policy_id) + "}";

    // Step 4: Allocate memory for the message and copy the policy query string
    unsigned char * message = (unsigned char *)calloc(policy_query.length(), sizeof(unsigned char));
    memcpy(message, policy_query.c_str(), policy_query.length());

    // Step 5: Create an RMR header for the policy query message
    xapp_rmr_header header;
    header.state = RMR_OK;
    header.payload_length = policy_query.length();
    header.message_type = A1_POLICY_QUERY;

    // Step 6: Log a message indicating the sending of the policy query request
    mdclog_write(MDCLOG_INFO, "Sending request for policy id %d\n", policy_id);

    // Step 7: Send the policy query message using the RMR
    rmr_ref->xapp_rmr_send(&header, (void *)message);

    // Step 8: Free the allocated memory for the message
    free(message);
}





/*
 * Function: set_rnib_gnblist
 * Description: Retrieves the list of gNodeB IDs from the R-NIB (RAN-Network Information Base)
 *              and stores them in the `rnib_gnblist` member variable.
 * Parameters: None
 * Returns: None
 */
void Xapp::set_rnib_gnblist(void) {
    // Step 1: Open the SDL (Shared Data Layer) connection
    openSdl();

    // Step 2: Get the list of gNodeB IDs from the R-NIB
    void *result = getListGnbIds();

    // Step 3: Check if the result is empty
    if (strlen((char*)result) < 1) {
        mdclog_write(MDCLOG_ERR, "ERROR: no data from getListGnbIds\n");
        return;
    }

    // Step 4: Log the retrieved gNodeB list
    mdclog_write(MDCLOG_INFO, "GNB List in R-NIB %s\n", (char*)result);

    // Step 5: Parse the JSON result
    Document doc;
    ParseResult parseJson = doc.Parse<kParseStopWhenDoneFlag>((char*)result);
    if (!parseJson) {
        mdclog_write(MDCLOG_ERR, "JSON parse error: %s", (char *)GetParseErrorFunc(parseJson.Code()));
        return;
    }

    // Step 6: Check if the JSON document has a "gnb_list" member
    if (!doc.HasMember("gnb_list")) {
        mdclog_write(MDCLOG_ERR, "JSON Has No GNB List Object");
        return;
    }
    assert(doc.HasMember("gnb_list"));

    // Step 7: Get the "gnb_list" array from the JSON document
    const Value& gnblist = doc["gnb_list"];
    if (gnblist.IsNull())
        return;
    if (!gnblist.IsArray()) {
        mdclog_write(MDCLOG_ERR, "GNB List is not an array");
        return;
    }
    assert(gnblist.IsArray());

    // Step 8: Iterate over each gNodeB object in the "gnb_list" array
    for (SizeType i = 0; i < gnblist.Size(); i++) {
        assert(gnblist[i].IsObject());
        const Value& gnbobj = gnblist[i];

        // Step 8.1: Check if the gNodeB object has an "inventory_name" member
        assert(gnbobj.HasMember("inventory_name"));
        assert(gnbobj["inventory_name"].IsString());

        // Step 8.2: Get the "inventory_name" value and store it in the `rnib_gnblist` member variable
        std::string name = gnbobj["inventory_name"].GetString();
        rnib_gnblist.push_back(name);
    }

    // Step 9: Close the SDL connection
    closeSdl();

    return;
}
