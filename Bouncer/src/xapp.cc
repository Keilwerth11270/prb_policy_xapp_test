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

#include "e2sm_subscription.hpp"
#include "msgs_proc.hpp"
#include "e2sm_indication.hpp"
#include "GlobalNgENB-ID.h"

using namespace utility;
using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace concurrency::streams;
using jsonn = nlohmann::json;

#define BUFFER_SIZE 1024

Xapp::Xapp(XappSettings &config, XappRmr &rmr){

	  rmr_ref = &rmr;
	  config_ref = &config;
	  xapp_mutex = NULL;
	  subhandler_ref = NULL;
	  return;
  }

Xapp::~Xapp(void){
	if(xapp_mutex!=NULL){
		xapp_mutex->~mutex();
		delete xapp_mutex;
	}
}

//Stop the xapp. Note- To be run only from unit test scripts.
void Xapp::stop(void){
  // Get the mutex lock
	std::lock_guard<std::mutex> guard(*xapp_mutex);
	rmr_ref->set_listen(false);
	rmr_ref->~XappRmr();

	//Detaching the threads....not sure if this is the right way to stop the receiver threads.
	//Hence function should be called only in Unit Tests
	int threadcnt = xapp_rcv_thread.size();
	for(int i=0; i<threadcnt; i++){
		xapp_rcv_thread[i].detach();
	}
	sleep(10);
}

void Xapp::startup(SubscriptionHandler &sub_ref) {

	subhandler_ref = &sub_ref;
	// set_rnib_gnblist();
	fetch_connected_nodeb_list();

	startup_registration_request(); // throws std::exception

	startup_http_listener();	// throws std::exception

	//send subscriptions.
	startup_subscribe_requests(); // throws std::exception

	/*
	
	
	LOOK HERE PLEASE - JUST BELOW THIS IS WHERE I EDIT THE CODE
	
	
	*/

	//read A1 policies - DEPRECATED FUNCTION SINCE WE ARE NO LONGER RETRIEVING POLICIES FROM THE A1 INTERFACE
	//startup_get_policies();

	start_xapp_receiver(); //do I need to run this function?? it was not being explicitly called before
	return;
}

void Xapp::send_hardcoded_policy() {
    while (true) {
        // Create a hardcoded policy with the same structure as the one expected from A1
        // This is done using the oran::service_message protobuf structure
        oran::service_message message;
        message.set_type(1);  // Set the message type to 1 (you can adjust this based on your requirements)

        // Add hardcoded UE and PRB allocation data to the message
        // This is just an example, you can modify the values and add more UEs as needed
        oran::rc_per_ue *rc = message.add_ue_max_prb_allocations();  // Add a new UE entry to the message
        rc->set_ue_index(1);  // Set the UE index to 1 (you can change this)
        rc->set_max_prb(10);  // Set the maximum PRB allocation for the UE to 10 (you can change this)

        // Serialize the message into a binary format
        // This step is necessary to convert the protobuf message into a string that can be encoded and sent
        std::string serialized_message = message.SerializeAsString();
        // If serialization fails, the program will continue to the next iteration of the loop

        // Encode the serialized message using ASN.1
        // This step is required to encode the message in the format expected by the E2 interface
        E2AP_PDU_t *e2ap_pdu = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU));  // Allocate memory for the E2AP_PDU structure
        // If memory allocation fails, the program will continue to the next iteration of the loop
        ASN_STRUCT_RESET(asn_DEF_E2AP_PDU, e2ap_pdu);  // Reset the E2AP_PDU structure to its default values

        // Populate the E2AP_PDU structure with the necessary fields
        e2ap_pdu->present = E2AP_PDU_PR_initiatingMessage;  // Set the presence field to indicate an initiating message
        e2ap_pdu->choice.initiatingMessage.procedureCode = ProcedureCode_id_RICcontrol;  // Set the procedure code to RICcontrol
        e2ap_pdu->choice.initiatingMessage.criticality = Criticality_ignore;  // Set the criticality to ignore
        e2ap_pdu->choice.initiatingMessage.value.present = InitiatingMessage__value_PR_RICcontrolRequest;  // Set the message type to RICcontrolRequest

        // Populate the RICcontrolRequest structure with the encoded policy message
        RICcontrolRequest_t *ric_control_request = &e2ap_pdu->choice.initiatingMessage.value.choice.RICcontrolRequest;  // Get a pointer to the RICcontrolRequest structure
        ric_control_request->protocolIEs.list.count = 1;  // Set the count of protocol IEs to 1
        ric_control_request->protocolIEs.list.array = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));  // Allocate memory for the protocol IEs array
        // If memory allocation fails, the program will continue to the next iteration of the loop

        ric_control_request->protocolIEs.list.array[0].id = ProtocolIE_ID_id_RICcontrolMessage;  // Set the protocol IE ID to RICcontrolMessage
        ric_control_request->protocolIEs.list.array[0].criticality = Criticality_reject;  // Set the criticality to reject
        ric_control_request->protocolIEs.list.array[0].value.present = RICcontrolRequest_IEs__value_PR_RICcontrolMessage;  // Set the value type to RICcontrolMessage

        OCTET_STRING_t *ric_control_message = &ric_control_request->protocolIEs.list.array[0].value.choice.RICcontrolMessage;  // Get a pointer to the RICcontrolMessage octet string
        ric_control_message->buf = (uint8_t *)serialized_message.c_str();  // Set the buffer of the octet string to the serialized message
        ric_control_message->size = serialized_message.size();  // Set the size of the octet string to the size of the serialized message

        // Encode the E2AP_PDU using ASN.1
        uint8_t e2ap_buf[8192];  // Create a buffer to store the encoded message
        size_t e2ap_buf_size = 8192;  // Set the size of the buffer
        asn_enc_rval_t enc_rval = asn_encode_to_buffer(nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2AP_PDU, e2ap_pdu, e2ap_buf, e2ap_buf_size);  // Encode the E2AP_PDU into the buffer
        // If encoding fails, enc_rval.encoded will be -1, and the program will skip the sending step

        if (enc_rval.encoded == -1) {
            mdclog_write(MDCLOG_ERR, "Error encoding E2AP PDU");  // Log an error message if encoding fails
        } else {
            // Send the encoded message via the E2 interface
            if (sockfd) {  // Check if the socket is valid
                if (send(sockfd, e2ap_buf, enc_rval.encoded, 0) == -1) {  // Send the encoded message via the socket
                    mdclog_write(MDCLOG_ERR, "Error :: Could not send message");  // Log an error message if sending fails
                }
            }
        }

        // Free the allocated memory to avoid memory leaks
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, e2ap_pdu);

        // Sleep for 30 seconds before sending the next policy
        std::this_thread::sleep_for(std::chrono::seconds(30));  // Pause the loop for 30 seconds before sending the next policy
    }
}

void Xapp::start_xapp_receiver(XappMsgHandler& mp_handler, int threads){
    if(threads < 1) {
        threads = 1;
    }
    rmr_ref->set_listen(true);
    if(xapp_mutex == NULL){
        xapp_mutex = new std::mutex();
    }

    for(int i = 0; i < threads; i++) {
        mdclog_write(MDCLOG_INFO,"Receiver Thread %d, file=%s, line=%d", i, __FILE__, __LINE__);
        {
            std::lock_guard<std::mutex> guard(*xapp_mutex);
            std::thread th_recv([&](){ rmr_ref->xapp_rmr_receive(std::move(mp_handler), rmr_ref);});
            xapp_rcv_thread.push_back(std::move(th_recv));
        }
    }

    // Start sending hardcoded policies at regular intervals
    std::thread policy_thread(&Xapp::send_hardcoded_policy, this);
    policy_thread.detach();

    return;
}

void Xapp::shutdown(){
	mdclog_write(MDCLOG_INFO, "Shutting down xapp %s", config_ref->operator[](XappSettings::SettingName::XAPP_ID).c_str());

	//send subscriptions delete.
	shutdown_delete_subscriptions();
	// send deregistration request
	shutdown_deregistration_request();

	sleep(2);
	rmr_ref->set_listen(false);

	shutdown_http_listener();

	//Joining the threads
	int threadcnt = xapp_rcv_thread.size();
	for(int i=0; i<threadcnt; i++){
		if(xapp_rcv_thread[i].joinable())
			xapp_rcv_thread[i].join();
	}
	xapp_rcv_thread.clear();

	return;
}

inline void Xapp::subscribe_delete_request(string sub_id) {
	auto delJson = pplx::create_task([sub_id, this]() {
		utility::string_t port = U("8088");
		utility::string_t address = U("http://service-ricplt-submgr-http.ricplt.svc.cluster.local:");
		address.append(port);
		address.append(U("/ric/v1/subscriptions/"));
		address.append( utility::string_t(sub_id));
		uri_builder uri(address);
		auto addr = uri.to_uri().to_string();
		http_client client(addr);
		ucout << utility::string_t(U("making requests at: ")) << addr <<std::endl;
		return client.request(methods::DEL);
	})

	// Get the response.
	.then([sub_id, this](http_response response) {
		// Check the status code.
		if (response.status_code() != 204) {
			throw std::runtime_error("Returned " + std::to_string(response.status_code()));
		}

		mdclog_write(MDCLOG_INFO, "Subscription %s has been deleted", sub_id.c_str());
	});

	try {
		delJson.wait();
	}
	catch (const std::exception& e) {
		mdclog_write(MDCLOG_ERR, "Subscription delete exception: %s", e.what());
	}
}

void Xapp::shutdown_delete_subscriptions() {
	std::string xapp_id = config_ref->operator [](XappSettings::SettingName::XAPP_ID);

	mdclog_write(MDCLOG_INFO,"Preparing to send subscription Delete in file=%s, line=%d",__FILE__,__LINE__);

	size_t len = subscription_map.size();
	mdclog_write(MDCLOG_INFO,"E2 NodeB List size : %lu", len);

	size_t i = 1;
	for (auto subs : subscription_map) {
		sleep(5);
		mdclog_write(MDCLOG_INFO,"sending subscription delete request %lu out of %lu to meid %s", i, len, subs.first.c_str());
		subscribe_delete_request(subs.second);
	}
}

inline void Xapp::subscribe_request(string meid, jsonn subObject) {
	mdclog_write(MDCLOG_INFO, "sending subscription to meid = %s", meid.c_str());

	auto postJson = pplx::create_task([meid, subObject, this]() {
		utility::stringstream_t s;
		s << subObject.dump().c_str();
		web::json::value ret = json::value::parse(s);
		// std::wcout << ret.serialize().c_str() << std::endl;
		utility::string_t address = U("http://service-ricplt-submgr-http.ricplt.svc.cluster.local:8088");
		address.append(U("/ric/v1/subscriptions"));
		uri_builder uri(address);
		auto addr = uri.to_uri().to_string();
		http_client client(addr);
		//std::cout<<uri::validate(addr)<<" validation \n";

		ucout << utility::string_t(U("making requests at: ")) << addr << "\n";

		return client.request(methods::POST,U("/"),ret.serialize(),U("application/json"));
	})

	// Get the response.
	.then([meid, this](http_response response)
		{
		// Check the status code.
		if (response.status_code() != 201) {
				throw std::runtime_error("Returned " + std::to_string(response.status_code()));
		}

		// Convert the response body to JSON object.
		return response.extract_json();
	})

	// serialize the user details.
	.then([meid, this](json::value jsonObject)
		{
			std::cout << "\nReceived REST subscription response: " << jsonObject.serialize().c_str() << "\n\n";

			std::string tmp;
			tmp = jsonObject[U("SubscriptionId")].as_string();
			subscription_map.emplace(std::make_pair(meid, tmp));
	});

	try
	{
		postJson.wait();
	}
	catch (const std::exception &e)
	{
		mdclog_write(MDCLOG_ERR, "xapp subscription exception: %s\n", e.what());
		throw;
	}
}

jsonn Xapp::build_rc_subscription_request(string meid) {
	mdclog_write(MDCLOG_INFO, "Building RC subscription request for %s", meid.c_str());

	std::string http_addr = config_ref->operator[](XappSettings::SettingName::HTTP_SRC_ID);
	std::string port = config_ref->operator[](XappSettings::SettingName::HTTP_PORT);
	int http_port = stoi(port);
	port = config_ref->operator[](XappSettings::SettingName::BOUNCER_PORT);
	int rmr_port = stoi(port);

	jsonn jsonObject =
		{
			{"SubscriptionId",""},
			{"ClientEndpoint",{{"Host",http_addr},{"HTTPPort",http_port},{"RMRPort",rmr_port}}},
			{"Meid",meid},
			{"RANFunctionID",1},
			{"SubscriptionDetails",
				{
					{
						{"XappEventInstanceId",12345},{"EventTriggers",{2}},
						{"ActionToBeSetupList",
							{
								{
									{"ActionID",1},
									{"ActionType","insert"},
									{"ActionDefinition",{3}},
									{"SubsequentAction",
										{
											{"SubsequentActionType","continue"},
											{"TimeToWait","w10ms"}
										}
									}
								}
							}
						}
					}
				}
			}
		};

	std::cout << jsonObject.dump(4) << "\n";

	return jsonObject;
}

jsonn Xapp::build_kpm_subscription_request(string meid) {
	mdclog_write(MDCLOG_INFO, "Building KPM subscription request for %s", meid.c_str());

	std::string http_addr = config_ref->operator[](XappSettings::SettingName::HTTP_SRC_ID);
	std::string port = config_ref->operator[](XappSettings::SettingName::HTTP_PORT);
	int http_port = stoi(port);
	port = config_ref->operator[](XappSettings::SettingName::BOUNCER_PORT);
	int rmr_port = stoi(port);

	e2sm_kpm_subscription_helper helper;
	helper.trigger.reportingPeriod = 5;	// TODO (should be each 500ms) could be changed via ENV (seems that srsRAN hardcoded it to 1)
	helper.action.granulPeriod = 3;  // TODO could be changed via ENV (seems that srsRAN hardcoded it to 1)

	helper.action.format = E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format4;

	e2sm_subscription kpm_sub;

	unsigned char buf[4096];
	ssize_t buflen = 4096;

	// RICeventTriggerDefinition
	if (!kpm_sub.encodeKPMTriggerDefinition(buf, &buflen, helper)) {
		mdclog_write(MDCLOG_ERR, "Unable to enconde E2SM_KPM_EventTriggerDefinition to create subscription request. Reason: %s", kpm_sub.get_error().c_str());
	}

	// converting to array of int as required by the json schema
	std::vector<int> kpm_trigger(buf, buf + buflen);

	buflen = 4096;
	if (!kpm_sub.encodeKPMActionDefinition(buf, &buflen, helper)) {
		mdclog_write(MDCLOG_ERR, "Unable to enconde E2SM_KPM_ActionDefinition to create subscription request. Reason: %s", kpm_sub.get_error().c_str());
	}

	// converting to array of int as required by the json schema
	std::vector<int> kpm_action(buf, buf + buflen);

	jsonn jsonObject =
		{
			{"SubscriptionId",""},
			{"ClientEndpoint",{{"Host",http_addr},{"HTTPPort",http_port},{"RMRPort",rmr_port}}},
			{"Meid",meid},
			{"RANFunctionID",147},
			{"SubscriptionDetails",
				{
					{
						{"XappEventInstanceId",12345},
						{"EventTriggers",kpm_trigger},
						{"ActionToBeSetupList",
							{
								{
									{"ActionID",1},
									{"ActionType","report"},
									{"ActionDefinition",kpm_action},
									{"SubsequentAction",{
										{"SubsequentActionType","continue"},
										{"TimeToWait","zero"}}
									}
								}
							}
						}
					}
				}
			}

		};

	std::cout << jsonObject.dump(4) << "\n";

	return jsonObject;
}

void Xapp::startup_subscribe_requests(){
	mdclog_write(MDCLOG_INFO, "Preparing to send subscriptions in file=%s, line=%d", __FILE__, __LINE__);

	size_t len = e2node_map.size();
	mdclog_write(MDCLOG_INFO, "E2 Node List size : %lu", len);
	if (len == 0) {
		throw std::runtime_error("Subscriptions cannot be sent as there is no E2 Node connected to the RIC");
	}

	string nodebid = config_ref->operator[](XappSettings::SettingName::NODEB_ID);
	unsigned long nodebid_num = 0;
	string plmnid;
	if (!nodebid.empty()) {
		plmnid = config_ref->buildPlmnId();
		transform(plmnid.begin(), plmnid.end(), plmnid.begin(), ::tolower);	// compare
		try {
			nodebid_num = std::stoul(nodebid, nullptr, 2);
		} catch (std::exception& e) {
			std::stringstream ss;
			ss << "unable to convert " << nodebid << " to number: " << e.what();
			throw std::runtime_error(ss.str());
		}
	}

	for (auto e2node : e2node_map) {
		if (!nodebid.empty()) {
			auto e2plmn = e2node.second[U("plmnId")].as_string();
			transform(e2plmn.begin(), e2plmn.end(), e2plmn.begin(), ::tolower);	// compare
			if (plmnid.compare(e2plmn) != 0) {
				continue;	// check next
			}
			auto e2nbId = e2node.second[U("nbId")].as_string();
			try {
				auto nbId = std::stoul(e2nbId, nullptr, 2);
				if (nodebid_num != nbId) {
					continue;	// check next
				}

			} catch (std::exception& e) {
				// If no conversion could be performed, an invalid_argument exception is thrown.
				// If the value read is out of the range of representable values by an unsigned long, an out_of_range exception is thrown.
				std::stringstream ss;
				ss << "unable to convert " << e2nbId << " to number: " << e.what();
				throw std::runtime_error(ss.str());
			}
		}

		/* ============ Building and sending subscription requests ============ */
		sleep(5);	// require to wait for registration to complete, and a pause between each subscription is also required

		// jsonn jsonObject = build_rc_subscription_request(e2node.first);
		jsonn jsonObject = build_kpm_subscription_request(e2node.first);
		subscribe_request(e2node.first, jsonObject); // this can be called only after the xApp has been registered
		/* ==================================================================== */

		if (!nodebid.empty()) {	// we only reach here when it's not empty when we found the nodebId to subscribe and we no longer need to iterate over the map
			break;	// avoids sleeping over remaining e2node list
		}
	}

	if (subscription_map.size() == 0) {
		throw std::runtime_error("Unable to subscribe to E2 Node");
	}
}

void Xapp::startup_get_policies(void){
	mdclog_write(MDCLOG_INFO, "Starting up A1 policies");

	int policy_id = BOUNCER_POLICY_ID;

	std::string policy_query = "{\"policy_type_id\":" + std::to_string(policy_id) + "}";
	unsigned char * message = (unsigned char *)calloc(policy_query.length(), sizeof(unsigned char));
	memcpy(message, policy_query.c_str(),  policy_query.length());
	xapp_rmr_header header;
	header.state = RMR_OK;
	header.payload_length = policy_query.length();
	header.message_type = A1_POLICY_QUERY;
	mdclog_write(MDCLOG_INFO, "Sending request for policy id %d\n", policy_id);
	rmr_ref->xapp_rmr_send(&header, (void *)message);
	free(message);

}

void Xapp::set_rnib_gnblist(void) {

	   openSdl();

	   void *result = getListGnbIds();
	   if(strlen((char*)result) < 1){
		    mdclog_write(MDCLOG_ERR, "ERROR: no data from getListGnbIds\n");
	        return;
	    }

	    mdclog_write(MDCLOG_INFO, "GNB List in R-NIB %s\n", (char*)result);


	    Document doc;
	    ParseResult parseJson = doc.Parse<kParseStopWhenDoneFlag>((char*)result);
	    if (!parseJson) {
			mdclog_write(MDCLOG_ERR, "JSON parse error: %s", (char *)GetParseErrorFunc(parseJson.Code()));
	    	return;
	    }

	    if(!doc.HasMember("gnb_list")){
	        mdclog_write(MDCLOG_ERR, "JSON Has No GNB List Object");
	    	return;
	    }
	    assert(doc.HasMember("gnb_list"));

	    const Value& gnblist = doc["gnb_list"];
	    if (gnblist.IsNull())
	      return;

	    if(!gnblist.IsArray()){
	        mdclog_write(MDCLOG_ERR, "GNB List is not an array");
	    	return;
	    }


	   	assert(gnblist.IsArray());
	    for (SizeType i = 0; i < gnblist.Size(); i++) // Uses SizeType instead of size_t
	    {
	    	assert(gnblist[i].IsObject());
	    	const Value& gnbobj = gnblist[i];
	    	assert(gnbobj.HasMember("inventory_name"));
	    	assert(gnbobj["inventory_name"].IsString());
	    	std::string name = gnbobj["inventory_name"].GetString();
	    	rnib_gnblist.push_back(name);

	    }
	    closeSdl();
	    return;

}

/*
	Fetches all E2 NodeBs from E2MGR that connected to the RIC, and stores
	in a map their InventoryName as the key and GlobalNodebID as the value.
*/
void Xapp::fetch_connected_nodeb_list() {
	mdclog_write(MDCLOG_INFO, "Fetching connected E2 NodeB list");

	pplx::create_task([this]()
		{
			utility::string_t address = U("http://service-ricplt-e2mgr-http.ricplt.svc.cluster.local:3800");
			address.append(U("/v1/nodeb/states"));
			uri_builder uri(address);
			auto addr = uri.to_uri().to_string();
			http_client client(addr);

			mdclog_write(MDCLOG_INFO, "sending request for E2 NodeB list at: %s", addr.c_str());

			return client.request(methods::GET,U("/"), U("accept: application/json"));
		})
		// Get the response.
		.then([this](http_response response)
		{
			// Check the status code
			if (response.status_code() != 200) {
				mdclog_write(MDCLOG_ERR, "request for E2 NodeB list returned http status code %s - %s",
							std::to_string(response.status_code()).c_str(), response.reason_phrase().c_str());

				throw std::runtime_error("Returned http status code " + std::to_string(response.status_code()));
			}

			// Convert the response body to JSON object.
			return response.extract_json();
		})
		// serialize the user details.
		.then([this](web::json::value resp) {
			mdclog_write(MDCLOG_INFO, "E2 NodeB list has been fetched successfuly");

				try {
					auto nodeb_list = resp.as_array();
					for (auto nodeb : nodeb_list) {
						auto inv_name = nodeb[U("inventoryName")].as_string();
						auto status = nodeb[U("connectionStatus")].as_string();

						mdclog_write(MDCLOG_DEBUG, "E2 NodeB %s is %s", inv_name.c_str(), status.c_str());

						if (status.compare("CONNECTED") == 0) {
							this->e2node_map.emplace(inv_name, nodeb[U("globalNbId")]);
						}
					}

				} catch (json::json_exception const &e) {
					mdclog_write(MDCLOG_ERR, "unable to process JSON payload from http response. Reason = %s", e.what());
				}
		})
		// catch any exception
		.then([](pplx::task<void> previousTask)
		{
			try {
				previousTask.wait();
			} catch (exception& e) {
				mdclog_write(MDCLOG_ERR, "Fetch E2 NodeB list exception: %s", e.what());
			}
		});
}


void Xapp::startup_registration_request() {
	mdclog_write(MDCLOG_INFO, "Preparing registration request");

	string xapp_name = config_ref->operator[](XappSettings::SettingName::XAPP_NAME);
	string xapp_id = config_ref->operator[](XappSettings::SettingName::XAPP_ID);
	string config_path = config_ref->operator[](XappSettings::SettingName::CONFIG_FILE);
	string config_str = config_ref->operator[](XappSettings::SettingName::CONFIG_STR);
	string version = config_ref->operator[](XappSettings::SettingName::VERSION);
	string rmr_addr = config_ref->operator[](XappSettings::SettingName::RMR_SRC_ID);
	string http_addr = config_ref->operator[](XappSettings::SettingName::HTTP_SRC_ID);
	string rmr_port = config_ref->operator[](XappSettings::SettingName::BOUNCER_PORT);
	string http_port = config_ref->operator[](XappSettings::SettingName::HTTP_PORT);

	rmr_addr.append(":" + rmr_port);

	if (!http_addr.empty() && !http_port.empty()) {
		http_addr.append(":" + http_port);
	}

	pplx::create_task([xapp_name, version, config_path, xapp_id, http_addr, rmr_addr, config_str]()
		{
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

			if (mdclog_level_get() > MDCLOG_INFO) {
				cerr << "registration body is\n" << jObj.dump(4) << "\n";
			}
			utility::stringstream_t s;
			s << jObj.dump().c_str();
			web::json::value ret = json::value::parse(s);

			utility::string_t port = U("8080");
			utility::string_t address = U("http://service-ricplt-appmgr-http.ricplt.svc.cluster.local:");
			address.append(port);
			address.append(U("/ric/v1/register"));
			uri_builder uri(address);
			auto addr = uri.to_uri().to_string();
			http_client client(addr);

			mdclog_write(MDCLOG_INFO, "sending registration request at: %s", addr.c_str());

			return client.request(methods::POST,U("/"),ret.serialize(),U("application/json"));
		})

		// Get the response.
		.then([xapp_id](http_response response)
		{
			// Check the status code
			if (response.status_code() == 201) {
				mdclog_write(MDCLOG_INFO, "xapp %s has been registered", xapp_id.c_str());
			} else {
				mdclog_write(MDCLOG_ERR, "registration returned http status code %s - %s",
							std::to_string(response.status_code()).c_str(), response.reason_phrase().c_str());
			}
		})

		// catch any exception
		.then([](pplx::task<void> previousTask)
		{
			try {
				previousTask.wait();
			} catch (exception& e) {
				mdclog_write(MDCLOG_ERR, "xapp registration exception: %s", e.what());
				throw;
			}
		}).get();	// get allows rethrowing exceptions from task
}

void Xapp::shutdown_deregistration_request() {
	mdclog_write(MDCLOG_INFO, "Preparing deregistration request");

	string xapp_name = config_ref->operator[](XappSettings::SettingName::XAPP_NAME);
	string xapp_id = config_ref->operator[](XappSettings::SettingName::XAPP_ID);

	pplx::create_task([xapp_name, xapp_id]()
		{
			jsonn jObj;
			jObj = {
				{"appName", xapp_name},
				{"appInstanceName", xapp_id}
			};

			if (mdclog_level_get() > MDCLOG_INFO) {
				cerr << "deregistration body is\n" << jObj.dump(4) << "\n";
			}
			utility::stringstream_t s;
			s << jObj.dump().c_str();
			web::json::value ret = json::value::parse(s);

			utility::string_t port = U("8080");
			utility::string_t address = U("http://service-ricplt-appmgr-http.ricplt.svc.cluster.local:");
			address.append(port);
			address.append(U("/ric/v1/deregister"));
			uri_builder uri(address);
			auto addr = uri.to_uri().to_string();
			http_client client(addr);

			mdclog_write(MDCLOG_INFO, "sending deregistration request at: %s", addr.c_str());

			return client.request(methods::POST,U("/"),ret.serialize(),U("application/json"));
		})

		// Get the response.
		.then([xapp_id](http_response response)
		{
			// Check the status code
			if (response.status_code() == 204) {
				mdclog_write(MDCLOG_INFO, "xapp %s has been deregistered", xapp_id.c_str());
			} else {
				mdclog_write(MDCLOG_ERR, "deregistration returned http status code %s - %s",
							std::to_string(response.status_code()).c_str(), response.reason_phrase().c_str());
			}
		})

		// catch any exception
		.then([](pplx::task<void> previousTask)
		{
			try {
				previousTask.wait();
			} catch (exception& e) {
				mdclog_write(MDCLOG_ERR, "deregistration exception: %s", e.what());
			}
		});
}

void Xapp::handle_error(pplx::task<void>& t, const utility::string_t msg) {
	try {
		t.get();
	} catch (std::exception& e) {
		mdclog_write(MDCLOG_ERR, "%s : Reason = %s", msg.c_str(), e.what());
	}
}

/*
	Handles JSON in http requests.
*/
void Xapp::handle_request(http_request request) {

	if (mdclog_level_get() > MDCLOG_INFO) {
		cerr << "\n===== Handling HTTP request =====\n" << request.to_string() << "\n=================================\n\n";
	}

	auto answer = json::value::object();
	request
		.extract_json()
		.then([&answer, request, this](pplx::task<json::value> task) {
			try {
				answer = task.get();
				mdclog_write(MDCLOG_INFO, "Received REST notification %s", answer.serialize().c_str());

				auto subscriptions = answer[U("SubscriptionInstances")].as_array();
				for (auto sub : subscriptions) {
					int event = sub[U("E2EventInstanceId")].as_integer();
					if (event == 0) {				// this is an error message, unable to subscribe to this event
						auto source = sub[U("ErrorSource")].as_string();
						auto cause = sub[U("ErrorCause")].as_string();
						mdclog_write(MDCLOG_ERR, "unable to complete subscription. ErrorSource: %s, ErrorCause: %s", source.c_str(), cause.c_str());
						kill(getpid(), SIGTERM);	// sending signal to shutdown the application
						break;
					}
				}

				request.reply(status_codes::OK)
					.then([this](pplx::task<void> t)
					{
						handle_error(t, "http reply exception");
					});

			} catch (json::json_exception const &e) {
				mdclog_write(MDCLOG_ERR, "unable to process JSON payload from http request. Reason = %s", e.what());

				request.reply(status_codes::InternalError)
					.then([this](pplx::task<void> t)
					{
						handle_error(t, "http reply exception");
					});
			}

		}).wait();

}

void Xapp::startup_http_listener() {
	mdclog_write(MDCLOG_INFO, "Starting up HTTP Listener");

	utility::string_t port = U(config_ref->operator[](XappSettings::SettingName::HTTP_PORT));
	utility::string_t address = U("http://0.0.0.0:");
	address.append(port);
	address.append(U("/ric/v1/subscriptions/response"));
	uri_builder uri(address);

	auto addr = uri.to_uri().to_string();
	if (!uri::validate(addr)) {
		throw std::runtime_error("unable starting up the http listener due to invalid URI: " + addr);
	}

	listener = make_unique<http_listener>(addr);
	mdclog_write(MDCLOG_INFO, "Listening for REST Notification at: %s", addr.c_str());

	listener->support(methods::POST,[this](http_request request) { handle_request(request); });
	listener->support(methods::PUT,[this](http_request request){ handle_request(request); });
	try {
		listener
			->open()
			.wait();	// non-blocking operation

	} catch (exception const &e) {
		mdclog_write(MDCLOG_ERR, "startup http listener exception: %s", e.what());
		throw;
	}
}

void Xapp::shutdown_http_listener() {
	mdclog_write(MDCLOG_INFO, "Shutting down HTTP Listener");

	try {
		listener->close().wait();

	} catch (exception const &e) {
		mdclog_write(MDCLOG_ERR, "shutdown http listener exception: %s", e.what());
	}
}
